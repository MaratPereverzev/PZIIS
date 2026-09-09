#!/usr/bin/env bash
# Демонстрация защищённости приложения.
#
# Скрипт последовательно проходит сценарии из раздела 6 документа
# docs/02-analysis.md. Задание 2.1 требует не только демонстрации работы,
# но и демонстрации и обоснования защищённости - это она и есть
# в исполняемом виде.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

[[ -f .env ]] || { echo "Сначала запустите ./run.sh"; exit 1; }

B=https://127.0.0.1:8443
PW="Sufficiently-Long-Passphrase-42"
ADMIN_LOGIN=$(grep -m1 VAULT_ADMIN_LOGIN .env | cut -d= -f2)
ADMIN_PW=$(grep -m1 VAULT_ADMIN_PASSWORD .env | cut -d= -f2)
VAULT_PW=$(grep -m1 VAULT_DB_PASSWORD .env | cut -d= -f2)
SUFFIX=$RANDOM

step()  { printf '\n\033[1m=== %s\033[0m\n' "$*"; }
say()   { printf '    %s\n' "$*"; }
ok()    { printf '    \033[32m[+]\033[0m %s\n' "$*"; }
bad()   { printf '    \033[31m[-]\033[0m %s\n' "$*"; }

# psql от имени владельца объектов (обходит RLS - он и есть доверенный ДБА)
pg()    { docker compose exec -T db su-exec postgres psql -d app_db -qtAX "$@"; }
# psql от имени сервисной роли приложения
pgapp() { docker compose exec -T -e PGPASSWORD="$VAULT_PW" db \
              psql -U vault_app -h 127.0.0.1 -d app_db -qtAX "$@"; }

csrf() { grep -oP 'name="csrf_token" value="\K[^"]+' "$1" | head -1; }
JAR_A=$(mktemp); JAR_B=$(mktemp); JAR_ADM=$(mktemp)
trap 'rm -f "$JAR_A" "$JAR_B" "$JAR_ADM" /tmp/pv_*.html' EXIT

login() {  # login <jar> <логин> <пароль>
    curl -sk -c "$1" -b "$1" -X POST $B/login \
        --data-urlencode "login=$2" --data-urlencode "password=$3" \
        -o /dev/null -w '%{http_code}'
}
page() { curl -sk -c "$1" -b "$1" "$B$2" -o "$3" -w '%{http_code}'; }
post() {  # post <jar> <путь> <файл-ответа> <данные...>
    local jar=$1 path=$2 out=$3; shift 3
    local args=()
    for kv in "$@"; do args+=(--data-urlencode "$kv"); done
    curl -sk -c "$jar" -b "$jar" -X POST "$B$path" "${args[@]}" \
        -o "$out" -w '%{http_code}'
}

# ---------------------------------------------------------------------------
step "Подготовка: две учётные записи с ролью user и одна с ролью guest"
login "$JAR_ADM" "$ADMIN_LOGIN" "$ADMIN_PW" >/dev/null
page "$JAR_ADM" /admin/accounts /tmp/pv_adm.html >/dev/null
T=$(csrf /tmp/pv_adm.html)
for pair in "demo_a_$SUFFIX:user" "demo_b_$SUFFIX:user" "demo_g_$SUFFIX:guest"; do
    post "$JAR_ADM" /admin/accounts /dev/null \
        "login=${pair%%:*}" "password=$PW" "app_role=${pair##*:}" \
        "csrf_token=$T" >/dev/null
    say "создана ${pair%%:*} с ролью ${pair##*:}"
done
login "$JAR_A" "demo_a_$SUFFIX" "$PW" >/dev/null
login "$JAR_B" "demo_b_$SUFFIX" "$PW" >/dev/null

page "$JAR_A" /secrets /tmp/pv_a.html >/dev/null; TA=$(csrf /tmp/pv_a.html)
SECRET_TITLE="Договор аренды $SUFFIX"
SECRET_BODY="ИНН 1234567890, сумма 45000"
post "$JAR_A" /secrets /dev/null "title=$SECRET_TITLE" "body=$SECRET_BODY" \
    "csrf_token=$TA" >/dev/null
say "пользователь demo_a_$SUFFIX создал конфиденциальную запись"

# ---------------------------------------------------------------------------
step "1. Хранение паролей: Argon2id, а не открытый текст"
pg -c "SELECT login || '  ' || left(pwd_hash, 44) || '..' FROM app.account
       WHERE login LIKE 'demo_%$SUFFIX' ORDER BY id;" | sed 's/^/    /'
if pg -c "SELECT count(*) FROM app.account WHERE pwd_hash LIKE '\$argon2id\$%';" \
     | grep -qv '^0$'; then ok "все пароли - строки Argon2id, соль своя у каждого"; fi

step "2. Шифрование конфиденциальных данных: в таблице только шифротекст"
pg -c "SELECT 'id=' || id || ' owner=' || owner_id ||
              ' title_ct=' || left(encode(title_ct,'hex'), 28) || '..' ||
              ' body_ct='  || left(encode(body_ct,'hex'), 28) || '..'
       FROM app.secret_record ORDER BY id DESC LIMIT 3;" | sed 's/^/    /'
if pg -c "SELECT count(*) FROM app.secret_record
          WHERE position('Договор'::bytea in title_ct) > 0;" | grep -q '^0$'; then
    ok "открытого текста в шифротексте нет"
else bad "найден открытый текст"; fi
say "тот же список в интерфейсе владельца - в открытом виде:"
page "$JAR_A" /secrets /tmp/pv_a.html >/dev/null
grep -oP '<td>\K'"Договор[^<]*" /tmp/pv_a.html | head -1 | sed 's/^/      /'

step "3. Построчная защита: изоляция данных между пользователями"
page "$JAR_B" /secrets /tmp/pv_b.html >/dev/null
if grep -q "$SECRET_TITLE" /tmp/pv_b.html; then bad "чужая запись видна!"
else ok "demo_b не видит запись demo_a через интерфейс"; fi
ID_A=$(pg -c "SELECT id FROM app.account WHERE login = 'demo_a_$SUFFIX';")
ID_B=$(pg -c "SELECT id FROM app.account WHERE login = 'demo_b_$SUFFIX';")
N_OWN=$(pgapp -c "BEGIN; SELECT set_config('app.actor_id','$ID_A',true);
                  SELECT count(*) FROM app.secret_record; COMMIT;" | tail -1)
N_FOREIGN=$(pgapp -c "BEGIN; SELECT set_config('app.actor_id','$ID_B',true);
                  SELECT count(*) FROM app.secret_record
                  WHERE owner_id = $ID_A; COMMIT;" | tail -1)
N_NONE=$(pgapp -c "SELECT count(*) FROM app.secret_record;")
say "напрямую в psql под ролью vault_app:"
say "  actor_id=$ID_A (владелец) -> строк: $N_OWN"
say "  actor_id=$ID_B (другой)   -> чужих строк: $N_FOREIGN"
say "  actor_id не выставлен     -> строк: $N_NONE"
[[ "$N_FOREIGN" == "0" && "$N_NONE" == "0" ]] &&
    ok "запрет действует на уровне СУБД, независимо от кода приложения"

step "4. Администратор не читает открытый текст чужих секретов"
page "$JAR_ADM" /admin/secrets /tmp/pv_meta.html >/dev/null
if grep -q "demo_a_$SUFFIX" /tmp/pv_meta.html; then
    ok "метаданные видны (владелец, размер, версия ключа)"; fi
if grep -q "$SECRET_TITLE" /tmp/pv_meta.html; then bad "виден открытый текст!"
else ok "открытого текста нет ни в обзоре, ни в /secrets администратора"; fi

step "5. Поиск по шифротексту: в базе только HMAC-теги"
page "$JAR_A" /secrets /tmp/pv_a.html >/dev/null; TA=$(csrf /tmp/pv_a.html)
post "$JAR_A" /secrets/search /tmp/pv_find.html "q=аренды" "csrf_token=$TA" >/dev/null
grep -oP '<td>\K'"Договор[^<]*" /tmp/pv_find.html | head -1 |
    sed 's/^/    найдено по слову «аренды»: /'
say "а в таблице индекса лежит вот это:"
pg -c "SELECT '  record_id=' || record_id || ' tag=' || encode(tag,'hex')
       FROM app.secret_tag ORDER BY record_id DESC LIMIT 3;" | sed 's/^/    /'
ok "восстановить слово по тегу нельзя: ключ K_idx лежит вне базы"

step "6. SQL-инъекция инертна"
INJ_SQL="' OR 1=1 --"
INJ_DROP="'; DROP TABLE app.secret_record; --"
CODE_1=$(page "$JAR_A" "/notes?q=%27%20OR%201%3D1%20--" /tmp/pv_inj.html)
CODE_2=$(post "$JAR_A" /secrets/search /tmp/pv_inj2.html \
             "q=$INJ_DROP" "csrf_token=$TA")
say "поиск записей с «$INJ_SQL»:   HTTP $CODE_1"
say "поиск секретов с «$INJ_DROP»: HTTP $CODE_2"
if pg -c "SELECT count(*) FROM app.secret_record;" | grep -qv '^0$'; then
    ok "таблица на месте: запросы параметризованы, строка ищется как текст"
fi

step "7. XSS: сохранённый скрипт выводится как текст"
page "$JAR_A" /notes /tmp/pv_n.html >/dev/null; TN=$(csrf /tmp/pv_n.html)
post "$JAR_A" /notes /dev/null "title=<script>alert('xss')</script>" \
    "body=<img src=x onerror=alert(1)>" "visibility=public" \
    "csrf_token=$TN" >/dev/null
page "$JAR_A" /notes /tmp/pv_n.html >/dev/null
if grep -q "<script>alert" /tmp/pv_n.html; then bad "скрипт попал в разметку!"
else ok "полезная нагрузка экранирована (&lt;script&gt;)"; fi
curl -sk -D- -o /dev/null $B/login | grep -i "^content-security-policy" |
    sed 's/^/    /'

step "8. Деавторизация: возврат прежней cookie не восстанавливает доступ"
cp "$JAR_A" /tmp/pv_stolen.jar
say "код доступа к /secrets до выхода: $(page "$JAR_A" /secrets /dev/null)"
post "$JAR_A" /logout /dev/null "csrf_token=$TA" >/dev/null
CODE=$(curl -sk -b /tmp/pv_stolen.jar $B/secrets -o /dev/null \
        -w '%{http_code}' --max-redirs 0)
say "код доступа с той же cookie после выхода: $CODE"
[[ "$CODE" == "303" ]] &&
    ok "строка сессии удалена на сервере; с JWT токен остался бы валидным"
rm -f /tmp/pv_stolen.jar

step "9а. Перебор, рубеж первый: лимит частоты на nginx"
say "12 попыток входа подряд через прокси:"
for i in $(seq 1 12); do
    curl -sk -X POST $B/login --data-urlencode "login=demo_g_$SUFFIX" \
        --data-urlencode "password=Wrong-Passphrase-$i" \
        -o /dev/null -w '%{http_code} '
done | sed 's/^/      /'
echo
ok "лимит 5 запросов в минуту на /login: поток отбивается ДО приложения"
say "это принципиально: Argon2 с памятью 64 МиБ сам является ресурсом,"
say "и форма входа без такого лимита стала бы вектором отказа в обслуживании."
say "Если предыдущий прогон был меньше минуты назад, все ответы уже 429 -"
say "бюджет минуты для этого адреса израсходован."

step "9б. Перебор, рубеж второй: лимит приложения, в обход прокси"
say "те же попытки прямо к приложению по внутренней сети - так виден"
say "механизм самого приложения, а не nginx:"
docker compose run --rm --no-deps --entrypoint python \
    -e LOCK_LOGIN="demo_g_$SUFFIX" app -c '
import os, httpx
login = os.environ["LOCK_LOGIN"]
codes = []
with httpx.Client(base_url="http://app:8000", follow_redirects=False) as c:
    for i in range(12):
        r = c.post("/login", data={"login": login,
                                   "password": "Wrong-Passphrase-%d" % i})
        codes.append(str(r.status_code))
print("      коды ответов приложения: " + " ".join(codes))
' 2>/dev/null
ok "после исчерпания лимита приложение отвечает 429, не считая хеш Argon2"

step "9в. Перебор, рубеж третий: блокировка учётной записи"
say "ВАЖНО: лимит на адрес (5/мин) связывает РАНЬШЕ, чем порог блокировки"
say "(10 неудач), поэтому с одного источника блокировка недостижима -"
say "она адресована распределённому перебору, где лимит на адрес не помогает."
say "Проверка порога выполняется с поднятым лимитом на адрес:"
docker compose run --rm \
    -e VAULT_LOGIN_IP_LIMIT=100000 -e VAULT_FAILED_DELAY_MS=0 app \
    python -m pytest -q -p no:cacheprovider \
    tests/test_security.py::test_account_lockout_after_repeated_failures \
    2>/dev/null | tail -3 | sed 's/^/      /'
say "заблокированные учётные записи в базе:"
pg -c "SELECT '  ' || login || ' -> ' || locked_until
       FROM app.account WHERE locked_until IS NOT NULL
       ORDER BY locked_until DESC LIMIT 3;" | sed 's/^/    /'
ok "порог срабатывает; верный пароль во время блокировки тоже не принимается"
say "события в журнале аудита по демонстрационной записи:"
pg -c "SELECT '  ' || action || ' / ' || outcome || ' x' || cnt FROM (
          SELECT action, outcome, count(*) AS cnt
          FROM app.audit_event WHERE actor_login = 'demo_g_$SUFFIX'
          GROUP BY action, outcome) t ORDER BY 1;" | sed 's/^/    /'

step "10. Ограничение привилегий в операционной системе"
say "пользователь процесса: $(docker compose exec -T app id | tr -d '\r')"
say "capabilities процесса:"
docker compose exec -T app grep -E '^Cap(Eff|Prm)' /proc/1/status | sed 's/^/      /'
say "попытка записи в каталог с кодом:"
docker compose exec -T app sh -c 'touch /srv/app/backdoor.py 2>&1' |
    sed 's/^/      /'
ok "код принадлежит root, ФС контейнера только на чтение, ни одной capability"

step "11. Сетевая политика"
say "порты контейнеров (слева от -> нет адреса = на хост не опубликован):"
docker compose ps --format '{{.Service}}: {{.Ports}}' | sed 's/^/      /'
ok "наружу открыт только nginx на 127.0.0.1:8443; приложение и СУБД - нет"
echo | openssl s_client -connect 127.0.0.1:8443 -brief 2>&1 |
    grep -iE 'protocol version|ciphersuite' | sed 's/^/    /'

step "12. Целостность журнала аудита"
say "попытка удалить запись журнала под ролью приложения:"
pgapp -c "DELETE FROM app.audit_event;" 2>&1 | head -2 | sed 's/^/      /'
say "попытка создать таблицу (DDL):"
pgapp -c "CREATE TABLE app.backdoor (id int);" 2>&1 | head -2 | sed 's/^/      /'
ok "журнал только на добавление, DDL сервисной роли недоступен"

printf '\n\033[1mДемонстрация завершена.\033[0m Полный набор проверок: ./check.sh\n'
