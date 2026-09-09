# Лабораторная работа №2, часть 1. Проектирование приложения

**Приложение:** `pziis-vault` — веб-реестр записей с разделением данных на
конфиденциальные и неконфиденциальные.

**Вариант окружения:** одноразовая ВМ / контейнер с Debian + PostgreSQL,
поднятой лабораторной работой №1 (база `app_db`, схема `app`, роли
`admin_role` / `user_role` / `guest_role`).

---

## 1. Соответствие требованиям задания

Задание 2.1 требует пять функций. Ниже — как каждая закрывается.

| № | Требование задания | Реализация |
|---|---|---|
| 1 | Добавить пользователя в систему | `POST /register` (самостоятельная регистрация, роль `guest`) и `POST /admin/accounts` (создание учётной записи администратором с назначением роли) |
| 2 | Авторизовать пользователя на основе идентификационных данных | `POST /login`: логин + пароль, проверка по хешу Argon2id, выдача серверной сессии |
| 3 | Создать, редактировать, удалить, найти **конфиденциальные** данные | `/secrets` — CRUD + `GET /secrets/search`; тело записей зашифровано AES-256-GCM, поиск через слепой индекс (HMAC) |
| 4 | Создать, редактировать, удалить, найти **неконфиденциальные** данные | `/notes` — CRUD + `GET /notes/search`; хранение в открытом виде, поиск полнотекстовый (`tsvector`) |
| 5 | Деавторизовать пользователя | `POST /logout`: удаление строки сессии на сервере + сброс cookie |

Разделение данных на два класса — не косметика, а несущая конструкция
работы: два класса хранятся в разных таблицах, под разными привилегиями,
с разными механизмами поиска и разной моделью угроз.

---

## 2. Технологический стек

| Слой | Выбор | Обоснование в терминах защищённости |
|---|---|---|
| Приложение | Python 3.11, FastAPI + Uvicorn | Pydantic даёт валидацию входных данных как часть контракта, а не «россыпью» проверок |
| Шаблоны | Jinja2 с включённым автоэкранированием | защита от XSS по умолчанию, а не по памяти разработчика |
| Доступ к БД | psycopg 3, **только** параметризованные запросы | защита от SQL-инъекций на уровне протокола (расширенный запрос), а не фильтрации строк |
| Хеш паролей | argon2-cffi (Argon2id) | победитель PHC, память-затратный — обесценивает GPU/ASIC-перебор |
| Симметричная криптография | `cryptography` (AES-256-GCM, HKDF, HMAC-SHA256) | аудированная библиотека, AEAD вместо самодельных схем |
| СУБД | PostgreSQL 15 (из лабы №1) | RLS и постолбцовые гранты позволяют дублировать контроль доступа на уровне БД |
| Обратный прокси | nginx, TLS 1.2/1.3 | терминация TLS, заголовки безопасности, ограничение размера тела запроса |
| Изоляция процесса | systemd-юнит с ужесточением + отдельный системный пользователь | принцип минимальных привилегий на уровне ОС |

Сознательно **не** используется: JWT в качестве сессии (нельзя отозвать при
деавторизации — прямое противоречие требованию №5), ORM с генерацией SQL из
строк, самописная криптография.

---

## 3. Архитектура

```
   Интернет / ЛВС
        │  только 443/tcp (ufw default deny incoming)
        ▼
┌──────────────────────────────────────────────┐
│ nginx  (пользователь www-data)               │
│  TLS 1.2/1.3, HSTS, CSP, лимит тела 64 КБ    │
│  rate limit: 10 r/s общий, 5 r/min на /login │
└───────────────┬──────────────────────────────┘
                │ HTTP по 127.0.0.1:8000 (loopback, наружу не слушает)
                ▼
┌──────────────────────────────────────────────┐
│ uvicorn / FastAPI  (пользователь pziis)      │
│  ┌────────────────────────────────────────┐  │
│  │ Слой сессий: opaque-токен, HttpOnly    │  │
│  │ Слой авторизации: RBAC admin/user/guest│  │
│  │ Слой криптографии: AES-GCM, слепой инд.│  │
│  │ Слой аудита: append-only журнал        │  │
│  └────────────────────────────────────────┘  │
└───────────────┬──────────────────────────────┘
                │ psycopg 3, SCRAM-SHA-256, роль vault_app
                │ SET LOCAL app.actor_id = <id> в каждой транзакции
                ▼
┌──────────────────────────────────────────────┐
│ PostgreSQL  (пользователь postgres)          │
│  listen_addresses = 'localhost'              │
│  схема app: account, session, public_note,   │
│             secret_record, secret_tag,       │
│             audit_event                      │
│  RLS: изоляция строк по владельцу            │
└──────────────────────────────────────────────┘

Ключи: /etc/pziis-vault/keys.env  (0640 root:pziis, вне репозитория)
```

Три доверительные границы, каждая со своим контролем:
сеть → nginx (TLS, лимиты), nginx → приложение (loopback),
приложение → СУБД (отдельная роль + RLS).

---

## 4. Ролевая модель и преемственность с лабой №1

Задание части 1.2 требовало три роли; приложение сохраняет ту же семантику,
поэтому настройка из лабы №1 переиспользуется как есть.

| Роль | Уровень СУБД (лаба №1) | Уровень приложения (лаба 2.1) |
|---|---|---|
| Администратор | `admin_role`: все привилегии на схему `app` с `WITH GRANT OPTION` | управление учётными записями, полный доступ к неконфиденциальным записям, чтение журнала аудита, **метаданные** конфиденциальных записей |
| Пользователь | `user_role`: `SELECT/INSERT/UPDATE/DELETE` на таблицы схемы, без DDL | полный CRUD над своими конфиденциальными и неконфиденциальными записями |
| Гость | `guest_role`: `SELECT (id, data)` + RLS `visibility='public'` | только чтение неконфиденциальных записей с `visibility='public'` |

### Осознанное отступление: администратор не читает чужие секреты

Методичка 1.2 описывает администратора как субъекта «с полным доступом ко
всем подсистемам». В приложении 2.1 это ограничено: администратор видит
метаданные конфиденциальных записей (владелец, время создания, размер), но
**не** открытый текст.

Обоснование: расшифровка выполняется только в контексте владельца, поэтому
компрометация административной учётной записи не приводит к раскрытию
конфиденциальных данных всех пользователей. Это прямое применение CWE-250
(выполнение с ненужными привилегиями) и разделение обязанностей
«администрирование системы ≠ доступ к содержимому данных». Полнота
административных полномочий сохранена там, где она нужна для эксплуатации:
учётные записи, роли, блокировки, аудит, неконфиденциальные данные.

---

## 5. Модель данных

Все объекты — в схеме `app` базы `app_db`, созданной лабораторной №1.

```sql
CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid
CREATE EXTENSION IF NOT EXISTS citext;     -- регистронезависимый логин

-- Сервисная роль приложения: минимум полномочий, RLS обходить не может.
CREATE ROLE vault_app LOGIN PASSWORD :'app_pw'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT;
GRANT CONNECT ON DATABASE app_db TO vault_app;
GRANT USAGE ON SCHEMA app TO vault_app;

-- 5.1 Учётные записи -------------------------------------------------------
CREATE TABLE app.account (
    id              bigserial PRIMARY KEY,
    login           citext UNIQUE NOT NULL,
    pwd_hash        text NOT NULL,                 -- строка Argon2id PHC
    app_role        text NOT NULL DEFAULT 'guest'
                    CHECK (app_role IN ('admin', 'user', 'guest')),
    is_active       boolean NOT NULL DEFAULT true,
    failed_count    smallint NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    pwd_changed_at  timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- 5.2 Сессии ---------------------------------------------------------------
-- В базе лежит ТОЛЬКО хеш токена: дамп таблицы не даёт возможности
-- переиграть чужую сессию.
CREATE TABLE app.session (
    id               bigserial PRIMARY KEY,
    token_hash       bytea UNIQUE NOT NULL,        -- SHA-256(opaque-токен)
    csrf_hash        bytea NOT NULL,
    account_id       bigint NOT NULL REFERENCES app.account(id) ON DELETE CASCADE,
    idle_expires_at  timestamptz NOT NULL,         -- +30 минут неактивности
    hard_expires_at  timestamptz NOT NULL,         -- +12 часов абсолютно
    ip_addr          inet,
    ua_hash          bytea,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON app.session (account_id);

-- 5.3 НЕконфиденциальные данные -------------------------------------------
CREATE TABLE app.public_note (
    id          bigserial PRIMARY KEY,
    owner_id    bigint NOT NULL REFERENCES app.account(id) ON DELETE CASCADE,
    title       varchar(200) NOT NULL,
    body        text NOT NULL CHECK (length(body) <= 8000),
    visibility  text NOT NULL DEFAULT 'public'
                CHECK (visibility IN ('public', 'internal')),
    search_vec  tsvector GENERATED ALWAYS AS
                (to_tsvector('russian', title || ' ' || body)) STORED,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON app.public_note USING gin (search_vec);

-- 5.4 КОНФИДЕНЦИАЛЬНЫЕ данные ---------------------------------------------
-- Открытого текста в таблице нет вообще. ext_id генерируется приложением
-- ДО вставки и входит в AAD, поэтому шифротекст нельзя переставить в
-- другую запись или подменить владельца, не сломав проверку GCM.
CREATE TABLE app.secret_record (
    id           bigserial PRIMARY KEY,
    ext_id       uuid UNIQUE NOT NULL,
    owner_id     bigint NOT NULL REFERENCES app.account(id) ON DELETE CASCADE,
    key_version  smallint NOT NULL DEFAULT 1,
    title_nonce  bytea NOT NULL CHECK (length(title_nonce) = 12),
    title_ct     bytea NOT NULL,
    body_nonce   bytea NOT NULL CHECK (length(body_nonce) = 12),
    body_ct      bytea NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    updated_at   timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX ON app.secret_record (owner_id);

-- 5.5 Слепой индекс для поиска по шифротексту ------------------------------
CREATE TABLE app.secret_tag (
    record_id  bigint NOT NULL REFERENCES app.secret_record(id) ON DELETE CASCADE,
    tag        bytea NOT NULL CHECK (length(tag) = 16),
    PRIMARY KEY (record_id, tag)
);
CREATE INDEX ON app.secret_tag (tag);

-- 5.6 Журнал аудита (append-only) -----------------------------------------
CREATE TABLE app.audit_event (
    id          bigserial PRIMARY KEY,
    at          timestamptz NOT NULL DEFAULT now(),
    actor_id    bigint REFERENCES app.account(id) ON DELETE SET NULL,
    actor_login citext,
    action      text NOT NULL,
    object_kind text,
    object_id   bigint,
    ip_addr     inet,
    outcome     text NOT NULL CHECK (outcome IN ('ok', 'denied', 'error'))
);
-- Никаких открытых данных в журнал не пишется: только идентификаторы.

-- 5.7 Привилегии сервисной роли -------------------------------------------
GRANT SELECT, INSERT, UPDATE, DELETE
    ON app.account, app.session, app.public_note,
       app.secret_record, app.secret_tag            TO vault_app;
GRANT INSERT, SELECT ON app.audit_event             TO vault_app;
-- UPDATE/DELETE на журнал не выданы намеренно: скомпрометированное
-- приложение не сможет затереть следы.
GRANT USAGE ON ALL SEQUENCES IN SCHEMA app          TO vault_app;

-- 5.8 RLS: изоляция строк по владельцу ------------------------------------
-- Второй, независимый от кода приложения контур контроля доступа.
-- Даже успешная инъекция в текст запроса не выдаст строки чужого владельца.
-- Владельцем таблиц является postgres, а НЕ vault_app: владелец таблицы по
-- умолчанию не подчиняется построчной защите, и если бы владельцем была
-- сервисная роль, все политики ниже не действовали бы на приложение.
-- FORCE ROW LEVEL SECURITY сознательно не включается: обход политики
-- владельцем нужен представлению app.secret_metadata (см. 5.9), а вреда
-- не несёт - в таблице нет открытого текста.
ALTER TABLE app.secret_record ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_secrets ON app.secret_record FOR ALL TO vault_app
    USING      (owner_id = nullif(current_setting('app.actor_id', true), '')::bigint)
    WITH CHECK (owner_id = nullif(current_setting('app.actor_id', true), '')::bigint);

-- Теги слепого индекса закрыты той же политикой через вложенный запрос:
-- сами теги открытого текста не содержат, но раскрывали бы равенство
-- токенов между пользователями.
ALTER TABLE app.secret_tag ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_tags ON app.secret_tag FOR ALL TO vault_app
    USING (EXISTS (SELECT 1 FROM app.secret_record r
                   WHERE r.id = secret_tag.record_id));

ALTER TABLE app.public_note ENABLE ROW LEVEL SECURITY;

CREATE POLICY note_owner_rw ON app.public_note FOR ALL TO vault_app
    USING      (owner_id = nullif(current_setting('app.actor_id', true), '')::bigint)
    WITH CHECK (owner_id = nullif(current_setting('app.actor_id', true), '')::bigint);

CREATE POLICY note_public_read ON app.public_note FOR SELECT TO vault_app
    USING (visibility = 'public');

-- Администратор системы: полный доступ к НЕконфиденциальной подсистеме.
-- Признак передаётся вторым локальным параметром транзакции.
CREATE POLICY note_admin ON app.public_note FOR ALL TO vault_app
    USING      (current_setting('app.is_admin', true) = 'on')
    WITH CHECK (current_setting('app.is_admin', true) = 'on');
```

### 5.9 Представление метаданных конфиденциальных записей

Администратору нужен обзор конфиденциальных записей, но не их содержимое.
Представление принадлежит `postgres` и исполняется с правами владельца
(`security_invoker = false` по умолчанию), поэтому обходит RLS таблицы, но
не отдаёт ни одного столбца с шифротекстом:

```sql
CREATE VIEW app.secret_metadata AS
SELECT r.id, r.ext_id, r.owner_id, a.login AS owner_login,
       length(r.title_ct) AS title_bytes, length(r.body_ct) AS body_bytes,
       r.key_version, r.created_at, r.updated_at
FROM app.secret_record r
JOIN app.account a ON a.id = r.owner_id;

GRANT SELECT ON app.secret_metadata TO vault_app;
```

Приложение в начале каждой транзакции выполняет
`SET LOCAL app.actor_id = %s` (параметризованно). `SET LOCAL` действует до
конца транзакции, поэтому значение не «протекает» между запросами из пула
соединений — это критично и проверяется тестом.

---

## 6. Криптография и работа с конфиденциальностью

### 6.1 Пароли

Argon2id, параметры: `time_cost=3`, `memory_cost=64 MiB`, `parallelism=4`,
`hash_len=32`, соль 16 байт (генерируется библиотекой на каждый пароль).
Хранится строка формата PHC — параметры едут вместе с хешем, что позволяет
поднять стоимость позже и перехешировать при следующем успешном входе
(`argon2.PasswordHasher.check_needs_rehash`).

Политика пароля: минимум 12 символов, проверка по списку топ-10000
скомпрометированных паролей. Ставка на длину, а не на «обязательный
спецсимвол» — так требует и практика NIST SP 800-63B.

### 6.2 Шифрование конфиденциальных записей

- Алгоритм: **AES-256-GCM** (AEAD: конфиденциальность + целостность одним
  примитивом).
- Nonce: 12 случайных байт на **каждую** операцию шифрования. Повтор nonce
  на одном ключе разрушает GCM, поэтому nonce никогда не переиспользуется
  при редактировании — запись перешифровывается с новым nonce.
- AAD (связанные данные, не шифруются, но аутентифицируются):
  `ext_id || owner_id || key_version || field_name`. Это привязывает
  шифротекст к конкретной записи, владельцу, версии ключа и полю.
  Перестановка шифротекста между записями или пользователями ломает
  проверку тега.

### 6.3 Управление ключами

Мастер-ключ (32 байта) читается из `/etc/pziis-vault/keys.env`
(`0640 root:pziis`), в код и в git не попадает. Из него через HKDF-SHA256
выводятся два независимых подключа с разными `info`:

```
K_enc = HKDF(master, info=b"pziis-vault/v1/aes-gcm")
K_idx = HKDF(master, info=b"pziis-vault/v1/blind-index")
```

Разделение обязательно: один и тот же ключ нельзя использовать и для
шифрования, и для индексации. Колонка `key_version` открывает путь к
ротации ключа без простоя (двойное чтение: новые записи — v2, старые
дочитываются v1 и лениво перешифровываются).

### 6.4 Поиск по зашифрованным данным — центральный компромисс работы

Требование «осуществить поиск конфиденциальных данных» противоречит
шифрованию: по шифротексту AES-GCM искать нельзя, а расшифровывать всю
таблицу на каждый запрос — и медленно, и опасно.

**Решение — слепой индекс (blind index).** При сохранении записи
приложение:

1. нормализует заголовок: NFKC, нижний регистр, разбиение на токены,
   отбрасывание токенов короче 3 символов;
2. для каждого токена считает
   `tag = HMAC-SHA256(K_idx, owner_id ‖ token)[:16]`;
3. складывает теги в `app.secret_tag`.

Поиск: тот же HMAC от поисковой фразы, затем `SELECT` по `tag`.

**Что утекает при полном дампе БД.** Не открытый текст, но *равенство и
частота* токенов: видно, что две записи одного владельца содержат
одинаковое слово, и как часто слово встречается. Для словарных полей
(например, названия организаций) это делает возможным частотный анализ.

**Как компромисс ограничен:**

- идентификатор владельца входит в вычисление тега, поэтому одинаковые
  слова у разных пользователей дают разные теги: частотный анализ ограничен
  пределами одной учётной записи и не работает по базе целиком;
- индексируется **только заголовок**, тело записи не индексируется вообще;
- `tag` усечён до 16 байт — коллизии дают ложноположительные совпадения,
  которые приложение отбрасывает после расшифровки; это дополнительно
  размывает частотную статистику;
- токены короче 3 символов не индексируются;
- `K_idx` лежит вне базы, поэтому дамп БД без доступа к файловой системе
  не позволяет даже построить словарь тегов.

Альтернативы, отвергнутые сознательно: детерминированное шифрование поля
(утечка равенства целых значений — хуже), поиск по расшифрованному кэшу в
памяти (открытый текст в RAM и в swap), полноценное searchable encryption
(несоразмерно объёму лабораторной работы). Этот выбор и его цена — то, что
подлежит защите на сдаче.

### 6.5 Сессии и деавторизация

- Токен: `secrets.token_urlsafe(32)` — 256 бит энтропии от CSPRNG.
- В БД — только `SHA-256(токен)`; поиск по `token_hash` с постоянным
  временем сравнения на стороне БД по уникальному индексу.
- Cookie: `HttpOnly; Secure; SameSite=Strict; Path=/`.
  `HttpOnly` — токен недостижим из JS даже при XSS;
  `Secure` — не уйдёт по HTTP; `SameSite=Strict` — базовая защита от CSRF.
- Двойной срок жизни: 30 минут неактивности и 12 часов абсолютно.
- Идентификатор сессии **пересоздаётся при входе** — защита от фиксации
  сессии (CWE-384).
- CSRF: помимо `SameSite` — токен в скрытом поле формы, сверяется с
  `csrf_hash` сессии для всех небезопасных методов.
- **Деавторизация = удаление строки сессии на сервере.** Именно поэтому
  выбран opaque-токен, а не JWT: отзыв мгновенный и полный. Дополнительно
  `POST /logout/all` закрывает все сессии учётной записи.

### 6.6 Противодействие перебору

| Мера | Параметр |
|---|---|
| Лимит на уровне nginx | 5 запросов/мин на `/login` с одного IP |
| Лимит на учётную запись | 10 неудач → блокировка на 15 минут (`locked_until`) |
| Задержка ответа | фиксированные ~200 мс на любой неуспешный вход |
| Единый текст ошибки | «Неверный логин или пароль» — без раскрытия существования учётной записи (CWE-204) |
| Проверка пароля при неизвестном логине | всё равно выполняется Argon2 по фиктивному хешу — иначе разница во времени ответа выдаёт существующие логины |

---

## 7. Функции и точки входа

| Метод и путь | Роль | Назначение |
|---|---|---|
| `POST /register` | анонимно | Требование №1: добавление пользователя, роль `guest` |
| `POST /login` | анонимно | Требование №2: авторизация |
| `POST /logout`, `POST /logout/all` | любая | Требование №5: деавторизация |
| `GET /notes`, `POST /notes`, `POST /notes/{id}/edit`, `POST /notes/{id}/delete` | user, admin | Требование №4: CRUD неконфиденциальных данных |
| `GET /notes?q=` | guest, user, admin | Требование №4: поиск (`search_vec @@ plainto_tsquery`) |
| `GET /secrets`, `POST /secrets`, `POST /secrets/{id}/edit`, `POST /secrets/{id}/delete` | user, admin (свои) | Требование №3: CRUD конфиденциальных данных |
| `POST /secrets/search` | user, admin (свои) | Требование №3: поиск по слепому индексу (метод POST, чтобы фраза не осела в журналах) |
| `GET/POST /admin/accounts`, `POST /admin/accounts/{id}/{role,active,delete}` | admin | управление учётными записями, ролями, блокировками |
| `GET /admin/secrets` | admin | обзор конфиденциальных записей: только метаданные |
| `GET /admin/audit` | admin | чтение журнала аудита |
| `GET /healthz` | анонимно | проверка живости, без раскрытия версий и конфигурации |

Изменяющие операции выполняются методом `POST`, а не `PUT`/`DELETE`:
клиент - серверные HTML-формы, а формы других методов не поддерживают.
Это не ослабляет защиту (CSRF-токен требуется для любого изменяющего
запроса), но избавляет от JavaScript, которого в приложении нет вовсе -
политика CSP задаёт `script-src 'none'`.

Правила, общие для всех обработчиков:

1. Валидация входа — Pydantic-моделью до попадания в бизнес-логику
   (белый список полей, длины, типы).
2. Авторизация — декоратор `@require(role, owner_check)`; проверка права
   выполняется **до** чтения объекта, а не после.
3. Все SQL-запросы параметризованы; конкатенации строк в SQL нет ни одной.
4. Ошибки наружу — обобщённые; трассировка и текст исключения СУБД идут
   только в журнал сервера (CWE-209).
5. Каждое изменение данных и каждая попытка входа — запись в
   `app.audit_event`.

---

## 8. Развёртывание и ужесточение окружения

### 8.1 Операционная система

```
Пользователь:  pziis (systemd-система, shell /usr/sbin/nologin, без домашнего каталога)
/opt/pziis-vault        0750 root:pziis     код (запись только у root)
/etc/pziis-vault/keys.env 0640 root:pziis   ключи и пароль к БД
/var/log/pziis-vault    0750 pziis:adm      журналы
umask сервиса           0027
```

Код принадлежит `root`, а исполняется от `pziis`: сервис не может
перезаписать собственные исполняемые файлы. Ни одного setuid-бинаря
приложение не устанавливает.

### 8.2 systemd-юнит

```ini
[Service]
User=pziis
Group=pziis
ExecStart=/opt/pziis-vault/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port 8000
EnvironmentFile=/etc/pziis-vault/keys.env

NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
ReadWritePaths=/var/log/pziis-vault
CapabilityBoundingSet=
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_UNIX
MemoryDenyWriteExecute=yes
SystemCallFilter=@system-service
SystemCallArchitectures=native
LockPersonality=yes
```

`CapabilityBoundingSet=` пуст: процессу не нужна ни одна capability, порт
443 слушает nginx. `ProtectSystem=strict` делает всю файловую систему
доступной только на чтение, кроме явно перечисленного `ReadWritePaths`.

### 8.3 Сеть

| Компонент | Настройка |
|---|---|
| ufw | `default deny incoming`, разрешён только 443/tcp (22/tcp — по ситуации демонстрации) |
| nginx | TLS 1.2/1.3, только AEAD-шифронаборы, `ssl_prefer_server_ciphers off`, OCSP stapling, HSTS `max-age=31536000; includeSubDomains` |
| uvicorn | `--host 127.0.0.1` — извне недостижим в принципе |
| PostgreSQL | `listen_addresses = 'localhost'`, `pg_hba.conf`: `scram-sha-256` для `vault_app`, метод `trust` отсутствует |
| Заголовки | `Content-Security-Policy: default-src 'self'; object-src 'none'; frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` |
| Тело запроса | `client_max_body_size 64k` — дешёвая отсечка примитивного flood |

Для демонстрации в ВМ — самоподписанный сертификат; в отчёте отмечается,
что в реальной эксплуатации требуется сертификат доверенного УЦ, иначе
защита от «человека посередине» неполна.
