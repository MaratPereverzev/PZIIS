#!/usr/bin/env python3
"""Лабораторная работа №1 по ПЗИИС. Часть 2.

Управление доступом к системам управления базами данных.
Вариант: PostgreSQL - реляционная СУБД.

Программа объединяет четыре требуемые заданием программы в одно меню:
  1) установка СУБД;
  2) настройка механизма контроля доступа (ролевая модель);
  3) проверка корректности настроенной политики безопасности;
  4) полное удаление СУБД и созданных ею объектов файловой системы.

Запускается от имени root ВНУТРИ одноразовой виртуальной машины или
контейнера: пункт 4 безвозвратно удаляет пакеты PostgreSQL, каталог данных
и системного пользователя postgres.
"""

import os
import shlex
import subprocess
import sys
import time

DB_NAME = "app_db"
SCHEMA = "app"

# Роли политики безопасности и их учётные записи (см. требования задания:
# администратор, пользователь, гость).
ACCOUNTS = [
    ("admin_sys", "Admin_123", "admin_role", "администратор системы"),
    ("user_sub", "User_123", "user_role", "пользователь подсистемы"),
    ("guest_read", "Guest_123", "guest_role", "гость"),
]
ROLES = ["admin_role", "user_role", "guest_role"]
POSTGRES_PASSWORD = "Postgres_123"

LOG_PATH = "/lab/part2.log" if os.path.isdir("/lab") else "part2.log"


# --------------------------------------------------------------------------
# Инфраструктура
# --------------------------------------------------------------------------

class Result:
    __slots__ = ("code", "out", "err")

    def __init__(self, code, out="", err=""):
        self.code = code
        self.out = out
        self.err = err

    @property
    def ok(self):
        return self.code == 0

    def reason(self):
        text = (self.err or self.out).strip().splitlines()
        return text[-1][:90] if text else "код возврата %d" % self.code


def q(value):
    return shlex.quote(str(value))


def run(cmd, verbose=False, timeout=900, env=None, stdin_text=None):
    full_env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    if env:
        full_env.update(env)
    try:
        proc = subprocess.run(
            ["/bin/sh", "-c", cmd], text=True, timeout=timeout, env=full_env,
            input=stdin_text,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except subprocess.TimeoutExpired:
        return Result(124, "", "превышено время ожидания команды")
    res = Result(proc.returncode, proc.stdout, proc.stderr)
    if verbose:
        if res.out.strip():
            print(res.out.rstrip())
        if res.err.strip():
            print(res.err.rstrip())
    return res


def section(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def assert_disposable_env(force=False):
    """Отказывается работать на рабочей машине.

    Пункт 4 меню выполняет apt purge пакетов PostgreSQL и удаляет каталог
    /var/lib/postgresql со всеми базами, поэтому запуск вне одноразового
    окружения недопустим.
    """
    if force:
        return
    if os.path.exists("/.dockerenv") or os.path.exists("/run/.containerenv"):
        return
    try:
        with open("/proc/1/cgroup", encoding="utf-8") as handle:
            if any(tag in handle.read() for tag in ("docker", "lxc", "podman")):
                return
    except OSError:
        pass
    virt = run("systemd-detect-virt 2>/dev/null")
    if virt.ok and virt.out.strip() not in ("", "none"):
        return
    sys.exit(
        "Отказ: окружение не распознано как одноразовое (контейнер или ВМ).\n"
        "Пункт 4 меню удаляет пакеты PostgreSQL и каталог /var/lib/postgresql.\n"
        "Запустите программу через ./run.sh либо подтвердите флагом --force."
    )


# --------------------------------------------------------------------------
# Состояние СУБД
# --------------------------------------------------------------------------

def is_installed():
    return run("command -v psql > /dev/null").ok


def cluster_version():
    """Версия установленного кластера, например 16."""
    res = run("ls /etc/postgresql 2>/dev/null")
    versions = sorted(res.out.split())
    return versions[-1] if versions else None


def has_systemd():
    return os.path.exists("/run/systemd/system")


def is_running():
    return run("runuser -u postgres -- psql -tAc 'SELECT 1' > /dev/null 2>&1").ok


def start_cluster():
    """Запуск кластера. В контейнере systemd отсутствует, поэтому
    используется штатная для Debian/Ubuntu обёртка pg_ctlcluster."""
    if has_systemd():
        run("systemctl enable --now postgresql", verbose=True)
    version = cluster_version()
    if version and not is_running():
        run("pg_ctlcluster %s main start" % q(version), verbose=True)
    for _ in range(20):
        if is_running():
            return True
        time.sleep(0.5)
    return False


def stop_cluster():
    if has_systemd():
        run("systemctl stop postgresql")
    version = cluster_version()
    if version:
        run("pg_ctlcluster %s main stop --mode fast" % q(version))
    run("pkill -9 -u postgres")


def psql_admin(sql, database="postgres"):
    """Выполнение SQL от имени суперпользователя postgres через сокет."""
    return run("runuser -u postgres -- psql -v ON_ERROR_STOP=1 -d %s -f -"
               % q(database), stdin_text=sql)


def psql_as(user, password, sql, database=DB_NAME, tuples_only=False):
    """Выполнение SQL от имени учётной записи СУБД по TCP с паролем.

    Подключение идёт именно по TCP, чтобы реально проверялась парольная
    аутентификация, а не локальный метод peer.
    """
    flags = "-tA" if tuples_only else ""
    cmd = ("psql -h 127.0.0.1 -p 5432 -U %s -d %s %s -v ON_ERROR_STOP=1 -c %s"
           % (q(user), q(database), flags, q(sql)))
    return run(cmd, env={"PGPASSWORD": password})


# --------------------------------------------------------------------------
# Пункт 1. Установка
# --------------------------------------------------------------------------

def release_apt_locks():
    print("Проверка блокировок dpkg/apt...")
    locks = [
        "/var/lib/dpkg/lock-frontend",
        "/var/lib/dpkg/lock",
        "/var/cache/apt/archives/lock",
        "/var/lib/apt/lists/lock",
    ]
    busy = any(run("lsof %s 2>/dev/null" % q(lock)).out.strip() for lock in locks)
    if not busy:
        return
    print("Обнаружены блокировки, завершение процессов apt/dpkg...")
    run("killall apt-get apt dpkg 2>/dev/null")
    time.sleep(1)
    for lock in locks:
        run("rm -f %s" % q(lock))
    run("dpkg --configure -a")


def configure_hba():
    """Требует парольную аутентификацию для подключений по TCP."""
    version = cluster_version()
    if not version:
        return
    path = "/etc/postgresql/%s/main/pg_hba.conf" % version
    with open(path, encoding="utf-8") as handle:
        lines = handle.readlines()

    marker = "# ПЗИИС: парольная аутентификация для локальных TCP-подключений\n"
    lines = [line for line in lines
             if line != marker and not line.startswith("host    all             all")]
    lines.append("\n" + marker)
    lines.append("host    all             all             127.0.0.1/32            scram-sha-256\n")
    lines.append("host    all             all             ::1/128                 scram-sha-256\n")
    with open(path, "w", encoding="utf-8") as handle:
        handle.writelines(lines)
    print("Настроен %s: подключения по TCP требуют пароль (scram-sha-256)." % path)
    run("pg_ctlcluster %s main reload" % q(version))


def install():
    section("Пункт 1. Установка PostgreSQL")

    if is_installed():
        print("PostgreSQL уже установлена. Для переустановки сначала выполните"
              " пункт 4.")
        return

    release_apt_locks()

    print("Обновление списков пакетов...")
    run("apt-get update -qq")

    print("Установка пакетов postgresql и postgresql-contrib...")
    res = run("apt-get install -y -qq postgresql postgresql-contrib")
    if not res.ok:
        print("Ошибка установки пакетов: %s" % res.reason())
        return
    installed = run("dpkg -l | awk '/^ii/ && $2 ~ /postgres/ {print $2}'").out.split()
    print("Установлены пакеты: %s" % ", ".join(installed))

    version = cluster_version()
    if not version:
        print("Ошибка: каталог конфигурации кластера не найден.")
        return
    print("Версия кластера: %s" % version)

    if not os.path.exists("/var/lib/postgresql/%s/main" % version):
        print("Кластер не создан postinst-сценарием, создаю вручную...")
        run("pg_createcluster %s main" % q(version), verbose=True)

    run("mkdir -p /var/run/postgresql")
    run("chown -R postgres:postgres /var/lib/postgresql /var/run/postgresql")
    run("chmod 700 /var/lib/postgresql/%s/main" % q(version))
    print("Каталог данных: /var/lib/postgresql/%s/main" % version)

    print("Запуск кластера...")
    if not start_cluster():
        print("Кластер не запустился.")
        run("tail -20 /var/log/postgresql/postgresql-%s-main.log" % q(version),
            verbose=True)
        return

    res = psql_admin("ALTER ROLE postgres WITH PASSWORD %s;"
                     % sql_literal(POSTGRES_PASSWORD))
    print("Пароль суперпользователя postgres установлен: %s"
          % ("да" if res.ok else res.reason()))

    configure_hba()

    print()
    run("psql --version", verbose=True)
    print("PostgreSQL успешно установлена и запущена.")


def sql_literal(value):
    return "'" + str(value).replace("'", "''") + "'"


# --------------------------------------------------------------------------
# Пункт 2. Настройка политики безопасности
# --------------------------------------------------------------------------

def build_global_sql():
    """Роли и база данных: объекты уровня кластера."""
    lines = ["DROP DATABASE IF EXISTS %s;" % DB_NAME]
    for account, _, _, _ in ACCOUNTS:
        lines.append("DROP ROLE IF EXISTS %s;" % account)
    for role in ROLES:
        lines.append("DROP ROLE IF EXISTS %s;" % role)

    for role in ROLES:
        lines.append("CREATE ROLE %s NOLOGIN;" % role)
    for account, password, role, _ in ACCOUNTS:
        lines.append("CREATE ROLE %s LOGIN PASSWORD %s;"
                     % (account, sql_literal(password)))
        lines.append("GRANT %s TO %s;" % (role, account))

    # Атрибуты роли (в отличие от привилегий) не наследуются через членство,
    # поэтому максимальные полномочия выдаются учётной записи администратора
    # напрямую. BYPASSRLS нужен, чтобы администратор видел все строки таблиц
    # с включённой построчной защитой.
    lines.append("ALTER ROLE admin_sys CREATEDB CREATEROLE BYPASSRLS;")
    lines.append("GRANT pg_read_all_data, pg_write_all_data TO admin_role;")

    lines.append("CREATE DATABASE %s;" % DB_NAME)
    # Без явного отзыва привилегия CONNECT досталась бы псевдороли PUBLIC,
    # то есть вообще всем учётным записям кластера.
    lines.append("REVOKE ALL ON DATABASE %s FROM PUBLIC;" % DB_NAME)
    lines.append("GRANT ALL PRIVILEGES ON DATABASE %s TO admin_role"
                 " WITH GRANT OPTION;" % DB_NAME)
    lines.append("GRANT CONNECT ON DATABASE %s TO user_role, guest_role;"
                 % DB_NAME)

    # Служебная база postgres по умолчанию доступна псевдороли PUBLIC.
    # Через неё пользователь и гость видели бы каталоги всего кластера,
    # что противоречит принципу минимальных привилегий.
    lines.append("REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;")
    lines.append("GRANT CONNECT ON DATABASE postgres TO admin_role;")
    return "\n".join(lines) + "\n"


def build_schema_sql():
    """Схема, таблицы, данные и привилегии внутри базы app_db."""
    return """
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA {schema};

CREATE TABLE {schema}.public_data (
    id          integer PRIMARY KEY,
    data        varchar(100) NOT NULL,
    visibility  varchar(16) NOT NULL DEFAULT 'public'
);

CREATE TABLE {schema}.private_data (
    id      integer PRIMARY KEY,
    secret  varchar(100) NOT NULL
);

INSERT INTO {schema}.public_data (id, data, visibility) VALUES
    (1, 'Общедоступная запись 1', 'public'),
    (2, 'Общедоступная запись 2', 'public'),
    (3, 'Общедоступная запись 3', 'public'),
    (4, 'Внутренняя запись 1',    'internal'),
    (5, 'Внутренняя запись 2',    'internal');

INSERT INTO {schema}.private_data (id, secret) VALUES
    (1, 'Секретные данные 1'),
    (2, 'Секретные данные 2');

-- Администратор: полный доступ ко всем подсистемам базы данных
-- с правом передачи привилегий дальше.
GRANT ALL PRIVILEGES ON SCHEMA {schema} TO admin_role WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA {schema} TO admin_role
    WITH GRANT OPTION;

-- Пользователь: полные права на данные в выданной администратором
-- подсистеме (схеме app), но без права менять её структуру.
GRANT USAGE ON SCHEMA {schema} TO user_role;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA {schema}
    TO user_role;

-- Гость: только чтение отдельных фрагментов. Ограничение задаётся сразу
-- по двум измерениям - по столбцам (привилегия выдана лишь на id и data,
-- служебный столбец visibility недоступен) и по строкам (политика RLS
-- показывает только записи с visibility = 'public').
GRANT USAGE ON SCHEMA {schema} TO guest_role;
GRANT SELECT (id, data) ON {schema}.public_data TO guest_role;

ALTER TABLE {schema}.public_data ENABLE ROW LEVEL SECURITY;

CREATE POLICY guest_public_rows ON {schema}.public_data
    FOR SELECT TO guest_role
    USING (visibility = 'public');

CREATE POLICY user_all_rows ON {schema}.public_data
    FOR ALL TO user_role
    USING (true) WITH CHECK (true);
""".format(schema=SCHEMA)


def configure():
    section("Пункт 2. Настройка политики безопасности")

    if not is_installed():
        print("Ошибка: PostgreSQL не установлена. Сначала выполните пункт 1.")
        return
    if not is_running() and not start_cluster():
        print("Ошибка: не удалось запустить кластер PostgreSQL.")
        return

    print("Создание ролей, учётных записей и базы данных...")
    res = psql_admin(build_global_sql())
    if not res.ok:
        print("Ошибка: %s" % res.reason())
        return

    print("Создание схемы, таблиц и выдача привилегий...")
    res = psql_admin(build_schema_sql(), database=DB_NAME)
    if not res.ok:
        print("Ошибка: %s" % res.reason())
        return

    print()
    print("Настроенная ролевая модель:")
    print("  %-12s %-12s %s" % ("роль", "учётная запись", "полномочия"))
    print("  " + "-" * 72)
    print("  %-12s %-12s %s" % ("admin_role", "admin_sys",
                                "все привилегии на app_db и схему app, "
                                "CREATEDB, CREATEROLE, BYPASSRLS"))
    print("  %-12s %-12s %s" % ("user_role", "user_sub",
                                "SELECT/INSERT/UPDATE/DELETE во всех таблицах "
                                "схемы app"))
    print("  %-12s %-12s %s" % ("guest_role", "guest_read",
                                "SELECT только столбцов (id, data) таблицы "
                                "public_data"))
    print("  %-12s %-12s %s" % ("", "", "и только строк с visibility = 'public'"))
    print()
    print("Политика безопасности настроена.")


# --------------------------------------------------------------------------
# Пункт 3. Проверка политики безопасности
# --------------------------------------------------------------------------

def build_checks():
    """(описание, учётная запись, SQL, ожидается ли успех)."""
    a_user, a_pass = ACCOUNTS[0][0], ACCOUNTS[0][1]
    u_user, u_pass = ACCOUNTS[1][0], ACCOUNTS[1][1]
    g_user, g_pass = ACCOUNTS[2][0], ACCOUNTS[2][1]
    s = SCHEMA
    return [
        ("Администратор: список баз данных", a_user, a_pass,
         "SELECT datname FROM pg_database;", True),
        ("Администратор: чтение private_data", a_user, a_pass,
         "SELECT * FROM %s.private_data;" % s, True),
        ("Администратор: создание таблицы", a_user, a_pass,
         "CREATE TABLE %s.tmp_check(id int); DROP TABLE %s.tmp_check;" % (s, s),
         True),
        ("Администратор: выдача привилегий", a_user, a_pass,
         "GRANT SELECT ON %s.private_data TO admin_role;" % s, True),
        ("Администратор: создание роли", a_user, a_pass,
         "CREATE ROLE tmp_check_role; DROP ROLE tmp_check_role;", True),

        ("Пользователь: чтение public_data", u_user, u_pass,
         "SELECT * FROM %s.public_data;" % s, True),
        ("Пользователь: чтение private_data", u_user, u_pass,
         "SELECT * FROM %s.private_data;" % s, True),
        ("Пользователь: вставка в public_data", u_user, u_pass,
         "INSERT INTO %s.public_data (id, data) VALUES (900, 'проверка');" % s,
         True),
        ("Пользователь: изменение public_data", u_user, u_pass,
         "UPDATE %s.public_data SET data = 'изменено' WHERE id = 900;" % s, True),
        ("Пользователь: удаление из public_data", u_user, u_pass,
         "DELETE FROM %s.public_data WHERE id = 900;" % s, True),
        ("Пользователь: создание таблицы (ожидается отказ)", u_user, u_pass,
         "CREATE TABLE %s.tmp_user(id int);" % s, False),
        ("Пользователь: смена владельца таблицы (ожидается отказ)",
         u_user, u_pass,
         "ALTER TABLE %s.private_data OWNER TO %s;" % (s, u_user), False),
        ("Пользователь: удаление таблицы (ожидается отказ)", u_user, u_pass,
         "DROP TABLE %s.private_data;" % s, False),
        ("Пользователь: создание базы данных (ожидается отказ)", u_user, u_pass,
         "CREATE DATABASE tmp_user_db;", False),

        ("Гость: чтение разрешённых столбцов public_data", g_user, g_pass,
         "SELECT id, data FROM %s.public_data;" % s, True),
        ("Гость: чтение всех столбцов public_data (ожидается отказ)",
         g_user, g_pass, "SELECT * FROM %s.public_data;" % s, False),
        ("Гость: чтение private_data (ожидается отказ)", g_user, g_pass,
         "SELECT * FROM %s.private_data;" % s, False),
        ("Гость: вставка в public_data (ожидается отказ)", g_user, g_pass,
         "INSERT INTO %s.public_data (id, data) VALUES (901, 'отказ');" % s,
         False),
        ("Гость: изменение public_data (ожидается отказ)", g_user, g_pass,
         "UPDATE %s.public_data SET data = 'отказ' WHERE id = 1;" % s, False),
        ("Гость: подключение к postgres (ожидается отказ)", g_user, g_pass,
         "SELECT 1;", False),
    ]


def verify():
    section("Пункт 3. Проверка корректности политики безопасности")

    if not is_installed():
        print("Ошибка: PostgreSQL не установлена. Сначала выполните пункт 1.")
        return
    if not is_running() and not start_cluster():
        print("Ошибка: не удалось запустить кластер PostgreSQL.")
        return
    probe = psql_as(ACCOUNTS[0][0], ACCOUNTS[0][1], "SELECT 1;")
    if not probe.ok:
        print("Ошибка: политика безопасности не настроена или недоступна"
              " (%s)." % probe.reason())
        print("Сначала выполните пункт 2.")
        return

    print("  %-56s %-10s %-10s %s"
          % ("проверка", "ожидание", "результат", "итог"))
    print("  " + "-" * 92)

    passed = 0
    checks = build_checks()
    for label, user, password, sql, expected in checks:
        database = "postgres" if "postgres" in label else DB_NAME
        res = psql_as(user, password, sql, database=database)
        actual = res.ok
        good = actual == expected
        passed += good
        print("  %-56s %-10s %-10s %s"
              % (label,
                 "успех" if expected else "отказ",
                 "успех" if actual else "отказ",
                 "PASS" if good else "FAIL"))

    # Отдельная проверка: попытка пользователя расширить права гостя.
    # PostgreSQL на команду GRANT от лица не-владельца выдаёт не ошибку,
    # а предупреждение, и код возврата psql остаётся нулевым, поэтому
    # проверять нужно результат, а не факт выполнения команды.
    psql_as(ACCOUNTS[1][0], ACCOUNTS[1][1],
            "GRANT SELECT ON %s.private_data TO guest_role;" % SCHEMA)
    leaked = psql_as(ACCOUNTS[2][0], ACCOUNTS[2][1],
                     "SELECT * FROM %s.private_data;" % SCHEMA).ok
    passed += not leaked
    print("  %-56s %-10s %-10s %s"
          % ("Пользователь: расширение прав гостя не имеет эффекта",
             "отказ", "успех" if leaked else "отказ",
             "FAIL" if leaked else "PASS"))

    # Отдельная проверка построчной защиты: гость обязан видеть строго
    # меньше строк, чем администратор.
    total = psql_as(ACCOUNTS[0][0], ACCOUNTS[0][1],
                    "SELECT count(*) FROM %s.public_data;" % SCHEMA,
                    tuples_only=True).out.strip()
    seen = psql_as(ACCOUNTS[2][0], ACCOUNTS[2][1],
                   "SELECT count(*) FROM %s.public_data;" % SCHEMA,
                   tuples_only=True).out.strip()
    rls_ok = total.isdigit() and seen.isdigit() and int(seen) < int(total)
    passed += rls_ok
    print("  %-56s %-10s %-10s %s"
          % ("Гость: построчная защита public_data",
             "меньше", "%s из %s" % (seen or "?", total or "?"),
             "PASS" if rls_ok else "FAIL"))

    total_checks = len(checks) + 2
    print()
    print("Итог: пройдено %d из %d проверок." % (passed, total_checks))
    if passed == total_checks:
        print("Политика безопасности работает корректно.")
    else:
        print("Обнаружены расхождения с ожидаемой политикой безопасности.")


# --------------------------------------------------------------------------
# Пункт 4. Полное удаление
# --------------------------------------------------------------------------

def uninstall():
    section("Пункт 4. Полное удаление PostgreSQL")

    if not is_installed() and not os.path.exists("/var/lib/postgresql"):
        print("PostgreSQL в системе не обнаружена.")
        return

    release_apt_locks()

    version = cluster_version()
    print("Остановка кластера...")
    stop_cluster()
    if version:
        run("pg_dropcluster --stop %s main" % q(version), verbose=True)

    print("Удаление пакетов...")
    packages = run("dpkg -l | awk '/^ii/ && $2 ~ /postgresql/ {print $2}'").out.split()
    if packages:
        print("  удаляются: %s" % ", ".join(packages))
        run("apt-get purge -y -qq %s" % " ".join(q(p) for p in packages))
    run("apt-get autoremove -y -qq")
    run("apt-get autoclean -y -qq")

    print("Удаление конфигурационных файлов, каталогов данных и журналов...")
    for path in ("/etc/postgresql", "/etc/postgresql-common",
                 "/var/lib/postgresql", "/var/log/postgresql",
                 "/var/run/postgresql"):
        run("rm -rf %s" % q(path))
        print("  удалён %s" % path)

    print("Удаление системной учётной записи...")
    if run("id postgres > /dev/null 2>&1").ok:
        run("userdel -r postgres 2>/dev/null")
        print("  пользователь postgres удалён")
    if run("getent group postgres > /dev/null").ok:
        run("groupdel postgres 2>/dev/null")
        print("  группа postgres удалена")

    print()
    print("Проверка результата удаления:")
    leftovers = []
    if is_installed():
        leftovers.append("бинарный файл psql")
    for path in ("/etc/postgresql", "/var/lib/postgresql"):
        if os.path.exists(path):
            leftovers.append(path)
    if run("id postgres > /dev/null 2>&1").ok:
        leftovers.append("пользователь postgres")
    if leftovers:
        print("  в системе остались: %s" % ", ".join(leftovers))
    else:
        print("  PostgreSQL полностью удалена, следов в системе не осталось.")


# --------------------------------------------------------------------------
# Меню
# --------------------------------------------------------------------------

ACTIONS = {
    "1": ("Установить PostgreSQL", install),
    "2": ("Настроить политику безопасности", configure),
    "3": ("Проверить политику безопасности", verify),
    "4": ("Полностью удалить PostgreSQL", uninstall),
}


def menu():
    while True:
        print()
        print("=" * 50)
        print("Управление доступом к СУБД PostgreSQL")
        print("=" * 50)
        for key in sorted(ACTIONS):
            print("%s. %s" % (key, ACTIONS[key][0]))
        print("5. Выход")
        print("-" * 50)

        try:
            choice = input("Выберите действие (1-5): ").strip()
        except EOFError:
            print()
            return
        print()

        if choice == "4":
            confirm = input("Удалить PostgreSQL со всеми базами данных? (y/n): ")
            if confirm.strip().lower() != "y":
                print("Удаление отменено.")
                continue
            uninstall()
        elif choice in ACTIONS:
            ACTIONS[choice][1]()
        elif choice == "5":
            print("Выход.")
            return
        else:
            print("Неверный ввод, выберите пункт от 1 до 5.")


class Tee:
    def __init__(self, stream, path):
        self.stream = stream
        self.file = open(path, "a", encoding="utf-8")

    def write(self, data):
        self.stream.write(data)
        self.file.write(data)

    def flush(self):
        self.stream.flush()
        self.file.flush()


def main():
    argv = sys.argv[1:]
    force = "--force" in argv
    steps = None
    if "--steps" in argv:
        steps = argv[argv.index("--steps") + 1].split(",")

    if os.geteuid() != 0:
        sys.exit("Отказ: программа должна выполняться от имени root.")
    assert_disposable_env(force)

    sys.stdout = Tee(sys.__stdout__, LOG_PATH)
    print("Лабораторная работа №1 по ПЗИИС, часть 2.")
    print("Вариант: PostgreSQL - реляционная СУБД.")
    print("Журнал прогона: %s" % LOG_PATH)

    if steps:
        for step in steps:
            step = step.strip()
            if step in ACTIONS:
                ACTIONS[step][1]()
            else:
                print("Неизвестный шаг: %s" % step)
        sys.stdout.flush()
        return

    menu()
    sys.stdout.flush()


if __name__ == "__main__":
    main()
