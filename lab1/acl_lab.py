#!/usr/bin/env python3
"""Лабораторная работа №1 по ПЗИИС. Часть 1.

Управление доступом к объектам операционной системы с помощью списков
контроля доступа. Программа выполняет шаги 1-17 задания: создаёт группы,
пользователей, каталоги и файлы с заданными комбинациями прав, затем
систематически проверяет, что реально может делать каждый субъект, и в
конце полностью убирает за собой.

Запускается от имени root ВНУТРИ одноразовой виртуальной машины или
контейнера: программа создаёт и удаляет системных учётных записей.
"""

import os
import shlex
import shutil
import subprocess
import sys
import time

BASE_DIR = "/pzs"
# Эталонная копия набора файлов. Лежит вне BASE_DIR, чтобы не попадать
# в проверки листинга каталогов на шаге 16.
TEMPLATE_DIR = "/var/tmp/pzs_template"
LOG_PATH = "/lab/part1.log" if os.path.isdir("/lab") else "part1.log"

GROUPS = ["group_iit1", "group_iit2"]

# (имя пользователя, первичная группа)
USERS = [
    ("iit11", "group_iit1"),
    ("iit12", "group_iit1"),
    ("iit21", "group_iit2"),
    ("iit22", "group_iit2"),
    ("iit3", None),
]

# Субъекты, от имени которых выполняются все проверки.
SUBJECTS = ["iit11", "iit12", "iit21", "iit22", "iit3", "root"]

# Шаги 6-11. Владельцем pzs12 и pzs13 намеренно назначается root, а не iit11:
# класс "владелец" в POSIX имеет приоритет над классом "группа" и "остальные",
# поэтому при владельце iit11 он сам потерял бы доступ и шаг 13 (создание
# файлов от имени iit11) стал бы невыполнимым.
DIR_SPECS = [
    ("pzs11", 0o700, "iit11", "group_iit1", "rwx только владельцу"),
    ("pzs12", 0o070, "root", "group_iit1", "rwx только группе"),
    ("pzs13", 0o007, "root", "root", "rwx только остальным"),
    ("pzs14", 0o777, "root", "root", "rwx всем"),
    ("pzs15", 0o700, "root", "root", "rwx только администратору"),
]

# Каталоги, в которых создаётся набор файлов (шаг 13).
TARGET_DIRS = ["pzs11", "pzs12", "pzs13", "pzs14"]

# Шаг 13. (имя, режим, владелец, группа, описание)
FILE_SPECS = [
    ("file11", 0o400, "iit11", "group_iit1", "чтение, владелец"),
    ("file12", 0o600, "iit11", "group_iit1", "чтение+запись, владелец"),
    ("file13", 0o200, "iit11", "group_iit1", "запись, владелец"),
    ("file14", 0o700, "iit11", "group_iit1", "чтение+запись+выполнение, владелец"),
    ("file15", 0o100, "iit11", "group_iit1", "выполнение, владелец"),
    ("file21", 0o040, "iit11", "group_iit1", "чтение, группа"),
    ("file22", 0o060, "iit11", "group_iit1", "чтение+запись, группа"),
    ("file23", 0o020, "iit11", "group_iit1", "запись, группа"),
    ("file24", 0o070, "iit11", "group_iit1", "чтение+запись+выполнение, группа"),
    ("file25", 0o010, "iit11", "group_iit1", "выполнение, группа"),
    ("file31", 0o004, "iit11", "group_iit1", "чтение, остальные"),
    ("file32", 0o006, "iit11", "group_iit1", "чтение+запись, остальные"),
    ("file33", 0o002, "iit11", "group_iit1", "запись, остальные"),
    ("file34", 0o007, "iit11", "group_iit1", "чтение+запись+выполнение, остальные"),
    ("file35", 0o001, "iit11", "group_iit1", "выполнение, остальные"),
    ("file41", 0o444, "iit11", "group_iit1", "чтение, все"),
    ("file42", 0o666, "iit11", "group_iit1", "чтение+запись, все"),
    ("file43", 0o222, "iit11", "group_iit1", "запись, все"),
    ("file44", 0o777, "iit11", "group_iit1", "чтение+запись+выполнение, все"),
    ("file45", 0o111, "iit11", "group_iit1", "выполнение, все"),
    ("file51", 0o400, "root", "root", "чтение, администратор"),
    ("file52", 0o600, "root", "root", "чтение+запись, администратор"),
    ("file53", 0o200, "root", "root", "запись, администратор"),
    ("file54", 0o700, "root", "root", "чтение+запись+выполнение, администратор"),
    ("file55", 0o100, "root", "root", "выполнение, администратор"),
]

# Шаг 15. Файлы вида filex5 содержат блокирующий read, поэтому годятся
# для проверки управления процессами.
PROC_FILES = ["file15", "file25", "file35", "file45", "file55"]

# Субъект, которому класс прав файла filex5 в принципе разрешает выполнение,
# и бит чтения, которого этому классу не хватает (см. пояснение в run_step15).
PROC_RUNNER = {
    "file15": ("iit11", 0o400),
    "file25": ("iit12", 0o040),
    "file35": ("iit3", 0o004),
    "file45": ("iit11", 0o444),
    "file55": ("root", 0o400),
}


# --------------------------------------------------------------------------
# Инфраструктура: логирование и выполнение команд от имени субъектов
# --------------------------------------------------------------------------

class Tee:
    """Дублирует вывод программы в файл, чтобы приложить его к отчёту."""

    def __init__(self, stream, path):
        self.stream = stream
        self.file = open(path, "w", encoding="utf-8")

    def write(self, data):
        self.stream.write(data)
        self.file.write(data)

    def flush(self):
        self.stream.flush()
        self.file.flush()


def section(title):
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def q(value):
    return shlex.quote(str(value))


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
        """Короткая причина отказа для таблиц отчёта."""
        text = (self.err or self.out).strip().splitlines()
        if not text:
            return "код возврата %d" % self.code
        line = text[-1]
        for marker in ("Permission denied", "отказано в доступе",
                       "No such file", "cannot open", "not permitted"):
            if marker.lower() in line.lower():
                return marker
        return line[:60]


def run(cmd, user="root", stdin_text=None, timeout=20):
    """Выполняет команду оболочки от имени указанного субъекта.

    Для непривилегированных субъектов используется runuser, который меняет
    UID/GID процесса, но не открывает PAM-сессию, поэтому pid результата
    совпадает с pid запущенной команды.
    """
    if user == "root":
        argv = ["/bin/sh", "-c", cmd]
    else:
        argv = ["runuser", "-u", user, "--", "/bin/sh", "-c", cmd]
    try:
        proc = subprocess.run(
            argv, input=stdin_text, text=True, timeout=timeout,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
    except subprocess.TimeoutExpired:
        return Result(124, "", "превышено время ожидания")
    except OSError as exc:
        return Result(127, "", str(exc))
    return Result(proc.returncode, proc.stdout, proc.stderr)


def assert_disposable_env(force=False):
    """Отказывается работать на рабочей машине.

    Программа создаёт и удаляет системных пользователей и каталоги в корне
    файловой системы, поэтому запуск вне одноразового окружения недопустим.
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
        "Программа создаёт и удаляет системных пользователей и каталог %s.\n"
        "Запустите её через ./run.sh либо явно подтвердите флагом --force."
        % BASE_DIR
    )


# --------------------------------------------------------------------------
# Шаги 1-5. Субъекты
# --------------------------------------------------------------------------

def create_subjects():
    section("Шаги 1-5. Создание групп и пользователей")

    for group in GROUPS:
        run("groupdel %s" % q(group))
        res = run("groupadd %s" % q(group))
        print("  группа %-12s %s" % (group, "создана" if res.ok else res.reason()))

    for name, primary in USERS:
        run("userdel -r %s" % q(name))
        opts = "-m -s /bin/bash"
        if primary:
            opts += " -g %s" % q(primary)
        res = run("useradd %s %s" % (opts, q(name)))
        groups = run("id -nG %s" % q(name)).out.strip()
        print("  пользователь %-6s %-9s группы: %s"
              % (name, "создан" if res.ok else "ошибка", groups))

    # Шаг 4: административные привилегии для iit21. Членства в группе sudo
    # недостаточно для неинтерактивных проверок, поэтому дополнительно
    # выдаётся правило sudoers без запроса пароля.
    admin_group = "sudo" if run("getent group sudo").ok else "wheel"
    run("usermod -aG %s iit21" % q(admin_group))
    with open("/etc/sudoers.d/iit21", "w", encoding="utf-8") as handle:
        handle.write("iit21 ALL=(ALL) NOPASSWD:ALL\n")
    os.chmod("/etc/sudoers.d/iit21", 0o440)
    print("  iit21 добавлен в группу %s и получил NOPASSWD в sudoers"
          % admin_group)


# --------------------------------------------------------------------------
# Шаги 6-11. Каталоги
# --------------------------------------------------------------------------

def create_directories():
    section("Шаги 6-11. Создание каталогов")

    shutil.rmtree(BASE_DIR, ignore_errors=True)
    os.makedirs(BASE_DIR)
    os.chmod(BASE_DIR, 0o755)
    print("  %s  root:root  755 (родительский каталог, доступен для обхода)"
          % BASE_DIR)

    for name, mode, owner, group, comment in DIR_SPECS:
        path = os.path.join(BASE_DIR, name)
        os.makedirs(path)
        run("chown %s:%s %s" % (q(owner), q(group), q(path)))
        os.chmod(path, mode)
        print("  %-22s %-12s %04o  %s"
              % (path, owner + ":" + group, mode, comment))


# --------------------------------------------------------------------------
# Шаги 12-13. Файлы
# --------------------------------------------------------------------------

def file_content(name):
    """Содержимое файла согласно заданию.

    Строка интерпретатора добавляется потому, что проверка права на
    выполнение делается прямым запуском файла: без неё ядро вернуло бы
    ошибку формата независимо от прав доступа.
    """
    body = "read testVariable\n" if name.endswith("5") else 'echo "Hello World"\n'
    return "#!/bin/sh\n" + body


def create_files():
    section("Шаги 12-13. Создание файлов от имени пользователя iit11")

    for dirname in TARGET_DIRS:
        dir_path = os.path.join(BASE_DIR, dirname)
        created = 0
        for name, mode, owner, group, _ in FILE_SPECS:
            path = os.path.join(dir_path, name)
            # Шаг 12: текущим пользователем становится iit11, все файлы
            # создаются именно им.
            res = run("cat > %s" % q(path), user="iit11",
                      stdin_text=file_content(name))
            if not res.ok:
                run("cat > %s" % q(path), stdin_text=file_content(name))
            run("chown %s:%s %s" % (q(owner), q(group), q(path)))
            os.chmod(path, mode)
            created += 1
        print("  %s: создано %d файлов" % (dir_path, created))

    # Эталон для быстрого восстановления файлов после разрушающих проверок
    # (запись на шаге 14, удаление на шаге 16).
    shutil.rmtree(TEMPLATE_DIR, ignore_errors=True)
    run("cp -a %s %s" % (q(os.path.join(BASE_DIR, "pzs11")), q(TEMPLATE_DIR)))
    os.chmod(TEMPLATE_DIR, 0o700)
    print("  эталонная копия набора файлов: %s" % TEMPLATE_DIR)


def restore_file(dir_path, name):
    run("cp -a --remove-destination %s %s"
        % (q(os.path.join(TEMPLATE_DIR, name)), q(dir_path)))


def apply_dir_spec(dirname):
    """Возвращает каталогу владельца, группу и режим согласно шагам 6-11."""
    for name, mode, owner, group, _ in DIR_SPECS:
        if name == dirname:
            path = os.path.join(BASE_DIR, name)
            run("chown %s:%s %s" % (q(owner), q(group), q(path)))
            os.chmod(path, mode)
            return


def restore_dir(dirname):
    dir_path = os.path.join(BASE_DIR, dirname)
    run("rm -rf %s/* %s/.[!.]*" % (q(dir_path), q(dir_path)))
    run("cp -a %s/. %s/" % (q(TEMPLATE_DIR), q(dir_path)))
    # cp -a переносит на каталог-приёмник атрибуты каталога-источника,
    # поэтому настроенные на шагах 6-11 права нужно выставить заново.
    apply_dir_spec(dirname)


# --------------------------------------------------------------------------
# Шаг 14. Права на файлы
# --------------------------------------------------------------------------

def check_read(path, user):
    return run("cat %s > /dev/null" % q(path), user=user)


def check_execute(path, user):
    """Настоящая попытка запуска файла, а не проверка одного лишь бита x.

    Файл запускается напрямую, поэтому проверяются оба условия сразу:
    ядру нужен бит выполнения, а интерпретатору, указанному в первой
    строке сценария, - ещё и бит чтения. Запуск командой "sh файл" здесь
    не годится: он не требует бита выполнения вовсе.

    На стандартный ввод подаётся строка, чтобы команда read в файлах
    filex5 завершилась успешно, а не по концу потока.
    """
    return run("%s > /dev/null" % q(path), user=user, stdin_text="x\n",
               timeout=10)


def check_write(dir_path, name, user):
    path = os.path.join(dir_path, name)
    res = run("echo proba >> %s" % q(path), user=user)
    if res.ok:
        restore_file(dir_path, name)
    return res


def run_step14():
    section("Шаг 14. Проверка чтения, записи и выполнения файлов")
    header = "  %-8s %-8s %-6s " % ("каталог", "файл", "режим")
    header += " ".join("%-6s" % s for s in SUBJECTS)
    denied_exec_with_x = []

    for dirname in TARGET_DIRS:
        dir_path = os.path.join(BASE_DIR, dirname)
        print()
        print("  Каталог %s (%s)" % (dir_path, dir_comment(dirname)))
        print(header)
        print("  " + "-" * (len(header) - 2))
        for name, mode, owner, group, _ in FILE_SPECS:
            path = os.path.join(dir_path, name)
            cells = []
            for user in SUBJECTS:
                r = check_read(path, user).ok
                x = check_execute(path, user).ok
                w = check_write(dir_path, name, user).ok
                cells.append("%s%s%s" % ("r" if r else "-",
                                         "w" if w else "-",
                                         "x" if x else "-"))
                bits = class_bits(user, owner, group, mode)
                if user != "root" and (bits & 0o1) and not (bits & 0o4):
                    denied_exec_with_x.append((dirname, name, user))
            print("  %-8s %-8s %04o   %s"
                  % (dirname, name, mode,
                     " ".join("%-6s" % c for c in cells)))

    print()
    print("  Наблюдение: случаев, когда классу субъекта выдан бит x, но не выдан"
          " бит r: %d, и все они завершились отказом." % len(denied_exec_with_x))
    print("  Интерпретатору, указанному в первой строке сценария, требуется"
          " прочитать его текст, поэтому режимы вида")
    print("  100, 010, 001 и 111 делают файл неисполнимым, несмотря на"
          " выставленный бит выполнения.")
    print("  Для суперпользователя действует отдельное правило: он читает и"
          " пишет любой файл, но выполнить может")
    print("  только тот, у которого выставлен хотя бы один бит x.")


_GROUP_CACHE = {}


def user_groups(user):
    if user not in _GROUP_CACHE:
        _GROUP_CACHE[user] = set(run("id -nG %s" % q(user)).out.split())
    return _GROUP_CACHE[user]


def class_bits(user, owner, group, mode):
    """Биты прав, действующие для субъекта: владелец, группа или остальные.

    Классы проверяются именно в этом порядке и взаимоисключающи - владелец
    файла никогда не получает права по классу группы, даже если состоит
    в группе-владельце.
    """
    if user == owner:
        return (mode >> 6) & 0o7
    if group in user_groups(user):
        return (mode >> 3) & 0o7
    return mode & 0o7


def dir_comment(dirname):
    for name, mode, owner, group, comment in DIR_SPECS:
        if name == dirname:
            return "%s %04o, %s" % (owner + ":" + group, mode, comment)
    return ""


# --------------------------------------------------------------------------
# Шаг 15. Управление процессами
# --------------------------------------------------------------------------

def find_pid(user, path):
    res = run("ps -eo pid=,user=,args=")
    for line in res.out.splitlines():
        parts = line.strip().split(None, 2)
        if len(parts) < 3:
            continue
        pid, owner, args = parts
        if owner == user and path in args and "ps -eo" not in args:
            return int(pid)
    return None


def start_process(user, path):
    """Запускает сценарий от имени субъекта и возвращает (Popen, pid)."""
    proc = subprocess.Popen(
        ["runuser", "-u", user, "--", path] if user != "root" else [path],
        stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE, text=True,
    )
    for _ in range(20):
        time.sleep(0.05)
        if proc.poll() is not None:
            return proc, None
        pid = find_pid(user, path)
        if pid:
            return proc, pid
    return proc, None


def process_alive(pid):
    """Жив ли процесс.

    Проверка сигналом kill -0 здесь не годится: она считает живым и
    завершённый процесс, запись о котором ещё не забрал родитель
    (состояние зомби), поэтому состояние читается напрямую из /proc.
    """
    try:
        with open("/proc/%d/stat" % pid, encoding="utf-8") as handle:
            state = handle.read().rsplit(")", 1)[1].split()[0]
    except (OSError, IndexError):
        return False
    return state != "Z"


def stop_process(proc, pid):
    if pid and process_alive(pid):
        run("kill -9 %d 2>/dev/null" % pid)
    try:
        if proc.stdin:
            proc.stdin.close()
        proc.wait(timeout=5)
    except Exception:
        proc.kill()


def run_step15():
    section("Шаг 15. Запуск файлов filex5 и проверка завершения процессов")

    print()
    print("  15.1. Запуск от имени iit11 в точном соответствии с заданием.")
    print("  %-8s %-8s %-6s %-10s %s"
          % ("каталог", "файл", "режим", "запуск", "причина"))
    print("  " + "-" * 74)
    started_any = False
    for dirname in TARGET_DIRS:
        for name in PROC_FILES:
            path = os.path.join(BASE_DIR, dirname, name)
            mode = dict((f[0], f[1]) for f in FILE_SPECS)[name]
            res = run(q(path), user="iit11", stdin_text="", timeout=5)
            ok = res.ok
            started_any = started_any or ok
            print("  %-8s %-8s %04o   %-10s %s"
                  % (dirname, name, mode,
                     "успешно" if ok else "отказ",
                     "" if ok else res.reason()))
    if not started_any:
        print()
        print("  Ни один файл filex5 не запускается пользователем iit11: у всех"
              " пяти файлов выставлен только бит")
        print("  выполнения без бита чтения, а для классов group и other"
              " пользователь iit11 является владельцем")
        print("  и попадает в класс owner с нулевыми правами. Это корректное"
              " поведение модели POSIX.")

    print()
    print("  15.2. Демонстрация правил управления процессами.")
    print("  Каждый файл запускается тем субъектом, которому его класс прав"
          " разрешает выполнение; недостающий")
    print("  классу бит чтения выдаётся временно и возвращается сразу после"
          " проверки. Затем каждый субъект")
    print("  пробует завершить процесс сигналом TERM.")
    print()
    header = "  %-8s %-8s %-8s " % ("каталог", "файл", "владелец")
    header += " ".join("%-6s" % s for s in SUBJECTS) + " sudo:iit21"
    print(header)
    print("  " + "-" * (len(header) - 2))

    modes = dict((f[0], f[1]) for f in FILE_SPECS)
    for dirname in TARGET_DIRS:
        for name in PROC_FILES:
            path = os.path.join(BASE_DIR, dirname, name)
            runner, read_bit = PROC_RUNNER[name]
            os.chmod(path, modes[name] | read_bit)
            cells = []
            for killer in SUBJECTS:
                proc, pid = start_process(runner, path)
                if pid is None:
                    stop_process(proc, pid)
                    cells.append("н/д")
                    continue
                res = run("kill -TERM %d" % pid, user=killer)
                time.sleep(0.15)
                cells.append("да" if (res.ok and not process_alive(pid))
                             else "нет")
                stop_process(proc, pid)

            # Отдельно: iit21 обладает административными привилегиями,
            # поэтому через sudo завершает чужой процесс.
            proc, pid = start_process(runner, path)
            if pid is None:
                sudo_cell = "н/д"
            else:
                res = run("sudo -n kill -TERM %d" % pid, user="iit21")
                time.sleep(0.15)
                sudo_cell = ("да" if (res.ok and not process_alive(pid))
                             else "нет")
            stop_process(proc, pid)

            os.chmod(path, modes[name])
            print("  %-8s %-8s %-8s %s %s"
                  % (dirname, name, runner,
                     " ".join("%-6s" % c for c in cells), sudo_cell))

    print()
    print("  Значение н/д означает, что процесс не удалось запустить: субъект,"
          " которому класс прав файла")
    print("  разрешает выполнение, не имеет доступа к самому каталогу.")


# --------------------------------------------------------------------------
# Шаг 16. Права на каталоги
# --------------------------------------------------------------------------

def run_step16():
    section("Шаг 16. Проверка листинга, создания и удаления файлов в каталогах")
    print("  %-8s %-6s %-8s %-8s %-14s %s"
          % ("каталог", "субъект", "листинг", "создание", "удаление", "примечание"))
    print("  " + "-" * 74)

    all_dirs = [spec[0] for spec in DIR_SPECS]
    for dirname in all_dirs:
        dir_path = os.path.join(BASE_DIR, dirname)
        has_files = dirname in TARGET_DIRS
        for user in SUBJECTS:
            can_list = run("ls %s > /dev/null" % q(dir_path), user=user).ok

            probe = os.path.join(dir_path, "probe_%s" % user)
            can_create = run("touch %s" % q(probe), user=user).ok
            if os.path.exists(probe):
                run("rm -f %s" % q(probe))

            if has_files:
                deleted = 0
                for name, _, _, _, _ in FILE_SPECS:
                    if run("rm -f %s" % q(os.path.join(dir_path, name)),
                           user=user).ok and not os.path.exists(
                               os.path.join(dir_path, name)):
                        deleted += 1
                restore_dir(dirname)
                delete_cell = "%d из %d" % (deleted, len(FILE_SPECS))
                note = ("удаление зависит от прав на каталог, "
                        "а не на файл") if deleted else ""
            else:
                delete_cell = "нет файлов"
                note = ""

            print("  %-8s %-6s %-8s %-8s %-14s %s"
                  % (dirname, user,
                     "да" if can_list else "нет",
                     "да" if can_create else "нет",
                     delete_cell, note))


# --------------------------------------------------------------------------
# Шаг 17. Очистка
# --------------------------------------------------------------------------

def cleanup():
    section("Шаг 17. Удаление созданных объектов")

    shutil.rmtree(BASE_DIR, ignore_errors=True)
    shutil.rmtree(TEMPLATE_DIR, ignore_errors=True)
    print("  каталоги %s и %s удалены" % (BASE_DIR, TEMPLATE_DIR))

    for name, _ in USERS:
        run("pkill -9 -u %s" % q(name))
        run("userdel -r %s" % q(name))
    if os.path.exists("/etc/sudoers.d/iit21"):
        os.remove("/etc/sudoers.d/iit21")
    for group in GROUPS:
        run("groupdel %s" % q(group))

    left_users = [n for n, _ in USERS if run("id %s" % q(n)).ok]
    left_groups = [g for g in GROUPS if run("getent group %s" % q(g)).ok]
    print("  пользователи удалены: %s"
          % ("да" if not left_users else "нет, остались %s" % left_users))
    print("  группы удалены: %s"
          % ("да" if not left_groups else "нет, остались %s" % left_groups))
    print("  каталог %s существует: %s"
          % (BASE_DIR, "да" if os.path.exists(BASE_DIR) else "нет"))


# --------------------------------------------------------------------------

def main():
    force = "--force" in sys.argv

    if os.geteuid() != 0:
        sys.exit("Отказ: программа должна выполняться от имени root.")
    assert_disposable_env(force)

    sys.stdout = Tee(sys.__stdout__, LOG_PATH)
    print("Лабораторная работа №1 по ПЗИИС, часть 1.")
    print("Управление доступом к объектам операционной системы.")
    print("Журнал прогона: %s" % LOG_PATH)

    try:
        create_subjects()
        create_directories()
        create_files()
        run_step14()
        run_step15()
        run_step16()
    finally:
        cleanup()
        print()
        print("Работа завершена, система возвращена в исходное состояние.")
        sys.stdout.flush()


if __name__ == "__main__":
    main()
