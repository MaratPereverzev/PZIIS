"""Аутентификация, сессии, CSRF и противодействие перебору."""

import hashlib
import hmac
import time
from collections import deque
from datetime import datetime, timedelta, timezone

from app import crypto
from app.config import settings

SESSION_COOKIE = "vault_session"
CSRF_COOKIE = "vault_csrf"


class Actor:
    """Проверенный субъект текущего запроса."""

    __slots__ = ("id", "login", "role", "session_id", "csrf_token")

    def __init__(self, id, login, role, session_id, csrf_token):
        self.id = id
        self.login = login
        self.role = role
        self.session_id = session_id
        self.csrf_token = csrf_token

    @property
    def is_admin(self):
        return self.role == "admin"

    def can_write(self):
        """Гость - только чтение неконфиденциальных публичных записей."""
        return self.role in ("admin", "user")


# ---------------------------------------------------------------------------
# Сессии
# ---------------------------------------------------------------------------

def issue_session(cur, account_id, ip, user_agent):
    """Создаёт сессию и возвращает (токен, csrf-токен).

    Вызывается только после успешной проверки пароля. Идентификатор сессии
    создаётся заново на каждый вход - это защита от фиксации сессии
    (CWE-384): токен, известный атакующему до входа жертвы, не станет
    авторизованным.
    """
    token = crypto.new_token()
    csrf = crypto.new_token()
    now = datetime.now(timezone.utc)
    cur.execute(
        """
        INSERT INTO app.session
            (token_hash, csrf_hash, account_id, idle_expires_at,
             hard_expires_at, ip_addr, ua_hash)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (
            crypto.token_digest(token),
            crypto.token_digest(csrf),
            account_id,
            now + timedelta(minutes=settings.session_idle_minutes),
            now + timedelta(hours=settings.session_hard_hours),
            ip,
            hashlib.sha256((user_agent or "").encode("utf-8")).digest(),
        ),
    )
    return token, csrf, cur.fetchone()["id"]


def load_session(cur, token, csrf_cookie):
    """Возвращает Actor или None.

    Проверяются оба срока жизни; при успехе срок неактивности сдвигается.
    Просроченные сессии удаляются сразу, а не просто игнорируются.
    """
    if not token:
        return None
    cur.execute(
        """
        SELECT s.id AS session_id, s.account_id, s.csrf_hash,
               s.idle_expires_at, s.hard_expires_at,
               a.login, a.app_role, a.is_active
        FROM app.session s
        JOIN app.account a ON a.id = s.account_id
        WHERE s.token_hash = %s
        """,
        (crypto.token_digest(token),),
    )
    row = cur.fetchone()
    if row is None:
        return None

    now = datetime.now(timezone.utc)
    if row["idle_expires_at"] <= now or row["hard_expires_at"] <= now:
        cur.execute("DELETE FROM app.session WHERE id = %s", (row["session_id"],))
        return None
    if not row["is_active"]:
        cur.execute("DELETE FROM app.session WHERE id = %s", (row["session_id"],))
        return None

    # CSRF-токен проверяется на связь с сессией: cookie должна
    # соответствовать хешу, сохранённому при входе.
    if not csrf_cookie or crypto.token_digest(csrf_cookie) != bytes(row["csrf_hash"]):
        csrf_cookie = None

    cur.execute(
        "UPDATE app.session SET idle_expires_at = %s WHERE id = %s",
        (now + timedelta(minutes=settings.session_idle_minutes), row["session_id"]),
    )
    return Actor(row["account_id"], row["login"], row["app_role"],
                 row["session_id"], csrf_cookie)


def destroy_session(cur, token):
    """Деавторизация: строка сессии удаляется на сервере.

    Именно поэтому выбран opaque-токен, а не JWT - отзыв мгновенный
    и полный, а не «до истечения срока подписи».
    """
    if not token:
        return 0
    cur.execute("DELETE FROM app.session WHERE token_hash = %s",
                (crypto.token_digest(token),))
    return cur.rowcount


def destroy_all_sessions(cur, account_id):
    cur.execute("DELETE FROM app.session WHERE account_id = %s", (account_id,))
    return cur.rowcount


def purge_expired(cur):
    cur.execute("DELETE FROM app.session WHERE hard_expires_at <= now()")
    return cur.rowcount


# ---------------------------------------------------------------------------
# CSRF
# ---------------------------------------------------------------------------

def csrf_ok(actor, form_token):
    """Двойная отправка: значение из формы должно совпасть со значением
    cookie, а cookie - с хешем, привязанным к сессии.

    Первый рубеж - SameSite=Strict на cookie; этот - второй, потому что
    SameSite не поддерживается совсем старыми браузерами и не покрывает
    все сценарии.
    """
    if actor is None or not actor.csrf_token or not form_token:
        return False
    # Сравнение именно на байтах: compare_digest на строках с символами вне
    # ASCII выбрасывает TypeError, и присланный атакующим токен с кириллицей
    # приводил бы к ответу 500 вместо чистого отказа.
    return hmac.compare_digest(actor.csrf_token.encode("utf-8"),
                               form_token.encode("utf-8"))


# ---------------------------------------------------------------------------
# Противодействие перебору
# ---------------------------------------------------------------------------

class SlidingWindow:
    """Лимит попыток на ключ в скользящем окне.

    Состояние в памяти процесса: при перезапуске сбрасывается и при
    нескольких рабочих процессах не разделяется. Это осознанно -
    основной лимит стоит на nginx, а этот работает как страховка
    для запуска без прокси.
    """

    def __init__(self, limit, window_sec):
        self.limit = limit
        self.window = window_sec
        self._hits = {}

    def allow(self, key):
        now = time.monotonic()
        bucket = self._hits.setdefault(key, deque())
        while bucket and now - bucket[0] > self.window:
            bucket.popleft()
        if len(bucket) >= self.limit:
            return False
        bucket.append(now)
        return True

    def reset(self, key):
        self._hits.pop(key, None)


login_limiter = SlidingWindow(settings.login_ip_limit,
                              settings.login_ip_window_sec)


def account_locked(row):
    locked_until = row.get("locked_until")
    if locked_until is None:
        return False
    return locked_until > datetime.now(timezone.utc)


def register_failure(cur, account_id, failed_count):
    """Инкремент счётчика неудач и блокировка при превышении порога."""
    failed = failed_count + 1
    if failed >= settings.lockout_threshold:
        cur.execute(
            """
            UPDATE app.account
            SET failed_count = 0, locked_until = now() + %s::interval
            WHERE id = %s
            """,
            ("%d minutes" % settings.lockout_minutes, account_id),
        )
        return True
    cur.execute("UPDATE app.account SET failed_count = %s WHERE id = %s",
                (failed, account_id))
    return False


def register_success(cur, account_id):
    cur.execute(
        "UPDATE app.account SET failed_count = 0, locked_until = NULL "
        "WHERE id = %s", (account_id,))
