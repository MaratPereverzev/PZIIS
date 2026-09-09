"""pziis-vault: точка входа приложения.

Требования задания 2.1 и закрывающие их обработчики:
  1) добавить пользователя           -> POST /register, POST /admin/accounts
  2) авторизовать пользователя       -> POST /login
  3) CRUD + поиск конфиденциальных   -> /secrets/*
  4) CRUD + поиск неконфиденциальных -> /notes/*
  5) деавторизовать пользователя     -> POST /logout, POST /logout/all

Общие правила для всех обработчиков:
  - вход валидируется до попадания в логику (типы и длины - в Form/Pydantic,
    смысловые проверки - явно);
  - право проверяется ДО чтения объекта, а не после;
  - любой изменяющий метод требует CSRF-токена;
  - все SQL-запросы параметризованы;
  - наружу уходят обобщённые сообщения об ошибке, детали - в журнал сервера
    (иначе это CWE-209).
"""

import ipaddress
import logging
import time
from contextlib import asynccontextmanager

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app import audit, auth, db, notes, passwords, secrets_store
from app.config import settings
from app.crypto import Crypto, IntegrityError

log = logging.getLogger("pziis-vault")

crypto = Crypto(settings.master_key)
templates = Jinja2Templates(directory="app/templates")
templates.env.autoescape = True   # защита от XSS по умолчанию

# Единый текст ошибки входа: не раскрывает, существует ли учётная запись,
# заблокирована она или просто введён неверный пароль (CWE-204).
LOGIN_ERROR = "Неверный логин или пароль."


class AuthRequired(Exception):
    pass


class Forbidden(Exception):
    pass


def _bootstrap_admin():
    """Создаёт администратора при первом запуске, если его ещё нет."""
    if not settings.bootstrap_admin_password:
        log.warning("VAULT_ADMIN_PASSWORD не задан: администратор не создан")
        return
    with db.tx() as cur:
        cur.execute("SELECT count(*) AS n FROM app.account "
                    "WHERE app_role = 'admin'")
        if cur.fetchone()["n"] > 0:
            return
        cur.execute(
            """
            INSERT INTO app.account (login, pwd_hash, app_role)
            VALUES (%s, %s, 'admin')
            ON CONFLICT (login) DO NOTHING
            RETURNING id
            """,
            (settings.bootstrap_admin_login,
             crypto.hash_password(settings.bootstrap_admin_password)),
        )
        row = cur.fetchone()
        if row:
            log.info("создана учётная запись администратора %s",
                     settings.bootstrap_admin_login)


@asynccontextmanager
async def lifespan(_app):
    db.open_pool(settings.dsn)
    _bootstrap_admin()
    with db.tx() as cur:
        removed = auth.purge_expired(cur)
    if removed:
        log.info("удалено просроченных сессий: %d", removed)
    yield
    db.close_pool()


app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None,
              openapi_url=None, title="pziis-vault")
# Интерактивная документация отключена: на рабочем стенде она раскрывает
# полную карту точек входа и схемы данных.

# Единственный каталог со статикой. Политика CSP разрешает стили только
# с собственного источника (style-src 'self'), внешних CDN приложение
# не использует вовсе.
app.mount("/static", StaticFiles(directory="app/static"), name="static")


# ---------------------------------------------------------------------------
# Инфраструктура запроса
# ---------------------------------------------------------------------------

@app.middleware("http")
async def security_headers(request, call_next):
    response = await call_next(request)
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'none'; "
        "object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    )
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    # Страницы приложения не кэшируются: иначе конфиденциальная запись
    # осталась бы в кэше браузера или промежуточного прокси.
    response.headers.setdefault("Cache-Control", "no-store, max-age=0")
    return response


@app.exception_handler(AuthRequired)
async def _auth_required(request, exc):
    return RedirectResponse("/login", status_code=303)


@app.exception_handler(Forbidden)
async def _forbidden(request, exc):
    return HTMLResponse("<h1>403</h1><p>Недостаточно прав.</p>", status_code=403)


@app.exception_handler(IntegrityError)
async def _integrity(request, exc):
    # Проверка тега AES-GCM не сошлась: запись изменена в обход приложения.
    log.error("нарушение целостности конфиденциальной записи: %s", exc)
    return HTMLResponse(
        "<h1>500</h1><p>Нарушена целостность данных. "
        "Обратитесь к администратору.</p>", status_code=500)


def client_ip(request):
    """IP клиента.

    За обратным прокси реальный адрес приходит в X-Forwarded-For, который
    выставляет nginx. Значение из заголовка проверяется как IP-адрес:
    в это поле клиент способен положить произвольный текст.
    """
    forwarded = request.headers.get("x-forwarded-for", "")
    candidate = forwarded.split(",")[0].strip() if forwarded else None
    if not candidate and request.client:
        candidate = request.client.host
    try:
        return str(ipaddress.ip_address(candidate))
    except (ValueError, TypeError):
        return None


def current_actor(request):
    """Субъект запроса или None. Источник - только проверенная сессия."""
    token = request.cookies.get(auth.SESSION_COOKIE)
    if not token:
        return None
    with db.tx() as cur:
        return auth.load_session(cur, token,
                                 request.cookies.get(auth.CSRF_COOKIE))


def require_actor(request, *roles):
    actor = current_actor(request)
    if actor is None:
        raise AuthRequired()
    if roles and actor.role not in roles:
        raise Forbidden()
    return actor


def require_csrf(actor, token):
    if not auth.csrf_ok(actor, token):
        raise Forbidden()


def render(request, name, actor=None, **ctx):
    context = {"actor": actor, "csrf": actor.csrf_token if actor else "", **ctx}
    return templates.TemplateResponse(request=request, name=name,
                                      context=context)


def redirect(path, ok=None, err=None):
    query = []
    if ok:
        query.append("ok=" + ok)
    if err:
        query.append("err=" + err)
    if query:
        path = path + ("&" if "?" in path else "?") + "&".join(query)
    return RedirectResponse(path, status_code=303)


def _set_session_cookies(response, token, csrf):
    common = {
        "httponly": True,             # токен недостижим из JS даже при XSS
        "secure": settings.cookie_secure,
        "samesite": "strict",         # базовая защита от CSRF
        "path": "/",
    }
    response.set_cookie(auth.SESSION_COOKIE, token, **common)
    response.set_cookie(auth.CSRF_COOKIE, csrf, **common)


def _clear_session_cookies(response):
    response.delete_cookie(auth.SESSION_COOKIE, path="/")
    response.delete_cookie(auth.CSRF_COOKIE, path="/")


# ---------------------------------------------------------------------------
# Служебное
# ---------------------------------------------------------------------------

@app.get("/healthz")
def healthz():
    # Ни версий, ни конфигурации: только факт живости.
    return JSONResponse({"status": "ok"})


@app.get("/")
def index(request: Request):
    return RedirectResponse("/notes" if current_actor(request) else "/login",
                            status_code=303)


# ---------------------------------------------------------------------------
# Требование 1: добавление пользователя в систему
# ---------------------------------------------------------------------------

@app.get("/register")
def register_form(request: Request, err: str = "", ok: str = ""):
    return render(request, "register.html", err=err, ok=ok,
                  min_len=settings.min_password_len)


@app.post("/register")
def register(request: Request,
             login: str = Form(..., min_length=3, max_length=64),
             password: str = Form(..., max_length=256),
             password2: str = Form(..., max_length=256)):
    login = login.strip()
    ip = client_ip(request)

    if password != password2:
        return redirect("/register", err="Пароли не совпадают.")
    reason = passwords.validate(password, login)
    if reason:
        return redirect("/register", err=reason)

    pwd_hash = crypto.hash_password(password)
    with db.tx() as cur:
        # Роль по умолчанию - guest: новый пользователь получает минимум
        # полномочий, повышает их администратор.
        cur.execute(
            """
            INSERT INTO app.account (login, pwd_hash, app_role)
            VALUES (%s, %s, 'guest')
            ON CONFLICT (login) DO NOTHING
            RETURNING id
            """,
            (login, pwd_hash),
        )
        row = cur.fetchone()
        audit.log(cur, "register", login=login, ip=ip,
                  outcome="ok" if row else "denied")

    # Ответ одинаков и при успехе, и при занятом логине: иначе форма
    # регистрации превращается в средство перечисления учётных записей.
    return redirect("/login",
                    ok="Если логин свободен, учётная запись создана. Войдите.")


# ---------------------------------------------------------------------------
# Требование 2: авторизация
# ---------------------------------------------------------------------------

@app.get("/login")
def login_form(request: Request, err: str = "", ok: str = ""):
    return render(request, "login.html", err=err, ok=ok)


@app.post("/login")
def login(request: Request,
          login: str = Form(..., max_length=64),
          password: str = Form(..., max_length=256)):
    login = login.strip()
    ip = client_ip(request)

    # Лимит попыток на адрес. Основной рубеж - nginx; этот работает,
    # когда приложение запущено без прокси.
    if not auth.login_limiter.allow(ip or "unknown"):
        with db.tx() as cur:
            audit.log(cur, "login", login=login, ip=ip, outcome="denied")
        return HTMLResponse(
            "<h1>429</h1><p>Слишком много попыток входа. Повторите позже.</p>",
            status_code=429)

    token = csrf = None
    with db.tx() as cur:
        cur.execute(
            """
            SELECT id, login, pwd_hash, app_role, is_active, failed_count,
                   locked_until
            FROM app.account
            WHERE login = %s
            """,
            (login,),
        )
        row = cur.fetchone()

        if row is None:
            # Проверка по фиктивному хешу: без неё разница во времени
            # ответа выдавала бы существующие логины.
            crypto.burn_password_time()
            audit.log(cur, "login", login=login, ip=ip, outcome="denied")
        elif not row["is_active"] or auth.account_locked(row):
            crypto.burn_password_time()
            audit.log(cur, "login", actor=row["id"], login=login, ip=ip,
                      outcome="denied")
            row = None
        else:
            ok_pwd, new_hash = crypto.verify_password(row["pwd_hash"], password)
            if not ok_pwd:
                locked = auth.register_failure(cur, row["id"],
                                               row["failed_count"])
                audit.log(cur, "login", actor=row["id"], login=login, ip=ip,
                          outcome="denied")
                if locked:
                    audit.log(cur, "admin_account_lock", actor=row["id"],
                              login=login, ip=ip, kind="account",
                              obj_id=row["id"], outcome="denied")
                row = None
            else:
                auth.register_success(cur, row["id"])
                if new_hash:
                    # Параметры стоимости в базе устарели - перехешируем.
                    cur.execute("UPDATE app.account SET pwd_hash = %s "
                                "WHERE id = %s", (new_hash, row["id"]))
                token, csrf, _sid = auth.issue_session(
                    cur, row["id"], ip, request.headers.get("user-agent"))
                audit.log(cur, "login", actor=row["id"], login=login, ip=ip,
                          outcome="ok")

    if token is None:
        # Фиксированная задержка на любой неуспешный вход.
        time.sleep(settings.failed_login_delay_ms / 1000.0)
        return redirect("/login", err=LOGIN_ERROR)

    auth.login_limiter.reset(ip or "unknown")
    response = redirect("/notes")
    _set_session_cookies(response, token, csrf)
    return response


# ---------------------------------------------------------------------------
# Требование 5: деавторизация
# ---------------------------------------------------------------------------

@app.post("/logout")
def logout(request: Request, csrf_token: str = Form("")):
    actor = require_actor(request)
    require_csrf(actor, csrf_token)
    with db.tx() as cur:
        auth.destroy_session(cur, request.cookies.get(auth.SESSION_COOKIE))
        audit.log(cur, "logout", actor=actor.id, login=actor.login,
                  ip=client_ip(request))
    response = redirect("/login", ok="Сессия закрыта.")
    _clear_session_cookies(response)
    return response


@app.post("/logout/all")
def logout_all(request: Request, csrf_token: str = Form("")):
    actor = require_actor(request)
    require_csrf(actor, csrf_token)
    with db.tx() as cur:
        count = auth.destroy_all_sessions(cur, actor.id)
        audit.log(cur, "logout_all", actor=actor.id, login=actor.login,
                  ip=client_ip(request), obj_id=count)
    response = redirect("/login", ok="Закрыты все сессии учётной записи.")
    _clear_session_cookies(response)
    return response


# ---------------------------------------------------------------------------
# Требование 4: неконфиденциальные данные
# ---------------------------------------------------------------------------

@app.get("/notes")
def notes_list(request: Request, q: str = Query("", max_length=200),
               ok: str = "", err: str = ""):
    actor = require_actor(request)
    with db.tx(actor.id, actor.is_admin) as cur:
        rows = notes.search(cur, q) if q.strip() else notes.list_visible(cur)
        if q.strip():
            audit.log(cur, "note_search", actor=actor.id, login=actor.login,
                      ip=client_ip(request))
    return render(request, "notes.html", actor=actor, rows=rows, q=q,
                  ok=ok, err=err)


@app.post("/notes")
def notes_create(request: Request,
                 title: str = Form(..., max_length=200),
                 body: str = Form(..., max_length=8000),
                 visibility: str = Form("public"),
                 csrf_token: str = Form("")):
    actor = require_actor(request)
    require_csrf(actor, csrf_token)
    if not actor.can_write():
        raise Forbidden()          # гость - только чтение
    if visibility not in ("public", "internal"):
        return redirect("/notes", err="Недопустимая видимость записи.")
    if not title.strip():
        return redirect("/notes", err="Заголовок не может быть пустым.")

    with db.tx(actor.id, actor.is_admin) as cur:
        note_id = notes.create(cur, actor.id, title.strip(), body, visibility)
        audit.log(cur, "note_create", actor=actor.id, login=actor.login,
                  kind="note", obj_id=note_id, ip=client_ip(request))
    return redirect("/notes", ok="Запись создана.")


@app.post("/notes/{note_id}/edit")
def notes_edit(request: Request, note_id: int,
               title: str = Form(..., max_length=200),
               body: str = Form(..., max_length=8000),
               visibility: str = Form("public"),
               csrf_token: str = Form("")):
    actor = require_actor(request)
    require_csrf(actor, csrf_token)
    if not actor.can_write():
        raise Forbidden()
    if visibility not in ("public", "internal"):
        return redirect("/notes", err="Недопустимая видимость записи.")

    with db.tx(actor.id, actor.is_admin) as cur:
        changed = notes.update(cur, note_id, title.strip(), body, visibility)
        audit.log(cur, "note_update", actor=actor.id, login=actor.login,
                  kind="note", obj_id=note_id, ip=client_ip(request),
                  outcome="ok" if changed else "denied")
    if not changed:
        return redirect("/notes", err="Запись не найдена или недоступна.")
    return redirect("/notes", ok="Запись изменена.")


@app.post("/notes/{note_id}/delete")
def notes_delete(request: Request, note_id: int, csrf_token: str = Form("")):
    actor = require_actor(request)
    require_csrf(actor, csrf_token)
    if not actor.can_write():
        raise Forbidden()
    with db.tx(actor.id, actor.is_admin) as cur:
        removed = notes.delete(cur, note_id)
        audit.log(cur, "note_delete", actor=actor.id, login=actor.login,
                  kind="note", obj_id=note_id, ip=client_ip(request),
                  outcome="ok" if removed else "denied")
    if not removed:
        return redirect("/notes", err="Запись не найдена или недоступна.")
    return redirect("/notes", ok="Запись удалена.")


# ---------------------------------------------------------------------------
# Требование 3: конфиденциальные данные
# ---------------------------------------------------------------------------
# Гость к этой подсистеме не допускается вовсе.

@app.get("/secrets")
def secrets_list(request: Request, ok: str = "", err: str = ""):
    actor = require_actor(request, "admin", "user")
    with db.tx(actor.id) as cur:
        rows = secrets_store.list_own(cur, crypto, actor.id)
    return render(request, "secrets.html", actor=actor, rows=rows, q="",
                  ok=ok, err=err)


@app.post("/secrets/search")
def secrets_search(request: Request, q: str = Form("", max_length=200),
                   csrf_token: str = Form("")):
    """Поиск конфиденциальных данных.

    Метод POST выбран сознательно: при GET поисковая фраза осела бы
    в access-логе nginx, в истории браузера и в заголовке Referer.
    """
    actor = require_actor(request, "admin", "user")
    require_csrf(actor, csrf_token)
    with db.tx(actor.id) as cur:
        rows = secrets_store.search(cur, crypto, actor.id, q)
        # В журнал пишется факт поиска, но не поисковая фраза.
        audit.log(cur, "secret_search", actor=actor.id, login=actor.login,
                  ip=client_ip(request), obj_id=len(rows))
    return render(request, "secrets.html", actor=actor, rows=rows, q=q)


@app.post("/secrets")
def secrets_create(request: Request,
                   title: str = Form(..., max_length=200),
                   body: str = Form(..., max_length=8000),
                   csrf_token: str = Form("")):
    actor = require_actor(request, "admin", "user")
    require_csrf(actor, csrf_token)
    if not title.strip():
        return redirect("/secrets", err="Заголовок не может быть пустым.")
    with db.tx(actor.id) as cur:
        record_id = secrets_store.create(cur, crypto, actor.id,
                                         title.strip(), body)
        audit.log(cur, "secret_create", actor=actor.id, login=actor.login,
                  kind="secret", obj_id=record_id, ip=client_ip(request))
    return redirect("/secrets", ok="Конфиденциальная запись создана.")


@app.post("/secrets/{record_id}/edit")
def secrets_edit(request: Request, record_id: int,
                 title: str = Form(..., max_length=200),
                 body: str = Form(..., max_length=8000),
                 csrf_token: str = Form("")):
    actor = require_actor(request, "admin", "user")
    require_csrf(actor, csrf_token)
    with db.tx(actor.id) as cur:
        changed = secrets_store.update(cur, crypto, actor.id, record_id,
                                       title.strip(), body)
        audit.log(cur, "secret_update", actor=actor.id, login=actor.login,
                  kind="secret", obj_id=record_id, ip=client_ip(request),
                  outcome="ok" if changed else "denied")
    if not changed:
        return redirect("/secrets", err="Запись не найдена или недоступна.")
    return redirect("/secrets", ok="Конфиденциальная запись изменена.")


@app.post("/secrets/{record_id}/delete")
def secrets_delete(request: Request, record_id: int,
                   csrf_token: str = Form("")):
    actor = require_actor(request, "admin", "user")
    require_csrf(actor, csrf_token)
    with db.tx(actor.id) as cur:
        removed = secrets_store.delete(cur, record_id)
        audit.log(cur, "secret_delete", actor=actor.id, login=actor.login,
                  kind="secret", obj_id=record_id, ip=client_ip(request),
                  outcome="ok" if removed else "denied")
    if not removed:
        return redirect("/secrets", err="Запись не найдена или недоступна.")
    return redirect("/secrets", ok="Конфиденциальная запись удалена.")


# ---------------------------------------------------------------------------
# Администрирование
# ---------------------------------------------------------------------------

@app.get("/admin/accounts")
def admin_accounts(request: Request, ok: str = "", err: str = ""):
    actor = require_actor(request, "admin")
    with db.tx(actor.id, True) as cur:
        cur.execute(
            """
            SELECT a.id, a.login, a.app_role, a.is_active, a.locked_until,
                   a.created_at,
                   (SELECT count(*) FROM app.session s
                    WHERE s.account_id = a.id) AS sessions
            FROM app.account a
            ORDER BY a.id
            """
        )
        rows = cur.fetchall()
    return render(request, "admin_accounts.html", actor=actor, rows=rows,
                  ok=ok, err=err, min_len=settings.min_password_len)


@app.post("/admin/accounts")
def admin_account_create(request: Request,
                         login: str = Form(..., min_length=3, max_length=64),
                         password: str = Form(..., max_length=256),
                         app_role: str = Form("guest"),
                         csrf_token: str = Form("")):
    actor = require_actor(request, "admin")
    require_csrf(actor, csrf_token)
    if app_role not in ("admin", "user", "guest"):
        return redirect("/admin/accounts", err="Недопустимая роль.")
    reason = passwords.validate(password, login)
    if reason:
        return redirect("/admin/accounts", err=reason)

    pwd_hash = crypto.hash_password(password)
    with db.tx(actor.id, True) as cur:
        cur.execute(
            """
            INSERT INTO app.account (login, pwd_hash, app_role)
            VALUES (%s, %s, %s)
            ON CONFLICT (login) DO NOTHING
            RETURNING id
            """,
            (login.strip(), pwd_hash, app_role),
        )
        row = cur.fetchone()
        audit.log(cur, "admin_account_create", actor=actor.id,
                  login=actor.login, kind="account",
                  obj_id=row["id"] if row else None, ip=client_ip(request),
                  outcome="ok" if row else "denied")
    if not row:
        return redirect("/admin/accounts", err="Логин уже занят.")
    return redirect("/admin/accounts", ok="Учётная запись создана.")


@app.post("/admin/accounts/{account_id}/role")
def admin_account_role(request: Request, account_id: int,
                       app_role: str = Form(...), csrf_token: str = Form("")):
    actor = require_actor(request, "admin")
    require_csrf(actor, csrf_token)
    if app_role not in ("admin", "user", "guest"):
        return redirect("/admin/accounts", err="Недопустимая роль.")
    if account_id == actor.id:
        # Иначе администратор способен снять роль сам с себя и запереть
        # систему без администратора.
        return redirect("/admin/accounts",
                        err="Нельзя изменить роль собственной учётной записи.")

    with db.tx(actor.id, True) as cur:
        cur.execute("UPDATE app.account SET app_role = %s WHERE id = %s",
                    (app_role, account_id))
        changed = cur.rowcount > 0
        if changed:
            # Смена роли должна вступить в силу немедленно, а не после
            # истечения текущей сессии пользователя.
            auth.destroy_all_sessions(cur, account_id)
        audit.log(cur, "admin_account_role", actor=actor.id,
                  login=actor.login, kind="account", obj_id=account_id,
                  ip=client_ip(request), outcome="ok" if changed else "denied")
    return redirect("/admin/accounts",
                    ok="Роль изменена, сессии пользователя закрыты."
                    if changed else None,
                    err=None if changed else "Учётная запись не найдена.")


@app.post("/admin/accounts/{account_id}/active")
def admin_account_active(request: Request, account_id: int,
                         csrf_token: str = Form("")):
    actor = require_actor(request, "admin")
    require_csrf(actor, csrf_token)
    if account_id == actor.id:
        return redirect("/admin/accounts",
                        err="Нельзя заблокировать собственную учётную запись.")
    with db.tx(actor.id, True) as cur:
        cur.execute(
            "UPDATE app.account SET is_active = NOT is_active WHERE id = %s "
            "RETURNING is_active", (account_id,))
        row = cur.fetchone()
        if row and not row["is_active"]:
            auth.destroy_all_sessions(cur, account_id)
        audit.log(cur, "admin_account_lock", actor=actor.id, login=actor.login,
                  kind="account", obj_id=account_id, ip=client_ip(request),
                  outcome="ok" if row else "denied")
    if not row:
        return redirect("/admin/accounts", err="Учётная запись не найдена.")
    return redirect("/admin/accounts",
                    ok="Учётная запись включена." if row["is_active"]
                    else "Учётная запись заблокирована, сессии закрыты.")


@app.post("/admin/accounts/{account_id}/delete")
def admin_account_delete(request: Request, account_id: int,
                         csrf_token: str = Form("")):
    actor = require_actor(request, "admin")
    require_csrf(actor, csrf_token)
    if account_id == actor.id:
        return redirect("/admin/accounts",
                        err="Нельзя удалить собственную учётную запись.")
    with db.tx(actor.id, True) as cur:
        # Записи, сессии и теги удалятся каскадом по внешним ключам,
        # а строки журнала аудита сохранятся (actor_id обнулится):
        # удаление пользователя не должно стирать следы его действий.
        cur.execute("DELETE FROM app.account WHERE id = %s", (account_id,))
        removed = cur.rowcount > 0
        audit.log(cur, "admin_account_delete", actor=actor.id,
                  login=actor.login, kind="account", obj_id=account_id,
                  ip=client_ip(request), outcome="ok" if removed else "denied")
    if not removed:
        return redirect("/admin/accounts", err="Учётная запись не найдена.")
    return redirect("/admin/accounts", ok="Учётная запись удалена.")


@app.get("/admin/secrets")
def admin_secrets(request: Request):
    """Обзор конфиденциальных записей БЕЗ содержимого.

    Осознанное ограничение полномочий администратора: расшифровка
    выполняется только в контексте владельца, поэтому компрометация
    административной учётной записи не раскрывает конфиденциальные данные
    всех пользователей (CWE-250).
    """
    actor = require_actor(request, "admin")
    with db.tx(actor.id, True) as cur:
        rows = secrets_store.metadata_for_admin(cur)
        audit.log(cur, "admin_secret_metadata", actor=actor.id,
                  login=actor.login, ip=client_ip(request))
    return render(request, "admin_secrets.html", actor=actor, rows=rows)


@app.get("/admin/audit")
def admin_audit(request: Request, limit: int = Query(200, ge=1, le=1000)):
    actor = require_actor(request, "admin")
    with db.tx(actor.id, True) as cur:
        cur.execute(
            """
            SELECT at, actor_id, actor_login, action, object_kind, object_id,
                   ip_addr, outcome
            FROM app.audit_event
            ORDER BY at DESC, id DESC
            LIMIT %s
            """,
            (limit,),
        )
        rows = cur.fetchall()
        audit.log(cur, "admin_audit_read", actor=actor.id, login=actor.login,
                  ip=client_ip(request))
    return render(request, "admin_audit.html", actor=actor, rows=rows)
