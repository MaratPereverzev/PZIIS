"""Проверки защищённости приложения целиком.

Требуют работающей СУБД (переменная VAULT_DSN). Каждая проверка
соответствует пункту раздела «План демонстрации защищённости» из
docs/02-analysis.md, поэтому набор одновременно служит и обоснованием
защищённости, и регрессионной защитой.
"""

import os
import uuid

import psycopg
import pytest
from fastapi.testclient import TestClient

PW = "Sufficiently-Long-Passphrase-42"
ADMIN_LOGIN = os.environ.get("VAULT_ADMIN_LOGIN", "admin_sys")
ADMIN_PW = os.environ.get("VAULT_ADMIN_PASSWORD", "")


def uniq(prefix):
    return "%s_%s" % (prefix, uuid.uuid4().hex[:10])


@pytest.fixture(scope="module")
def client():
    from app.main import app
    # base_url https: cookie выставлены с флагом Secure и по http
    # не сохранились бы.
    with TestClient(app, base_url="https://testserver") as test_client:
        yield test_client


@pytest.fixture(scope="module")
def sql():
    """Прямое подключение к БД под ролью приложения - для проверок,
    которые невозможно выполнить через HTTP (привилегии, RLS)."""
    from app import db
    return db


def register(client, login, password=PW):
    response = client.post("/register",
                           data={"login": login, "password": password,
                                 "password2": password},
                           follow_redirects=False)
    assert response.status_code == 303
    return login


def do_login(client, login, password=PW):
    """Возвращает набор cookie сессии либо None при отказе."""
    client.cookies.clear()
    response = client.post("/login", data={"login": login, "password": password},
                           follow_redirects=False)
    if "vault_session" not in client.cookies:
        return None, response
    return ({"vault_session": client.cookies["vault_session"],
             "vault_csrf": client.cookies["vault_csrf"]}, response)


def use(client, session):
    client.cookies.clear()
    for name, value in (session or {}).items():
        client.cookies.set(name, value)


def account_id(db, login):
    with db.tx() as cur:
        cur.execute("SELECT id FROM app.account WHERE login = %s", (login,))
        return cur.fetchone()["id"]


def set_role(db, login, role):
    """Подготовка данных: назначение роли напрямую в БД.

    Работа самого административного обработчика проверяется отдельно
    (test_admin_can_change_role_via_http).
    """
    with db.tx() as cur:
        cur.execute("UPDATE app.account SET app_role = %s WHERE login = %s",
                    (role, login))


@pytest.fixture(scope="module")
def user_a(client, sql):
    login = register(client, uniq("alice"))
    set_role(sql, login, "user")
    return login


@pytest.fixture(scope="module")
def user_b(client, sql):
    login = register(client, uniq("bob"))
    set_role(sql, login, "user")
    return login


@pytest.fixture(scope="module")
def guest(client):
    return register(client, uniq("guest"))


# ===========================================================================
# 1. Хранение паролей
# ===========================================================================

def test_passwords_stored_as_argon2id(sql, user_a):
    with sql.tx() as cur:
        cur.execute("SELECT pwd_hash FROM app.account WHERE login = %s",
                    (user_a,))
        stored = cur.fetchone()["pwd_hash"]
    assert stored.startswith("$argon2id$")
    assert PW not in stored


# ===========================================================================
# 2. Шифрование конфиденциальных данных
# ===========================================================================

def test_secret_is_stored_encrypted(client, sql, user_a):
    session, _ = do_login(client, user_a)
    use(client, session)
    title = "Договор аренды " + uuid.uuid4().hex[:6]
    body = "Очень секретное содержимое " + uuid.uuid4().hex[:6]
    response = client.post("/secrets",
                           data={"title": title, "body": body,
                                 "csrf_token": session["vault_csrf"]},
                           follow_redirects=False)
    assert response.status_code == 303

    # Ни заголовка, ни тела в открытом виде в таблице нет ни в одном столбце.
    with sql.tx() as cur:
        cur.execute("SELECT title_ct, body_ct, title_nonce, body_nonce "
                    "FROM app.secret_record")
        rows = cur.fetchall()
    blob = b"".join(bytes(r[c]) for r in rows for c in
                    ("title_ct", "body_ct", "title_nonce", "body_nonce"))
    assert title.encode("utf-8") not in blob
    assert body.encode("utf-8") not in blob

    # Владельцу запись видна в открытом виде.
    page = client.get("/secrets")
    assert title in page.text and body in page.text


def test_blind_index_stores_only_hmac_tags(client, sql, user_a):
    session, _ = do_login(client, user_a)
    use(client, session)
    marker = "уникальноеслово" + uuid.uuid4().hex[:6]
    client.post("/secrets", data={"title": marker, "body": "тело",
                                  "csrf_token": session["vault_csrf"]},
                follow_redirects=False)
    with sql.tx() as cur:
        cur.execute("SELECT tag FROM app.secret_tag")
        tags = b"".join(bytes(r["tag"]) for r in cur.fetchall())
    assert marker.encode("utf-8") not in tags
    assert all(len(bytes(t)) == 16 for t in [tags[i:i + 16]
                                             for i in range(0, len(tags), 16)])


def test_search_over_ciphertext_works(client, user_a):
    session, _ = do_login(client, user_a)
    use(client, session)
    token = "инвентаризация" + uuid.uuid4().hex[:5]
    client.post("/secrets", data={"title": "Акт " + token, "body": "тело акта",
                                  "csrf_token": session["vault_csrf"]},
                follow_redirects=False)
    found = client.post("/secrets/search",
                        data={"q": token, "csrf_token": session["vault_csrf"]})
    assert token in found.text
    missing = client.post("/secrets/search",
                          data={"q": "словокоторогонет" + uuid.uuid4().hex[:5],
                                "csrf_token": session["vault_csrf"]})
    assert "Ничего не найдено" in missing.text


# ===========================================================================
# 3. Построчная защита: изоляция данных между пользователями
# ===========================================================================

def test_user_cannot_read_another_users_secret_over_http(client, sql,
                                                        user_a, user_b):
    session_a, _ = do_login(client, user_a)
    use(client, session_a)
    title = "ТайнаА" + uuid.uuid4().hex[:6]
    client.post("/secrets", data={"title": title, "body": "тело",
                                  "csrf_token": session_a["vault_csrf"]},
                follow_redirects=False)

    session_b, _ = do_login(client, user_b)
    use(client, session_b)
    assert title not in client.get("/secrets").text


def test_rls_blocks_foreign_rows_in_database(sql, user_a, user_b):
    """Тот же запрет на уровне СУБД, независимо от кода приложения."""
    id_a, id_b = account_id(sql, user_a), account_id(sql, user_b)
    with sql.tx(actor_id=id_a) as cur:
        cur.execute("SELECT count(*) AS n FROM app.secret_record")
        own = cur.fetchone()["n"]
    assert own > 0
    with sql.tx(actor_id=id_b) as cur:
        cur.execute("SELECT count(*) AS n FROM app.secret_record "
                    "WHERE owner_id = %s", (id_a,))
        assert cur.fetchone()["n"] == 0


def test_rls_denies_everything_without_actor(sql):
    """Безопасный отказ: не выставлен actor_id - не видно ни одной строки."""
    with sql.tx() as cur:
        cur.execute("SELECT count(*) AS n FROM app.secret_record")
        assert cur.fetchone()["n"] == 0


def test_actor_id_does_not_leak_between_transactions(sql, user_a):
    """set_config(..., is_local => true) действует до конца транзакции.

    Без этого значение сохранялось бы в соединении и следующий запрос из
    пула увидел бы данные предыдущего пользователя.
    """
    id_a = account_id(sql, user_a)
    with sql.tx(actor_id=id_a) as cur:
        cur.execute("SELECT count(*) AS n FROM app.secret_record")
        assert cur.fetchone()["n"] > 0
    for _ in range(10):
        with sql.tx() as cur:
            cur.execute("SELECT current_setting('app.actor_id', true) AS a")
            assert (cur.fetchone()["a"] or "") == ""


def test_blind_index_tags_are_not_visible_across_users(sql, user_a, user_b):
    id_b = account_id(sql, user_b)
    with sql.tx(actor_id=id_b) as cur:
        cur.execute(
            """
            SELECT count(*) AS n FROM app.secret_tag t
            JOIN app.secret_record r ON r.id = t.record_id
            WHERE r.owner_id <> %s
            """,
            (id_b,),
        )
        assert cur.fetchone()["n"] == 0


# ===========================================================================
# 4. Ограничение полномочий администратора
# ===========================================================================

@pytest.mark.skipif(not ADMIN_PW, reason="VAULT_ADMIN_PASSWORD не задан")
def test_admin_sees_metadata_but_not_plaintext(client, user_a):
    session_a, _ = do_login(client, user_a)
    use(client, session_a)
    title = "СекретДляПроверкиАдмина" + uuid.uuid4().hex[:6]
    client.post("/secrets", data={"title": title, "body": "тело",
                                  "csrf_token": session_a["vault_csrf"]},
                follow_redirects=False)

    session_admin, _ = do_login(client, ADMIN_LOGIN, ADMIN_PW)
    assert session_admin is not None, "администратор не смог войти"
    use(client, session_admin)

    overview = client.get("/admin/secrets")
    assert overview.status_code == 200
    assert user_a in overview.text          # метаданные: владелец виден
    assert title not in overview.text       # открытого текста нет
    assert title not in client.get("/secrets").text


@pytest.mark.skipif(not ADMIN_PW, reason="VAULT_ADMIN_PASSWORD не задан")
def test_admin_can_change_role_via_http(client, sql, guest):
    session_admin, _ = do_login(client, ADMIN_LOGIN, ADMIN_PW)
    use(client, session_admin)
    target = account_id(sql, guest)
    response = client.post("/admin/accounts/%d/role" % target,
                           data={"app_role": "user",
                                 "csrf_token": session_admin["vault_csrf"]},
                           follow_redirects=False)
    assert response.status_code == 303
    with sql.tx() as cur:
        cur.execute("SELECT app_role FROM app.account WHERE id = %s", (target,))
        assert cur.fetchone()["app_role"] == "user"
    # Смена роли закрывает сессии пользователя немедленно.
    with sql.tx() as cur:
        cur.execute("SELECT count(*) AS n FROM app.session WHERE account_id = %s",
                    (target,))
        assert cur.fetchone()["n"] == 0
    set_role(sql, guest, "guest")


# ===========================================================================
# 5. Разграничение прав в приложении
# ===========================================================================

def test_guest_has_no_access_to_confidential_subsystem(client, guest):
    session, _ = do_login(client, guest)
    use(client, session)
    assert client.get("/secrets").status_code == 403


def test_guest_cannot_write_notes(client, guest):
    session, _ = do_login(client, guest)
    use(client, session)
    response = client.post("/notes",
                           data={"title": "от гостя", "body": "текст",
                                 "visibility": "public",
                                 "csrf_token": session["vault_csrf"]},
                           follow_redirects=False)
    assert response.status_code == 403


def test_guest_cannot_reach_admin_pages(client, guest):
    session, _ = do_login(client, guest)
    use(client, session)
    for path in ("/admin/accounts", "/admin/audit", "/admin/secrets"):
        assert client.get(path).status_code == 403


def test_anonymous_is_redirected_to_login(client):
    client.cookies.clear()
    for path in ("/notes", "/secrets", "/admin/accounts"):
        response = client.get(path, follow_redirects=False)
        assert response.status_code == 303
        assert response.headers["location"] == "/login"


def test_internal_notes_hidden_from_others(client, sql, user_a, guest):
    session_a, _ = do_login(client, user_a)
    use(client, session_a)
    marker = "ВнутренняяЗапись" + uuid.uuid4().hex[:6]
    client.post("/notes", data={"title": marker, "body": "текст",
                                "visibility": "internal",
                                "csrf_token": session_a["vault_csrf"]},
                follow_redirects=False)
    session_guest, _ = do_login(client, guest)
    use(client, session_guest)
    assert marker not in client.get("/notes").text


# ===========================================================================
# 6. Инъекции и XSS
# ===========================================================================

def test_sql_injection_in_note_search_is_inert(client, user_a):
    session, _ = do_login(client, user_a)
    use(client, session)
    response = client.get("/notes", params={"q": "' OR 1=1 --"})
    assert response.status_code == 200
    assert "Записей нет" in response.text or "<tbody>" in response.text
    # База по-прежнему жива: инъекция не выполнилась.
    assert client.get("/healthz").json() == {"status": "ok"}


def test_sql_injection_in_secret_search_is_inert(client, user_a):
    session, _ = do_login(client, user_a)
    use(client, session)
    response = client.post("/secrets/search",
                           data={"q": "'; DROP TABLE app.secret_record; --",
                                 "csrf_token": session["vault_csrf"]})
    assert response.status_code == 200
    assert client.get("/secrets").status_code == 200


def test_stored_xss_is_escaped(client, user_a):
    session, _ = do_login(client, user_a)
    use(client, session)
    payload = "<script>alert('xss')</script>"
    client.post("/notes", data={"title": payload, "body": payload,
                                "visibility": "public",
                                "csrf_token": session["vault_csrf"]},
                follow_redirects=False)
    page = client.get("/notes")
    assert "<script>alert" not in page.text
    assert "&lt;script&gt;" in page.text
    assert "script-src 'none'" in page.headers["content-security-policy"]


def test_security_headers_present(client):
    response = client.get("/login")
    headers = response.headers
    assert "default-src 'self'" in headers["content-security-policy"]
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert "no-store" in headers["cache-control"]


# ===========================================================================
# 7. Сессии, CSRF и деавторизация
# ===========================================================================

def test_logout_invalidates_session_immediately(client, user_a):
    session, _ = do_login(client, user_a)
    use(client, session)
    assert client.get("/secrets").status_code == 200

    client.post("/logout", data={"csrf_token": session["vault_csrf"]},
                follow_redirects=False)

    # Возврат прежних cookie не восстанавливает доступ: строка сессии
    # удалена на сервере. С JWT токен остался бы валидным.
    use(client, session)
    response = client.get("/secrets", follow_redirects=False)
    assert response.status_code == 303
    assert response.headers["location"] == "/login"


def test_logout_all_closes_every_session(client, sql, user_a):
    first, _ = do_login(client, user_a)
    second, _ = do_login(client, user_a)
    use(client, second)
    client.post("/logout/all", data={"csrf_token": second["vault_csrf"]},
                follow_redirects=False)
    use(client, first)
    assert client.get("/secrets", follow_redirects=False).status_code == 303


def test_session_id_changes_on_every_login(client, user_a):
    """Защита от фиксации сессии: токен, известный до входа, не станет
    авторизованным."""
    first, _ = do_login(client, user_a)
    second, _ = do_login(client, user_a)
    assert first["vault_session"] != second["vault_session"]


def test_session_token_is_not_stored_in_plaintext(sql, client, user_a):
    session, _ = do_login(client, user_a)
    with sql.tx() as cur:
        cur.execute("SELECT token_hash FROM app.session")
        stored = b"".join(bytes(r["token_hash"]) for r in cur.fetchall())
    assert session["vault_session"].encode() not in stored


def test_write_without_csrf_token_is_rejected(client, user_a):
    session, _ = do_login(client, user_a)
    use(client, session)
    for data in ({}, {"csrf_token": "подделка"}):
        payload = {"title": "без csrf", "body": "текст",
                   "visibility": "public", **data}
        assert client.post("/notes", data=payload,
                           follow_redirects=False).status_code == 403


def test_session_cookie_flags(client, user_a):
    client.cookies.clear()
    response = client.post("/login", data={"login": user_a, "password": PW},
                           follow_redirects=False)
    cookies = "; ".join(response.headers.get_list("set-cookie"))
    assert "HttpOnly" in cookies      # недостижимо из JS даже при XSS
    assert "SameSite=strict" in cookies.replace("samesite", "SameSite")
    if os.environ.get("VAULT_COOKIE_SECURE", "1") == "1":
        assert "Secure" in cookies


# ===========================================================================
# 8. Противодействие перебору и перечислению учётных записей
# ===========================================================================

def test_no_account_enumeration(client, user_a):
    """Ответ на неизвестный логин и на неверный пароль неразличим."""
    _, unknown = do_login(client, uniq("nobody"), "Some-Wrong-Passphrase-1")
    _, wrong = do_login(client, user_a, "Some-Wrong-Passphrase-1")
    assert unknown.status_code == wrong.status_code == 303
    assert unknown.headers["location"] == wrong.headers["location"]


def test_registration_does_not_reveal_taken_login(client, user_a):
    taken = client.post("/register",
                        data={"login": user_a, "password": PW,
                              "password2": PW}, follow_redirects=False)
    free = client.post("/register",
                       data={"login": uniq("fresh"), "password": PW,
                             "password2": PW}, follow_redirects=False)
    assert taken.headers["location"] == free.headers["location"]


def test_weak_password_rejected(client):
    response = client.post("/register",
                           data={"login": uniq("weak"), "password": "password123",
                                 "password2": "password123"},
                           follow_redirects=False)
    assert response.status_code == 303
    assert "/register" in response.headers["location"]


def test_short_password_rejected(client):
    response = client.post("/register",
                           data={"login": uniq("short"), "password": "Abc12345",
                                 "password2": "Abc12345"},
                           follow_redirects=False)
    assert "/register" in response.headers["location"]


def test_account_lockout_after_repeated_failures(client, sql):
    login = register(client, uniq("locktest"))
    for _ in range(10):
        do_login(client, login, "Definitely-Wrong-Passphrase-9")
    with sql.tx() as cur:
        cur.execute("SELECT locked_until FROM app.account WHERE login = %s",
                    (login,))
        assert cur.fetchone()["locked_until"] is not None
    # Верный пароль во время блокировки тоже не принимается.
    session, _ = do_login(client, login)
    assert session is None


# ===========================================================================
# 9. Привилегии сервисной роли в СУБД
# ===========================================================================

def test_audit_log_is_append_only(sql):
    """Скомпрометированное приложение не сможет затереть следы."""
    for statement in ("DELETE FROM app.audit_event",
                      "UPDATE app.audit_event SET action = 'подделка'",
                      "TRUNCATE app.audit_event"):
        with pytest.raises(psycopg.errors.InsufficientPrivilege):
            with sql.tx() as cur:
                cur.execute(statement)


def test_service_role_cannot_execute_ddl(sql):
    for statement in ("CREATE TABLE app.tmp_check (id int)",
                      "DROP TABLE app.secret_record",
                      "ALTER TABLE app.account ADD COLUMN backdoor text"):
        with pytest.raises(psycopg.Error):
            with sql.tx() as cur:
                cur.execute(statement)


def test_service_role_cannot_create_roles(sql):
    with pytest.raises(psycopg.Error):
        with sql.tx() as cur:
            cur.execute("CREATE ROLE tmp_backdoor LOGIN PASSWORD 'x'")


def test_service_role_cannot_disable_rls(sql):
    with pytest.raises(psycopg.Error):
        with sql.tx() as cur:
            cur.execute("ALTER TABLE app.secret_record DISABLE ROW LEVEL SECURITY")


def test_service_role_is_not_superuser(sql):
    with sql.tx() as cur:
        cur.execute("SELECT current_user AS who, "
                    "usesuper AS is_super, userepl AS is_repl "
                    "FROM pg_user WHERE usename = current_user")
        row = cur.fetchone()
    assert row["who"] == "vault_app"
    assert row["is_super"] is False
    assert row["is_repl"] is False
    with sql.tx() as cur:
        cur.execute("SELECT rolbypassrls, rolcreatedb, rolcreaterole "
                    "FROM pg_roles WHERE rolname = current_user")
        row = cur.fetchone()
    assert row["rolbypassrls"] is False
    assert row["rolcreatedb"] is False
    assert row["rolcreaterole"] is False


# ===========================================================================
# 10. Журнал аудита пишет события и не пишет содержимое
# ===========================================================================

def test_audit_records_events_without_confidential_content(client, sql, user_a):
    session, _ = do_login(client, user_a)
    use(client, session)
    marker = "СекретДляАудита" + uuid.uuid4().hex[:6]
    client.post("/secrets", data={"title": marker, "body": "тело",
                                  "csrf_token": session["vault_csrf"]},
                follow_redirects=False)
    client.post("/secrets/search", data={"q": marker,
                                         "csrf_token": session["vault_csrf"]})
    with sql.tx() as cur:
        cur.execute(
            """
            SELECT action, outcome, actor_login, object_kind
            FROM app.audit_event
            WHERE actor_login = %s
            ORDER BY id DESC LIMIT 20
            """,
            (user_a,),
        )
        rows = cur.fetchall()
    actions = {r["action"] for r in rows}
    assert "secret_create" in actions and "secret_search" in actions
    # Ни заголовка записи, ни поисковой фразы в журнале нет.
    assert marker not in str(rows)


def test_failed_login_is_audited_as_denied(client, sql):
    login = register(client, uniq("audit"))
    do_login(client, login, "Definitely-Wrong-Passphrase-9")
    with sql.tx() as cur:
        cur.execute(
            "SELECT outcome FROM app.audit_event "
            "WHERE actor_login = %s AND action = 'login' ORDER BY id DESC LIMIT 1",
            (login,),
        )
        assert cur.fetchone()["outcome"] == "denied"


# ===========================================================================
# 11. Целостность конфиденциальных записей
# ===========================================================================

def test_ciphertext_tampering_is_detected_end_to_end(client, sql, user_a):
    """Правка шифротекста в обход приложения обнаруживается на чтении."""
    session, _ = do_login(client, user_a)
    use(client, session)
    title = "ЗаписьДляПорчи" + uuid.uuid4().hex[:6]
    client.post("/secrets", data={"title": title, "body": "тело",
                                  "csrf_token": session["vault_csrf"]},
                follow_redirects=False)
    owner = account_id(sql, user_a)
    with sql.tx(actor_id=owner) as cur:
        cur.execute("SELECT id, body_ct FROM app.secret_record "
                    "ORDER BY id DESC LIMIT 1")
        row = cur.fetchone()
        broken = bytearray(bytes(row["body_ct"]))
        broken[0] ^= 0x01
        cur.execute("UPDATE app.secret_record SET body_ct = %s WHERE id = %s",
                    (bytes(broken), row["id"]))

    use(client, session)
    response = client.get("/secrets")
    assert response.status_code == 500
    assert "целостност" in response.text.lower()

    # Убираем испорченную запись, чтобы не мешать остальным проверкам.
    with sql.tx(actor_id=owner) as cur:
        cur.execute("DELETE FROM app.secret_record WHERE id = %s", (row["id"],))
