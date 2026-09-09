"""Журнал аудита.

Роли приложения выданы только INSERT и SELECT на app.audit_event, поэтому
скомпрометированное приложение не может изменить или удалить запись
журнала. В журнал попадают только идентификаторы объектов: ни заголовков,
ни тел конфиденциальных записей, ни поисковых фраз - иначе журнал стал бы
вторым, незащищённым хранилищем конфиденциальных данных.
"""

ACTIONS = (
    "register", "login", "logout", "logout_all",
    "note_create", "note_update", "note_delete", "note_search",
    "secret_create", "secret_update", "secret_delete", "secret_search",
    "admin_account_create", "admin_account_role", "admin_account_lock",
    "admin_account_delete", "admin_audit_read", "admin_secret_metadata",
)


def log(cur, action, actor=None, login=None, kind=None, obj_id=None,
        ip=None, outcome="ok"):
    cur.execute(
        """
        INSERT INTO app.audit_event
            (actor_id, actor_login, action, object_kind, object_id,
             ip_addr, outcome)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        """,
        (actor, login, action, kind, obj_id, ip, outcome),
    )
