"""Доступ к PostgreSQL.

Ключевой инвариант модуля: каждая транзакция начинается с установки
app.actor_id (и app.is_admin) через set_config(..., is_local => true).
Параметр локален для транзакции, поэтому значение не переносится между
запросами через пул соединений - иначе построчная защита показывала бы
данные предыдущего пользователя.

Идентификатор субъекта берётся ТОЛЬКО из проверенной сессии и никогда
не принимается из параметров запроса.
"""

from contextlib import contextmanager

from psycopg.rows import dict_row
from psycopg_pool import ConnectionPool

_pool = None


def open_pool(dsn, min_size=1, max_size=8):
    global _pool
    _pool = ConnectionPool(dsn, min_size=min_size, max_size=max_size,
                           kwargs={"row_factory": dict_row}, open=False)
    _pool.open()
    _pool.wait(timeout=30)
    return _pool


def close_pool():
    global _pool
    if _pool is not None:
        _pool.close()
        _pool = None


@contextmanager
def tx(actor_id=None, is_admin=False):
    """Транзакция с установленным контекстом субъекта.

    Вызов без actor_id используется до аутентификации (таблицы account и
    session построчной защитой не закрыты - иначе вход был бы невозможен).
    Для таблиц с RLS отсутствие actor_id означает пустую выборку.
    """
    if _pool is None:
        raise RuntimeError("пул соединений не открыт")
    with _pool.connection() as conn:
        with conn.transaction():
            with conn.cursor() as cur:
                cur.execute("SELECT set_config('app.actor_id', %s, true)",
                            ("" if actor_id is None else str(actor_id),))
                cur.execute("SELECT set_config('app.is_admin', %s, true)",
                            ("on" if is_admin else "off",))
                yield cur
