"""НЕконфиденциальные данные (app.public_note).

Хранятся в открытом виде: этот класс данных по условию задачи не требует
шифрования, а полнотекстовый поиск по tsvector даёт полноценную семантику
без компромиссов. Ограничение доступа - построчной защитой на уровне СУБД
плюс проверка роли в обработчике.

Все запросы параметризованы. Ни одной конкатенации строк в SQL в модуле нет.
"""

FIELDS = ("id", "owner_id", "title", "body", "visibility",
          "created_at", "updated_at")


def create(cur, owner_id, title, body, visibility):
    cur.execute(
        """
        INSERT INTO app.public_note (owner_id, title, body, visibility)
        VALUES (%s, %s, %s, %s)
        RETURNING id
        """,
        (owner_id, title, body, visibility),
    )
    return cur.fetchone()["id"]


def update(cur, note_id, title, body, visibility):
    """Возвращает False, если строка недоступна.

    Отличить «нет такой записи» от «запись чужая» здесь невозможно и не
    нужно: политика note_owner_rw просто не покажет чужую строку, и
    rowcount окажется нулевым. Наружу в обоих случаях уходит один и тот же
    ответ - раскрывать существование чужих записей незачем.
    """
    cur.execute(
        """
        UPDATE app.public_note
        SET title = %s, body = %s, visibility = %s, updated_at = now()
        WHERE id = %s
        """,
        (title, body, visibility, note_id),
    )
    return cur.rowcount > 0


def delete(cur, note_id):
    cur.execute("DELETE FROM app.public_note WHERE id = %s", (note_id,))
    return cur.rowcount > 0


def list_visible(cur, limit=200):
    cur.execute(
        """
        SELECT n.id, n.owner_id, n.title, n.body, n.visibility,
               n.created_at, n.updated_at, a.login AS owner_login
        FROM app.public_note n
        JOIN app.account a ON a.id = n.owner_id
        ORDER BY n.updated_at DESC
        LIMIT %s
        """,
        (limit,),
    )
    return cur.fetchall()


def search(cur, query, limit=200):
    """Полнотекстовый поиск.

    plainto_tsquery принимает произвольный пользовательский ввод и сама
    превращает его в корректный tsquery, поэтому спецсимволы поисковой
    строки не могут сломать запрос.
    """
    cur.execute(
        """
        SELECT n.id, n.owner_id, n.title, n.body, n.visibility,
               n.created_at, n.updated_at, a.login AS owner_login,
               ts_rank(n.search_vec, plainto_tsquery('russian', %s)) AS rank
        FROM app.public_note n
        JOIN app.account a ON a.id = n.owner_id
        WHERE n.search_vec @@ plainto_tsquery('russian', %s)
        ORDER BY rank DESC, n.updated_at DESC
        LIMIT %s
        """,
        (query, query, limit),
    )
    return cur.fetchall()
