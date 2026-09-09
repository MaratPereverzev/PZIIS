"""КОНФИДЕНЦИАЛЬНЫЕ данные (app.secret_record + app.secret_tag).

Заголовок и тело записи шифруются AES-256-GCM. В таблице нет ни одного
столбца с открытым текстом, поэтому дамп базы без доступа к ключу из
файловой системы не раскрывает содержимое.

Поиск - через слепой индекс. Это центральный компромисс работы: по
шифротексту AES-GCM искать нельзя, а расшифровывать таблицу целиком на
каждый запрос и медленно, и опасно. Цена решения - утечка равенства и
частоты токенов заголовков в пределах одной учётной записи; подробнее
в docs/02-analysis.md.
"""

from app.crypto import KEY_VERSION, normalize_tokens

# Модуль намеренно не имеет ни одной операции, работающей «по всем
# владельцам»: расшифровка возможна только в контексте владельца записи.


def _encrypt_pair(crypto, ext_id, owner_id, title, body):
    title_nonce, title_ct = crypto.encrypt_field(ext_id, owner_id, "title", title)
    body_nonce, body_ct = crypto.encrypt_field(ext_id, owner_id, "body", body)
    return title_nonce, title_ct, body_nonce, body_ct


def _store_tags(cur, crypto, record_id, owner_id, title):
    """Теги слепого индекса для заголовка.

    Индексируется ТОЛЬКО заголовок: тело записи не индексируется вовсе,
    чтобы не расширять утечку частотной статистики на весь текст.
    """
    tags = crypto.blind_tags(owner_id, title)
    for tag in tags:
        cur.execute(
            "INSERT INTO app.secret_tag (record_id, tag) VALUES (%s, %s) "
            "ON CONFLICT DO NOTHING",
            (record_id, tag),
        )
    return len(tags)


def create(cur, crypto, owner_id, title, body):
    from app.crypto import new_ext_id

    # ext_id генерируется до вставки: он входит в связанные данные (AAD),
    # поэтому должен быть известен на момент шифрования.
    ext_id = new_ext_id()
    tn, tc, bn, bc = _encrypt_pair(crypto, ext_id, owner_id, title, body)
    cur.execute(
        """
        INSERT INTO app.secret_record
            (ext_id, owner_id, key_version, title_nonce, title_ct,
             body_nonce, body_ct)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING id
        """,
        (ext_id, owner_id, KEY_VERSION, tn, tc, bn, bc),
    )
    record_id = cur.fetchone()["id"]
    _store_tags(cur, crypto, record_id, owner_id, title)
    return record_id


def update(cur, crypto, owner_id, record_id, title, body):
    """Перешифровывает запись целиком.

    Nonce генерируется заново для каждого поля: переиспользование nonce
    на одном ключе разрушает стойкость GCM, поэтому «частичное»
    редактирование шифротекста не предусмотрено принципиально.
    """
    # Политика own_secrets не покажет чужую строку - выборка ext_id
    # одновременно служит проверкой права на запись.
    cur.execute(
        "SELECT ext_id, key_version FROM app.secret_record WHERE id = %s",
        (record_id,),
    )
    row = cur.fetchone()
    if row is None:
        return False

    ext_id = row["ext_id"]
    tn, tc = crypto.encrypt_field(ext_id, owner_id, "title", title,
                                  row["key_version"])
    bn, bc = crypto.encrypt_field(ext_id, owner_id, "body", body,
                                  row["key_version"])
    cur.execute(
        """
        UPDATE app.secret_record
        SET title_nonce = %s, title_ct = %s, body_nonce = %s, body_ct = %s,
            updated_at = now()
        WHERE id = %s
        """,
        (tn, tc, bn, bc, record_id),
    )
    if cur.rowcount == 0:
        return False
    cur.execute("DELETE FROM app.secret_tag WHERE record_id = %s", (record_id,))
    _store_tags(cur, crypto, record_id, owner_id, title)
    return True


def delete(cur, record_id):
    # Теги удаляются каскадом по внешнему ключу.
    cur.execute("DELETE FROM app.secret_record WHERE id = %s", (record_id,))
    return cur.rowcount > 0


def _decrypt_rows(crypto, owner_id, rows):
    out = []
    for row in rows:
        item = {
            "id": row["id"],
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "title": crypto.decrypt_field(row["ext_id"], owner_id, "title",
                                          row["title_nonce"], row["title_ct"],
                                          row["key_version"]),
            "body": crypto.decrypt_field(row["ext_id"], owner_id, "body",
                                         row["body_nonce"], row["body_ct"],
                                         row["key_version"]),
        }
        out.append(item)
    return out


_SELECT_COLUMNS = """
    id, ext_id, key_version, title_nonce, title_ct, body_nonce, body_ct,
    created_at, updated_at
"""


def list_own(cur, crypto, owner_id, limit=200):
    cur.execute(
        "SELECT %s FROM app.secret_record ORDER BY updated_at DESC LIMIT %%s"
        % _SELECT_COLUMNS,
        (limit,),
    )
    return _decrypt_rows(crypto, owner_id, cur.fetchall())


def search(cur, crypto, owner_id, query, limit=200):
    """Поиск по слепому индексу.

    1. Поисковая фраза нормализуется теми же правилами, что при сохранении.
    2. Для каждого токена считается HMAC-тег.
    3. Отбираются записи, содержащие ВСЕ теги фразы.
    4. Записи расшифровываются, и совпадение проверяется по открытому
       тексту - это отбрасывает ложные срабатывания из-за усечения тега
       до 16 байт.
    """
    tokens = sorted(normalize_tokens(query))
    if not tokens:
        return []
    tags = [crypto.blind_tag(owner_id, t) for t in tokens]

    cur.execute(
        """
        SELECT record_id
        FROM app.secret_tag
        WHERE tag = ANY(%s)
        GROUP BY record_id
        HAVING count(DISTINCT tag) = %s
        LIMIT %s
        """,
        (tags, len(set(tags)), limit),
    )
    ids = [r["record_id"] for r in cur.fetchall()]
    if not ids:
        return []

    cur.execute(
        "SELECT %s FROM app.secret_record WHERE id = ANY(%%s) "
        "ORDER BY updated_at DESC" % _SELECT_COLUMNS,
        (ids,),
    )
    found = _decrypt_rows(crypto, owner_id, cur.fetchall())

    # Отсев коллизий усечённого тега: проверка по расшифрованному тексту.
    result = []
    for item in found:
        title_tokens = normalize_tokens(item["title"])
        if all(t in title_tokens for t in tokens):
            result.append(item)
    return result


def metadata_for_admin(cur, limit=200):
    """Обзор конфиденциальных записей для администратора - без содержимого.

    Читается представление app.secret_metadata, которое не отдаёт ни одного
    столбца с шифротекстом. Расшифровать чужую запись администратор не
    может: операции расшифровки существуют только в контексте владельца.
    """
    cur.execute(
        """
        SELECT id, ext_id, owner_id, owner_login, title_bytes, body_bytes,
               key_version, created_at, updated_at
        FROM app.secret_metadata
        ORDER BY updated_at DESC
        LIMIT %s
        """,
        (limit,),
    )
    return cur.fetchall()
