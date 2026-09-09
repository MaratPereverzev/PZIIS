-- Схема app: объекты приложения pziis-vault.
--
-- Скрипт выполняется от имени postgres, поэтому владельцем всех таблиц
-- становится postgres, а НЕ vault_app. Это принципиально: владелец таблицы
-- по умолчанию не подчиняется построчной защите, и если бы владельцем была
-- сервисная роль, все политики RLS ниже не действовали бы на приложение.

\set ON_ERROR_STOP on

CREATE EXTENSION IF NOT EXISTS pgcrypto;   -- gen_random_uuid()
CREATE EXTENSION IF NOT EXISTS citext;     -- регистронезависимый логин

-- Схема public по умолчанию доступна всем на создание объектов.
REVOKE ALL ON SCHEMA public FROM PUBLIC;

CREATE SCHEMA app;
GRANT USAGE ON SCHEMA app TO vault_app;

-- ===========================================================================
-- Учётные записи
-- ===========================================================================
CREATE TABLE app.account (
    id              bigserial PRIMARY KEY,
    login           citext UNIQUE NOT NULL CHECK (length(login) BETWEEN 3 AND 64),
    -- Строка Argon2id в формате PHC: параметры стоимости едут вместе
    -- с хешем, поэтому их можно поднять и перехешировать пароль
    -- при следующем успешном входе.
    pwd_hash        text NOT NULL,
    app_role        text NOT NULL DEFAULT 'guest'
                    CHECK (app_role IN ('admin', 'user', 'guest')),
    is_active       boolean NOT NULL DEFAULT true,
    failed_count    smallint NOT NULL DEFAULT 0,
    locked_until    timestamptz,
    pwd_changed_at  timestamptz NOT NULL DEFAULT now(),
    created_at      timestamptz NOT NULL DEFAULT now()
);

-- ===========================================================================
-- Сессии
-- ===========================================================================
-- В базе лежит только SHA-256 от opaque-токена: дамп таблицы не позволяет
-- переиграть чужую сессию. Деавторизация - удаление строки, поэтому отзыв
-- мгновенный (в отличие от JWT, который остался бы валидным).
CREATE TABLE app.session (
    id               bigserial PRIMARY KEY,
    token_hash       bytea UNIQUE NOT NULL CHECK (length(token_hash) = 32),
    csrf_hash        bytea NOT NULL CHECK (length(csrf_hash) = 32),
    account_id       bigint NOT NULL REFERENCES app.account(id) ON DELETE CASCADE,
    idle_expires_at  timestamptz NOT NULL,
    hard_expires_at  timestamptz NOT NULL,
    ip_addr          inet,
    ua_hash          bytea,
    created_at       timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX session_account_idx ON app.session (account_id);
CREATE INDEX session_hard_exp_idx ON app.session (hard_expires_at);

-- ===========================================================================
-- НЕконфиденциальные данные
-- ===========================================================================
-- Хранятся в открытом виде, поиск - штатный полнотекстовый.
CREATE TABLE app.public_note (
    id          bigserial PRIMARY KEY,
    owner_id    bigint NOT NULL REFERENCES app.account(id) ON DELETE CASCADE,
    title       varchar(200) NOT NULL CHECK (length(btrim(title)) > 0),
    body        text NOT NULL CHECK (length(body) <= 8000),
    visibility  text NOT NULL DEFAULT 'public'
                CHECK (visibility IN ('public', 'internal')),
    search_vec  tsvector GENERATED ALWAYS AS
                (to_tsvector('russian', title || ' ' || body)) STORED,
    created_at  timestamptz NOT NULL DEFAULT now(),
    updated_at  timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX note_search_idx ON app.public_note USING gin (search_vec);
CREATE INDEX note_owner_idx  ON app.public_note (owner_id);

-- ===========================================================================
-- КОНФИДЕНЦИАЛЬНЫЕ данные
-- ===========================================================================
-- Открытого текста в таблице нет. ext_id генерируется приложением ДО
-- вставки и входит в связанные данные (AAD) режима AES-256-GCM, поэтому
-- шифротекст нельзя переставить в другую запись, другое поле или другому
-- владельцу - проверка тега аутентичности не пройдёт.
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
CREATE INDEX secret_owner_idx ON app.secret_record (owner_id);

-- Слепой индекс: HMAC-SHA256(K_idx, owner_id || token), усечённый до 16 байт.
-- Позволяет искать по зашифрованным записям, не расшифровывая таблицу.
-- Владелец входит в вычисление тега, поэтому одинаковые слова у разных
-- пользователей дают разные теги - частотный анализ ограничен одной
-- учётной записью.
CREATE TABLE app.secret_tag (
    record_id  bigint NOT NULL REFERENCES app.secret_record(id) ON DELETE CASCADE,
    tag        bytea NOT NULL CHECK (length(tag) = 16),
    PRIMARY KEY (record_id, tag)
);
CREATE INDEX secret_tag_idx ON app.secret_tag (tag);

-- ===========================================================================
-- Журнал аудита (только добавление)
-- ===========================================================================
-- Открытых данных в журнале нет: только идентификаторы объектов, иначе
-- журнал стал бы вторым, незащищённым хранилищем конфиденциальной
-- информации.
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
CREATE INDEX audit_at_idx ON app.audit_event (at DESC);

-- ===========================================================================
-- Представление метаданных конфиденциальных записей
-- ===========================================================================
-- Администратору нужен обзор конфиденциальных записей, но НЕ их содержимое.
-- Представление принадлежит postgres и по умолчанию исполняется с правами
-- владельца (security_invoker = false), поэтому обходит RLS таблицы, но
-- не отдаёт ни одного столбца с шифротекстом.
CREATE VIEW app.secret_metadata AS
SELECT r.id,
       r.ext_id,
       r.owner_id,
       a.login                AS owner_login,
       length(r.title_ct)     AS title_bytes,
       length(r.body_ct)      AS body_bytes,
       r.key_version,
       r.created_at,
       r.updated_at
FROM app.secret_record r
JOIN app.account a ON a.id = r.owner_id;

-- ===========================================================================
-- Привилегии сервисной роли
-- ===========================================================================
GRANT SELECT, INSERT, UPDATE, DELETE ON app.account       TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.session       TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.public_note   TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.secret_record TO vault_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON app.secret_tag    TO vault_app;
GRANT SELECT                         ON app.secret_metadata TO vault_app;

-- Журнал: только добавление и чтение. UPDATE и DELETE не выданы намеренно -
-- скомпрометированное приложение не сможет затереть следы своих действий.
GRANT SELECT, INSERT ON app.audit_event TO vault_app;

GRANT USAGE ON ALL SEQUENCES IN SCHEMA app TO vault_app;

-- DDL сервисной роли недоступен вовсе: CREATE на схеме app не выдан.

-- ===========================================================================
-- Построчная защита: второй, независимый от кода приложения контур
-- ===========================================================================
-- Идентификатор действующего субъекта приложение выставляет в каждой
-- транзакции через set_config('app.actor_id', ..., true). Параметр локален
-- для транзакции, поэтому не протекает между запросами через пул соединений.
--
-- Если параметр не выставлен, current_setting(..., true) вернёт NULL,
-- сравнение даст NULL, и политика не пропустит ни одной строки -
-- безопасный отказ по умолчанию.

ALTER TABLE app.secret_record ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_secrets ON app.secret_record FOR ALL TO vault_app
    USING      (owner_id = nullif(current_setting('app.actor_id', true), '')::bigint)
    WITH CHECK (owner_id = nullif(current_setting('app.actor_id', true), '')::bigint);

-- Администратор сознательно НЕ получает политики на secret_record:
-- открытый текст чужих записей ему недоступен, обзор - через
-- представление secret_metadata.

ALTER TABLE app.secret_tag ENABLE ROW LEVEL SECURITY;

CREATE POLICY own_tags ON app.secret_tag FOR ALL TO vault_app
    USING (EXISTS (SELECT 1 FROM app.secret_record r
                   WHERE r.id = secret_tag.record_id))
    WITH CHECK (EXISTS (SELECT 1 FROM app.secret_record r
                        WHERE r.id = secret_tag.record_id));
-- Вложенный запрос сам подчиняется политике own_secrets, поэтому теги
-- видны только вместе со своими записями.

ALTER TABLE app.public_note ENABLE ROW LEVEL SECURITY;

CREATE POLICY note_owner_rw ON app.public_note FOR ALL TO vault_app
    USING      (owner_id = nullif(current_setting('app.actor_id', true), '')::bigint)
    WITH CHECK (owner_id = nullif(current_setting('app.actor_id', true), '')::bigint);

-- Неконфиденциальные записи с visibility='public' доступны на чтение всем,
-- включая гостя - ровно та же логика, что в политике guest_public_rows
-- лабораторной работы №1.
CREATE POLICY note_public_read ON app.public_note FOR SELECT TO vault_app
    USING (visibility = 'public');

-- Администратор системы: полный доступ к неконфиденциальной подсистеме.
CREATE POLICY note_admin ON app.public_note FOR ALL TO vault_app
    USING      (current_setting('app.is_admin', true) = 'on')
    WITH CHECK (current_setting('app.is_admin', true) = 'on');
