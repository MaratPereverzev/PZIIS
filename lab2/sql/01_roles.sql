-- Роли уровня кластера.
--
-- Первый блок воспроизводит ролевую модель лабораторной работы №1
-- (администратор / пользователь / гость) - приложение 2.1 работает на той
-- же модели, поэтому её достаточно один раз настроить и переиспользовать.
-- Второй блок добавляет сервисную роль самого приложения.

\set ON_ERROR_STOP on

-- Пароли не зашиты в скрипт: приходят из переменных окружения контейнера.
\getenv vault_pw VAULT_DB_PASSWORD
\getenv admin_pw LAB1_ADMIN_PASSWORD
\getenv user_pw  LAB1_USER_PASSWORD
\getenv guest_pw LAB1_GUEST_PASSWORD

-- ---------------------------------------------------------------------------
-- Ролевая модель лабораторной работы №1
-- ---------------------------------------------------------------------------
CREATE ROLE admin_role NOLOGIN;
CREATE ROLE user_role  NOLOGIN;
CREATE ROLE guest_role NOLOGIN;

CREATE ROLE admin_sys  LOGIN PASSWORD :'admin_pw';
CREATE ROLE user_sub   LOGIN PASSWORD :'user_pw';
CREATE ROLE guest_read LOGIN PASSWORD :'guest_pw';

GRANT admin_role TO admin_sys;
GRANT user_role  TO user_sub;
GRANT guest_role TO guest_read;

-- Атрибуты роли не наследуются через членство, поэтому максимальные
-- полномочия выдаются учётной записи администратора напрямую.
ALTER ROLE admin_sys CREATEDB CREATEROLE BYPASSRLS;
GRANT pg_read_all_data, pg_write_all_data TO admin_role;

-- ---------------------------------------------------------------------------
-- Сервисная роль приложения: минимум полномочий
-- ---------------------------------------------------------------------------
-- NOBYPASSRLS - обязательно: иначе построчная защита превратится
-- в декорацию. NOINHERIT - привилегии выдаются роли напрямую, членство
-- в других ролях не используется.
CREATE ROLE vault_app LOGIN PASSWORD :'vault_pw'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS NOINHERIT NOREPLICATION;

-- Без явного отзыва привилегия CONNECT досталась бы псевдороли PUBLIC,
-- то есть вообще всем учётным записям кластера.
REVOKE ALL ON DATABASE app_db FROM PUBLIC;
GRANT CONNECT ON DATABASE app_db TO vault_app, admin_role, user_role, guest_role;

-- Служебная база postgres по умолчанию доступна PUBLIC. Через неё
-- сервисная роль видела бы каталоги всего кластера.
REVOKE CONNECT ON DATABASE postgres FROM PUBLIC;
