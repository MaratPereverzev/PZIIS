"""Конфигурация приложения.

Все секреты приходят только из окружения (в эксплуатации - из файла
/etc/pziis-vault/keys.env с правами 0640 root:pziis). В коде и в репозитории
секретов нет: зашитые учётные данные - это CWE-798.
"""

import base64
import os
import sys


def _env(name, default=None, required=False):
    value = os.environ.get(name, default)
    if required and not value:
        sys.exit("Ошибка конфигурации: не задана переменная окружения %s" % name)
    return value


def _decode_key(raw):
    """Мастер-ключ принимается в base64 или в hex, ровно 32 байта."""
    for decoder in (base64.b64decode, bytes.fromhex):
        try:
            key = decoder(raw)
        except Exception:
            continue
        if len(key) == 32:
            return key
    sys.exit("Ошибка конфигурации: VAULT_MASTER_KEY должен быть 32 байта "
             "в base64 или hex (сгенерировать: openssl rand -base64 32)")


class Settings:
    def __init__(self):
        self.dsn = _env("VAULT_DSN", required=True)
        self.master_key = _decode_key(_env("VAULT_MASTER_KEY", required=True))

        # Срок жизни сессии: по неактивности и абсолютный.
        self.session_idle_minutes = int(_env("VAULT_SESSION_IDLE_MIN", "30"))
        self.session_hard_hours = int(_env("VAULT_SESSION_HARD_H", "12"))

        # Противодействие перебору на уровне приложения. Основной лимит
        # стоит выше, на nginx: Argon2 с памятью 64 МиБ сам является
        # ресурсом, и до него поток запросов доходить не должен.
        self.login_ip_limit = int(_env("VAULT_LOGIN_IP_LIMIT", "5"))
        self.login_ip_window_sec = int(_env("VAULT_LOGIN_IP_WINDOW", "60"))
        self.lockout_threshold = int(_env("VAULT_LOCKOUT_THRESHOLD", "10"))
        self.lockout_minutes = int(_env("VAULT_LOCKOUT_MINUTES", "15"))
        self.failed_login_delay_ms = int(_env("VAULT_FAILED_DELAY_MS", "200"))

        # Флаг Secure на cookie. Выключается только для локального прогона
        # без TLS; в докер-композиции с nginx остаётся включённым.
        self.cookie_secure = _env("VAULT_COOKIE_SECURE", "1") == "1"

        # Учётная запись администратора создаётся при первом запуске,
        # если в системе нет ни одного администратора.
        self.bootstrap_admin_login = _env("VAULT_ADMIN_LOGIN", "admin_sys")
        self.bootstrap_admin_password = _env("VAULT_ADMIN_PASSWORD")

        self.min_password_len = int(_env("VAULT_MIN_PASSWORD_LEN", "12"))


settings = Settings()
