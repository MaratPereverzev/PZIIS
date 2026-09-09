"""Политика пароля.

Ставка на длину, а не на «обязательный спецсимвол»: так рекомендует
NIST SP 800-63B, и так политика реально сопротивляется словарной атаке,
а не заставляет пользователя писать пароль на стикере.

Список скомпрометированных паролей подключается файлом
app/data/weak-passwords.txt (по одному в строке) - туда кладётся, например,
список top-10000 из утечек. Встроенного минимума достаточно для
демонстрации, но он сознательно не выдаётся за полноценный список.
"""

import os
import unicodedata

from app.config import settings

_BUILTIN_WEAK = {
    "password", "password1", "password123", "passw0rd", "qwerty",
    "qwerty123", "qwertyuiop", "123456", "1234567", "12345678",
    "123456789", "1234567890", "111111", "000000", "iloveyou",
    "admin", "administrator", "root", "toor", "letmein", "welcome",
    "monkey", "dragon", "sunshine", "princess", "football", "baseball",
    "master", "superman", "trustno1", "changeme", "secret", "abc123",
    "qazwsxedc", "zaq12wsx", "пароль", "йцукен", "йцукенгш",
}

_WEAK_FILE = os.path.join(os.path.dirname(__file__), "data",
                          "weak-passwords.txt")


def _load_weak():
    weak = set(_BUILTIN_WEAK)
    try:
        with open(_WEAK_FILE, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip().casefold()
                if line:
                    weak.add(line)
    except OSError:
        pass
    return weak


_WEAK = _load_weak()


def validate(password, login=None):
    """Возвращает None, если пароль допустим, иначе текст причины отказа."""
    if password is None:
        return "Пароль не задан."
    normalized = unicodedata.normalize("NFKC", password)
    if len(normalized) < settings.min_password_len:
        return ("Пароль короче %d символов." % settings.min_password_len)
    if len(normalized) > 256:
        # Верхняя граница нужна не для стойкости, а против отказа
        # в обслуживании: Argon2 считает хеш от входа любой длины.
        return "Пароль длиннее 256 символов."
    folded = normalized.casefold()
    if folded in _WEAK:
        return "Пароль входит в список скомпрометированных."
    if login and folded == login.strip().casefold():
        return "Пароль совпадает с логином."
    if len(set(folded)) < 5:
        return "В пароле слишком мало различных символов."
    return None


def weak_list_size():
    return len(_WEAK)
