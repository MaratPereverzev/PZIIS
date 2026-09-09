"""Криптографический слой.

Три независимые задачи и три разных примитива:
  - пароли             -> Argon2id (память-затратная функция);
  - конфиденциальные
    данные             -> AES-256-GCM (AEAD: шифрование + целостность);
  - поиск по
    шифротексту        -> HMAC-SHA256 (слепой индекс).

Подключи для шифрования и для индексации выводятся из общего мастер-ключа
через HKDF с разными метками info. Один и тот же ключ для двух задач
использовать нельзя: компрометация индексации не должна влечь
компрометацию шифрования.
"""

import hashlib
import hmac
import secrets
import unicodedata
import uuid

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerifyMismatchError, VerificationError
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

AAD_PREFIX = b"pziis-vault/v1"
NONCE_LEN = 12          # штатный размер nonce для GCM
TAG_LEN = 16            # длина усечённого тега слепого индекса
MIN_INDEX_TOKEN = 3     # токены короче не индексируются
KEY_VERSION = 1         # версия ключа для новых записей (задел под ротацию)

# Параметры Argon2id. 64 МиБ памяти обесценивают перебор на GPU и ASIC.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 65536
ARGON2_PARALLELISM = 4


class IntegrityError(Exception):
    """Тег аутентичности AES-GCM не сошёлся: запись повреждена или подменена."""


def normalize_tokens(text):
    """Нормализация текста в набор токенов для слепого индекса.

    NFKC + приведение регистра убирают тривиальные различия написания,
    иначе поиск не находил бы записи, сохранённые в другом регистре.
    """
    normalized = unicodedata.normalize("NFKC", text or "").casefold()
    cleaned = "".join(ch if ch.isalnum() else " " for ch in normalized)
    return {t for t in cleaned.split() if len(t) >= MIN_INDEX_TOKEN}


class Crypto:
    def __init__(self, master_key):
        if len(master_key) != 32:
            raise ValueError("мастер-ключ должен быть длиной 32 байта")
        self._k_enc = self._derive(master_key, b"pziis-vault/v1/aes-gcm")
        self._k_idx = self._derive(master_key, b"pziis-vault/v1/blind-index")
        self._aead = AESGCM(self._k_enc)
        self._hasher = PasswordHasher(
            time_cost=ARGON2_TIME_COST,
            memory_cost=ARGON2_MEMORY_KIB,
            parallelism=ARGON2_PARALLELISM,
            hash_len=32,
            salt_len=16,
        )
        # Фиктивный хеш: проверяется, когда логин не найден, чтобы время
        # ответа не выдавало существование учётной записи (CWE-204).
        self._dummy_hash = self._hasher.hash("nonexistent-account-placeholder")

    @staticmethod
    def _derive(master_key, info):
        return HKDF(algorithm=hashes.SHA256(), length=32,
                    salt=None, info=info).derive(master_key)

    # -- пароли -------------------------------------------------------------

    def hash_password(self, password):
        return self._hasher.hash(password)

    def verify_password(self, stored_hash, password):
        """Возвращает (успех, новый_хеш_или_None).

        Второй элемент не None, когда параметры стоимости в базе устарели -
        пароль перехешируется при успешном входе.
        """
        try:
            self._hasher.verify(stored_hash, password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False, None
        if self._hasher.check_needs_rehash(stored_hash):
            return True, self._hasher.hash(password)
        return True, None

    def burn_password_time(self):
        """Проверка по фиктивному хешу для выравнивания времени ответа."""
        self.verify_password(self._dummy_hash, "wrong-password")

    # -- шифрование конфиденциальных полей ----------------------------------

    @staticmethod
    def _aad(ext_id, owner_id, key_version, field):
        """Связанные данные привязывают шифротекст к записи, владельцу,
        версии ключа и имени поля. Перестановка шифротекста между записями
        или подмена владельца ломают проверку тега."""
        return b"|".join([
            AAD_PREFIX,
            ext_id.bytes,
            int(owner_id).to_bytes(8, "big"),
            int(key_version).to_bytes(2, "big"),
            field.encode("utf-8"),
        ])

    def encrypt_field(self, ext_id, owner_id, field, plaintext,
                      key_version=KEY_VERSION):
        # Новый nonce на каждую операцию шифрования. Повтор nonce на одном
        # ключе полностью разрушает стойкость GCM, поэтому при
        # редактировании запись перешифровывается, а не «доправляется».
        nonce = secrets.token_bytes(NONCE_LEN)
        aad = self._aad(ext_id, owner_id, key_version, field)
        ct = self._aead.encrypt(nonce, plaintext.encode("utf-8"), aad)
        return nonce, ct

    def decrypt_field(self, ext_id, owner_id, field, nonce, ciphertext,
                      key_version=KEY_VERSION):
        aad = self._aad(ext_id, owner_id, key_version, field)
        try:
            plain = self._aead.decrypt(bytes(nonce), bytes(ciphertext), aad)
        except InvalidTag as exc:
            raise IntegrityError(
                "нарушена целостность конфиденциальной записи") from exc
        return plain.decode("utf-8")

    # -- слепой индекс ------------------------------------------------------

    def blind_tag(self, owner_id, token):
        """HMAC-SHA256(K_idx, owner_id || token), усечённый до 16 байт.

        Владелец входит в вычисление: одинаковые слова у разных
        пользователей дают разные теги, поэтому частотный анализ ограничен
        одной учётной записью. Усечение до 16 байт даёт редкие коллизии -
        ложные совпадения отбрасываются после расшифровки, а статистика
        дополнительно размывается.
        """
        message = int(owner_id).to_bytes(8, "big") + b"|" + token.encode("utf-8")
        return hmac.new(self._k_idx, message, hashlib.sha256).digest()[:TAG_LEN]

    def blind_tags(self, owner_id, text):
        return [self.blind_tag(owner_id, t) for t in normalize_tokens(text)]


# -- токены сессий ----------------------------------------------------------

def new_token():
    """256 бит энтропии от криптографического генератора ОС."""
    return secrets.token_urlsafe(32)


def token_digest(token):
    """В базе хранится только этот хеш, но не сам токен."""
    return hashlib.sha256(token.encode("utf-8")).digest()


def new_ext_id():
    return uuid.uuid4()
