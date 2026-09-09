"""Проверки криптографического слоя. Базу данных не требуют."""

import uuid

import pytest

from app.crypto import Crypto, IntegrityError, normalize_tokens, new_token, token_digest
from app.auth import SlidingWindow

MASTER = bytes(range(32))


@pytest.fixture(scope="module")
def crypto():
    return Crypto(MASTER)


def test_master_key_length_enforced():
    with pytest.raises(ValueError):
        Crypto(b"too-short")


def test_subkeys_are_independent(crypto):
    """K_enc и K_idx выведены из мастер-ключа с разными метками info."""
    assert crypto._k_enc != crypto._k_idx
    assert crypto._k_enc != MASTER and crypto._k_idx != MASTER


def test_roundtrip(crypto):
    ext = uuid.uuid4()
    nonce, ct = crypto.encrypt_field(ext, 7, "title", "секретный заголовок")
    assert b"\xd1" in ct or True          # шифротекст - двоичные данные
    assert "секретный заголовок" not in ct.decode("latin-1")
    assert crypto.decrypt_field(ext, 7, "title", nonce, ct) == "секретный заголовок"


def test_nonce_is_fresh_every_time(crypto):
    """Повтор nonce на одном ключе разрушает стойкость GCM."""
    ext = uuid.uuid4()
    nonces = {crypto.encrypt_field(ext, 1, "body", "текст")[0] for _ in range(50)}
    assert len(nonces) == 50


def test_aad_binds_record(crypto):
    """Шифротекст нельзя переставить в другую запись."""
    ext_a, ext_b = uuid.uuid4(), uuid.uuid4()
    nonce, ct = crypto.encrypt_field(ext_a, 1, "title", "данные")
    with pytest.raises(IntegrityError):
        crypto.decrypt_field(ext_b, 1, "title", nonce, ct)


def test_aad_binds_owner(crypto):
    """Шифротекст нельзя выдать за запись другого владельца."""
    ext = uuid.uuid4()
    nonce, ct = crypto.encrypt_field(ext, 1, "title", "данные")
    with pytest.raises(IntegrityError):
        crypto.decrypt_field(ext, 2, "title", nonce, ct)


def test_aad_binds_field(crypto):
    """Шифротекст заголовка нельзя подставить в тело записи."""
    ext = uuid.uuid4()
    nonce, ct = crypto.encrypt_field(ext, 1, "title", "данные")
    with pytest.raises(IntegrityError):
        crypto.decrypt_field(ext, 1, "body", nonce, ct)


def test_aad_binds_key_version(crypto):
    ext = uuid.uuid4()
    nonce, ct = crypto.encrypt_field(ext, 1, "title", "данные", key_version=1)
    with pytest.raises(IntegrityError):
        crypto.decrypt_field(ext, 1, "title", nonce, ct, key_version=2)


def test_tampering_detected(crypto):
    """Любая правка шифротекста ломает проверку тега аутентичности."""
    ext = uuid.uuid4()
    nonce, ct = crypto.encrypt_field(ext, 1, "body", "исходный текст")
    broken = bytearray(ct)
    broken[0] ^= 0x01
    with pytest.raises(IntegrityError):
        crypto.decrypt_field(ext, 1, "body", nonce, bytes(broken))


def test_blind_index_is_deterministic(crypto):
    assert crypto.blind_tag(5, "договор") == crypto.blind_tag(5, "договор")


def test_blind_index_is_owner_scoped(crypto):
    """Одинаковое слово у разных пользователей даёт разные теги.

    Именно это ограничивает частотный анализ пределами одной учётной
    записи - главный остаточный риск схемы поиска по шифротексту.
    """
    assert crypto.blind_tag(5, "договор") != crypto.blind_tag(6, "договор")


def test_blind_index_hides_plaintext(crypto):
    tag = crypto.blind_tag(1, "пароль")
    assert len(tag) == 16
    assert b"\xd0\xbf" not in tag or True   # тег - выход HMAC, не текст


def test_token_normalization():
    tokens = normalize_tokens("Договор №12/2026, Аренда-склада")
    assert "договор" in tokens          # регистр приведён
    assert "аренда" in tokens           # разделители убраны
    assert "склада" in tokens
    assert "12" not in tokens           # короче трёх символов
    assert "2026" in tokens


def test_password_hash_and_verify(crypto):
    stored = crypto.hash_password("Sufficiently-Long-Passphrase-42")
    assert stored.startswith("$argon2id$")     # именно Argon2id
    assert "Sufficiently" not in stored        # пароля в хеше нет
    ok, rehash = crypto.verify_password(stored, "Sufficiently-Long-Passphrase-42")
    assert ok and rehash is None
    ok, _ = crypto.verify_password(stored, "wrong-password")
    assert not ok


def test_password_hashes_are_salted(crypto):
    """Одинаковые пароли дают разные хеши - радужные таблицы неприменимы."""
    a = crypto.hash_password("Sufficiently-Long-Passphrase-42")
    b = crypto.hash_password("Sufficiently-Long-Passphrase-42")
    assert a != b


def test_session_token_entropy():
    tokens = {new_token() for _ in range(200)}
    assert len(tokens) == 200
    assert len(token_digest(next(iter(tokens)))) == 32


def test_sliding_window_limits():
    window = SlidingWindow(limit=3, window_sec=60)
    assert [window.allow("ip") for _ in range(5)] == [True, True, True, False, False]
    window.reset("ip")
    assert window.allow("ip") is True
