import os
import hashlib
import hmac
from typing import Tuple

PBKDF2_ITERATIONS = 200_000
SALT_LEN = 16  # bytes
DK_LEN = 32    # bytes (256 bits)

NONCE_LEN = 16  # bytes (128 bits)


def make_salt() -> bytes:
    return os.urandom(SALT_LEN)


def pbkdf2_hash_password(password: str, salt: bytes, iterations: int = PBKDF2_ITERATIONS) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=DK_LEN
    )


def hash_for_storage(password: str) -> Tuple[str, str, int]:
    salt = make_salt()
    dk = pbkdf2_hash_password(password, salt, PBKDF2_ITERATIONS)
    return salt.hex(), dk.hex(), PBKDF2_ITERATIONS


def verify_password(password: str, salt_hex: str, hash_hex: str, iterations: int) -> bool:
    salt = bytes.fromhex(salt_hex)
    expected = bytes.fromhex(hash_hex)
    computed = pbkdf2_hash_password(password, salt, iterations)
    return hmac.compare_digest(computed, expected)


def make_nonce_hex() -> str:
    return os.urandom(NONCE_LEN).hex()


def make_session_id() -> str:
    # 128-bit aleatorio
    return os.urandom(16).hex()


def make_session_key_hex() -> str:
    # 256-bit aleatorio
    return os.urandom(32).hex()


def hmac_sha256_hex(key_hex: str, message: str) -> str:
    key = bytes.fromhex(key_hex)
    mac = hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()
    return mac


def secure_eq_hex(a: str, b: str) -> bool:
    return hmac.compare_digest(a.lower(), b.lower())
