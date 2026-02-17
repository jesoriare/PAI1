import json
from pathlib import Path
from typing import Dict, Any

from crypto_utils import hash_for_storage, verify_password

DATA_DIR = Path(__file__).resolve().parents[1] / "data"
USERS_FILE = DATA_DIR / "users.json"


def load_users() -> Dict[str, Any]:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    if not USERS_FILE.exists():
        return {}
    return json.loads(USERS_FILE.read_text(encoding="utf-8"))


def save_users(users: Dict[str, Any]) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    USERS_FILE.write_text(json.dumps(users, ensure_ascii=False, indent=2), encoding="utf-8")


def migrate_plaintext_users(users: Dict[str, Any]) -> Dict[str, Any]:
    """
    Migración automática: si existe users[username]["password"] en claro, lo convierte
    a salt/hash/iterations y elimina el campo password.
    """
    changed = False
    for username, info in users.items():
        if isinstance(info, dict) and "password" in info:
            salt_hex, hash_hex, iters = hash_for_storage(info["password"])
            users[username] = {
                "salt": salt_hex,
                "hash": hash_hex,
                "iterations": iters
            }
            changed = True
    if changed:
        save_users(users)
    return users


def add_user(username: str, password: str) -> None:
    users = load_users()
    users = migrate_plaintext_users(users)

    if username in users:
        raise ValueError("USER_ALREADY_EXISTS")

    salt_hex, hash_hex, iters = hash_for_storage(password)
    users[username] = {"salt": salt_hex, "hash": hash_hex, "iterations": iters}
    save_users(users)


def verify_user(username: str, password: str) -> bool:
    users = load_users()
    users = migrate_plaintext_users(users)

    if username not in users:
        return False

    info = users[username]
    try:
        return verify_password(password, info["salt"], info["hash"], int(info["iterations"]))
    except Exception:
        return False
