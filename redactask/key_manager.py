"""[11] The encryption key for session files (SPEC: key_manager.py).

The key is derived from a passphrase the user types at every run (scrypt) and is never
stored anywhere. Only a random salt and a check value (to recognise a wrong passphrase) are
kept in the config folder. Without the passphrase, nothing running as the user can decrypt
the session files. The passphrase is read from the terminal itself, never from stdin, an
argument or an environment variable. Never prints or logs the key or the passphrase.

Older versions kept a random key in the OS keyring (or a key file); `legacy_key()` and
`delete_legacy()` exist only to migrate those sessions once.
"""
from __future__ import annotations

import base64
import os
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .models import StorageError

SALT_FILE = "key.salt"
CHECK_FILE = "key.check"
CHECK_PLAINTEXT = b"redact-ask passphrase check"
MIN_LENGTH = 8
MAX_TRIES = 3

LEGACY_SERVICE = "redact-ask"
LEGACY_ACCOUNT = "session-encryption-key"
LEGACY_FILE = "key"

_cache: dict[str, bytes] = {}


# ---------------------------------------------------------------------------
# Reading the passphrase from the terminal
# ---------------------------------------------------------------------------
def _prompt(message: str) -> str:
    """Read a passphrase from the console without echo. Never falls back to stdin, so piped
    input (the text to analyze) is never consumed and a script can't supply the passphrase."""
    import getpass
    if sys.platform == "win32":
        try:
            import msvcrt  # noqa: F401  (getpass uses the console via msvcrt)
        except ImportError as e:
            raise StorageError("No console available to ask for the passphrase.") from e
        return getpass.win_getpass(message, stream=sys.stderr)
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
        os.close(fd)
    except OSError as e:
        raise StorageError("No terminal available to ask for the passphrase; run redact-ask from a terminal.") from e
    return getpass.unix_getpass(message, stream=sys.stderr)


def reset(config_dir: Path) -> bytes:
    """Forget the passphrase (delete salt and check value) and create a new one.
    The caller deletes the sessions, which can't be read without the old passphrase."""
    (config_dir / SALT_FILE).unlink(missing_ok=True)
    (config_dir / CHECK_FILE).unlink(missing_ok=True)
    _cache.pop(str(config_dir), None)
    key = _create(config_dir)
    _cache[str(config_dir)] = key
    return key


def _derive(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1)
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))


def is_set_up(config_dir: Path) -> bool:
    return (config_dir / SALT_FILE).exists() and (config_dir / CHECK_FILE).exists()


def _create(config_dir: Path) -> bytes:
    print("redact-ask: create a passphrase to encrypt your session mappings. It is never stored;\n"
          "you'll type it each time. If you forget it, the saved sessions can't be recovered.",
          file=sys.stderr)
    for _ in range(MAX_TRIES):
        first = _prompt("New passphrase: ")
        if len(first) < MIN_LENGTH:
            print(f"redact-ask: use at least {MIN_LENGTH} characters.", file=sys.stderr)
            continue
        if _prompt("Repeat passphrase: ") != first:
            print("redact-ask: the two entries didn't match.", file=sys.stderr)
            continue
        salt = os.urandom(16)
        key = _derive(first, salt)
        config_dir.mkdir(parents=True, exist_ok=True)
        (config_dir / SALT_FILE).write_bytes(base64.b64encode(salt))
        (config_dir / CHECK_FILE).write_bytes(Fernet(key).encrypt(CHECK_PLAINTEXT))
        return key
    raise StorageError("No passphrase was set.")


def _unlock(config_dir: Path) -> bytes:
    salt = base64.b64decode((config_dir / SALT_FILE).read_bytes())
    check = (config_dir / CHECK_FILE).read_bytes()
    for attempt in range(MAX_TRIES):
        key = _derive(_prompt("redact-ask passphrase: "), salt)
        try:
            if Fernet(key).decrypt(check) == CHECK_PLAINTEXT:
                return key
        except InvalidToken:
            pass
        if attempt < MAX_TRIES - 1:
            print("redact-ask: wrong passphrase, try again.", file=sys.stderr)
    raise StorageError("Wrong passphrase.")


def get_key(config_dir: Path) -> tuple[bytes, bool]:
    """(key, newly_created). Prompts at most once per process."""
    cached = _cache.get(str(config_dir))
    if cached:
        return cached, False
    created = not is_set_up(config_dir)
    key = _create(config_dir) if created else _unlock(config_dir)
    _cache[str(config_dir)] = key
    return key, created


# ---------------------------------------------------------------------------
# One-time migration from the old keyring / key-file storage
# ---------------------------------------------------------------------------
def legacy_key(config_dir: Path) -> bytes | None:
    """The key an older version stored, if any (never creates one)."""
    path = config_dir / LEGACY_FILE
    if path.exists():
        return path.read_bytes().strip()
    try:
        import keyring
        value = keyring.get_password(LEGACY_SERVICE, LEGACY_ACCOUNT)
    except Exception:
        return None
    return value.encode("ascii") if value else None


def delete_legacy(config_dir: Path) -> None:
    """Remove the stored key so nothing can decrypt old copies without the passphrase."""
    (config_dir / LEGACY_FILE).unlink(missing_ok=True)
    try:
        import keyring
        keyring.delete_password(LEGACY_SERVICE, LEGACY_ACCOUNT)
    except Exception:
        pass
