"""[11] The encryption key for session files (SPEC: key_manager.py).

Stored in the OS credential store via `keyring` (Windows Credential Manager, Debian Secret
Service). On a headless Debian box with no keyring backend, falls back to a key file with
mode 600. Never prints or logs the key.
"""
from __future__ import annotations

import os
import stat
import sys
from pathlib import Path

from cryptography.fernet import Fernet

from .models import StorageError

SERVICE = "redact-ask"
ACCOUNT = "session-encryption-key"
_warned = False


def _keyring_backend():
    """The usable keyring backend, or None when there is none (headless Linux)."""
    try:
        import keyring
        from keyring.backends import fail, null
    except ImportError:
        return None
    kr = keyring.get_keyring()
    if isinstance(kr, (fail.Keyring, null.Keyring)):
        return None
    # chainer with no usable backends also counts as none
    try:
        from keyring.backends.chainer import ChainerBackend
        if isinstance(kr, ChainerBackend) and not kr.backends:
            return None
    except ImportError:
        pass
    return kr


def _from_keyring(kr) -> bytes:
    from keyring.errors import KeyringError, KeyringLocked
    try:
        key = kr.get_password(SERVICE, ACCOUNT)
        if key is None:
            key = Fernet.generate_key().decode("ascii")
            kr.set_password(SERVICE, ACCOUNT, key)
        return key.encode("ascii")
    except KeyringLocked as e:
        raise StorageError("The system keyring is locked. Unlock it (log in to the desktop session or "
                           "unlock GNOME Keyring/KWallet) and try again.") from e
    except KeyringError as e:
        raise StorageError(f"Couldn't use the system keyring: {e}") from e


def _from_file(path: Path) -> bytes:
    global _warned
    if not _warned:
        print(f"redact-ask: no system keyring found; using the key file {path} (weaker protection).",
              file=sys.stderr)
        _warned = True
    if path.exists():
        if sys.platform != "win32":
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                raise StorageError(f"Key file {path} has permissions {oct(mode)}; it must be 600 "
                                   f"(chmod 600 '{path}').")
        return path.read_bytes().strip()
    path.parent.mkdir(parents=True, exist_ok=True)
    key = Fernet.generate_key()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(key)
    return key


def get_key(config_dir: Path) -> bytes:
    if os.environ.get("REDACT_ASK_KEY_FILE_ONLY") == "1":   # tests: never touch the real keyring
        return _from_file(config_dir / "key")
    kr = _keyring_backend()
    if kr is None:
        return _from_file(config_dir / "key")
    return _from_keyring(kr)
