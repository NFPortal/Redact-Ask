"""[12] Sessions: encrypted placeholder mappings and cloud conversation IDs (SPEC: session_store.py)."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from datetime import timedelta
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken

from .models import Mapping, Session, StorageError, now


class SessionStore:
    def __init__(self, sessions_dir: Path, workdirs_dir: Path, key: bytes, expiry_days: int):
        self.dir = sessions_dir
        self.workdirs = workdirs_dir
        self.fernet = Fernet(key)
        self.expiry = timedelta(days=expiry_days)
        self.dir.mkdir(parents=True, exist_ok=True)
        self.workdirs.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def wipe(sessions_dir: Path, workdirs_dir: Path) -> int:
        """Delete every session file and working folder without needing the key
        (used when the passphrase is reset). Returns how many sessions were deleted."""
        n = len(list(sessions_dir.glob("*.session"))) if sessions_dir.exists() else 0
        shutil.rmtree(sessions_dir, ignore_errors=True)
        shutil.rmtree(workdirs_dir, ignore_errors=True)
        return n

    # -- naming -------------------------------------------------------------
    @staticmethod
    def session_name(name: str | None, cwd: str | None = None) -> str:
        if name:
            return name
        return "folder:" + str(Path(cwd or os.getcwd()).resolve())

    @staticmethod
    def session_id(name: str) -> str:
        key = name.casefold() if name.startswith("folder:") and os.name == "nt" else name
        return hashlib.sha256(key.encode("utf-8")).hexdigest()

    def _path(self, sid: str) -> Path:
        return self.dir / f"{sid}.session"

    def workdir(self, sid: str) -> Path:
        """Stable, empty working folder for the cloud CLI (one per session, so follow-ups can resume)."""
        return self.workdirs / sid[:32]

    # -- load / save --------------------------------------------------------
    def load(self, name: str) -> Session:
        sid = self.session_id(name)
        path = self._path(sid)
        if not path.exists():
            t = now()
            return Session(id=sid, name=name, mapping=Mapping(), conversations={}, created=t, last_used=t)
        try:
            data = json.loads(self.fernet.decrypt(path.read_bytes()).decode("utf-8"))
        except InvalidToken as e:
            raise StorageError(f"Session '{name}' can't be decrypted (the encryption key changed?). "
                               f"Remove it with: python redact_ask.py sessions clear \"{name}\"") from e
        except (OSError, ValueError) as e:
            raise StorageError(f"Session file for '{name}' is unreadable: {e}") from e
        return Session.from_dict(data)

    def save(self, session: Session) -> None:
        session.last_used = now()
        blob = self.fernet.encrypt(json.dumps(session.to_dict()).encode("utf-8"))
        fd, tmp = tempfile.mkstemp(dir=self.dir, prefix=".tmp-", suffix=".session")
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(blob)
            os.replace(tmp, self._path(session.id))
        except OSError as e:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise StorageError(f"Couldn't save session: {e}") from e

    def migrate(self, old_key: bytes) -> int:
        """Re-encrypt session files written with an older key under the current key."""
        old = Fernet(old_key)
        moved = 0
        for p in sorted(self.dir.glob("*.session")):
            blob = p.read_bytes()
            try:
                self.fernet.decrypt(blob)
                continue                      # already uses the current key
            except InvalidToken:
                pass
            try:
                plain = old.decrypt(blob)
            except InvalidToken:
                continue                      # neither key works; left for 'sessions clear'
            tmp = p.with_suffix(".tmp")
            tmp.write_bytes(self.fernet.encrypt(plain))
            os.replace(tmp, p)
            moved += 1
        return moved

    def reset(self, session: Session) -> Session:
        """--new-session: forget mapping and conversations."""
        self._delete(session.id)
        t = now()
        return Session(id=session.id, name=session.name, mapping=Mapping(), conversations={}, created=t, last_used=t)

    # -- housekeeping -------------------------------------------------------
    def _all(self) -> list[tuple[Path, Session | None]]:
        out = []
        for p in sorted(self.dir.glob("*.session")):
            try:
                out.append((p, Session.from_dict(json.loads(self.fernet.decrypt(p.read_bytes())))))
            except (InvalidToken, OSError, ValueError, KeyError):
                out.append((p, None))
        return out

    def _delete(self, sid: str) -> None:
        try:
            self._path(sid).unlink()
        except FileNotFoundError:
            pass
        shutil.rmtree(self.workdir(sid), ignore_errors=True)

    def expire(self) -> int:
        cutoff = now() - self.expiry
        removed = 0
        for p, s in self._all():
            if s is not None and s.last_used < cutoff:
                self._delete(s.id)
                removed += 1
        return removed

    def list(self) -> list[dict]:
        rows = []
        for p, s in self._all():
            if s is None:
                rows.append({"name": f"(unreadable: {p.stem[:12]}…)", "last_used": "?", "counts": {}})
                continue
            counts: dict[str, int] = dict(sorted(s.mapping.counters.items()))
            rows.append({"name": s.name, "last_used": s.last_used.astimezone().strftime("%Y-%m-%d %H:%M"),
                         "counts": counts, "targets": sorted(s.conversations)})
        return rows

    def clear(self, name: str | None = None, all_: bool = False) -> int:
        if all_:
            n = 0
            for p, s in self._all():
                p.unlink(missing_ok=True)
                n += 1
            shutil.rmtree(self.workdirs, ignore_errors=True)
            self.workdirs.mkdir(parents=True, exist_ok=True)
            return n
        if name is None:
            raise StorageError("Give a session name or --all.")
        sid = self.session_id(name)
        existed = self._path(sid).exists()
        self._delete(sid)
        return 1 if existed else 0
