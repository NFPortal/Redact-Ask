"""[14] Record exactly what left the machine (SPEC: audit_log.py).

Only ever receives redacted text; never the mapping or real values. Two JSON lines per run
(status "sending", then "done"/"error") with the same run_id.
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from .models import now

FILE_NAME = "audit.jsonl"


class AuditLog:
    def __init__(self, audit_dir: Path, retention_days: int):
        self.path = audit_dir / FILE_NAME
        self.retention = timedelta(days=retention_days)
        audit_dir.mkdir(parents=True, exist_ok=True)

    def _append(self, entry: dict) -> None:
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def start(self, redacted_text: str, target: str, model: str | None, session_id: str,
              counts: dict[str, int], retries: int, source: str) -> str:
        run_id = uuid.uuid4().hex
        self._append({
            "run_id": run_id, "time": now().isoformat(), "status": "sending", "target": target,
            "model": model, "session": session_id[:16], "source": source, "counts": counts,
            "scan_retries": retries, "sent_text": redacted_text,
        })
        return run_id

    def finish(self, run_id: str, status: str, redacted_answer: str | None = None, error: str | None = None) -> None:
        entry = {"run_id": run_id, "time": now().isoformat(), "status": status}
        if redacted_answer is not None:
            entry["answer"] = redacted_answer
        if error:
            entry["error"] = error
        self._append(entry)

    def expire(self) -> int:
        """Drop entries older than the retention period (same rule as sessions)."""
        if not self.path.exists():
            return 0
        cutoff = now() - self.retention
        kept, dropped = [], 0
        for line in self.path.read_text(encoding="utf-8").splitlines():
            try:
                t = datetime.fromisoformat(json.loads(line)["time"])
            except (ValueError, KeyError, TypeError):
                kept.append(line)
                continue
            if t < cutoff:
                dropped += 1
            else:
                kept.append(line)
        if dropped:
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text("".join(l + "\n" for l in kept), encoding="utf-8")
            tmp.replace(self.path)
        return dropped
