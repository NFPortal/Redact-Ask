"""[17] Show the restored answer on stdout, and in --out FILE if requested (SPEC: output_writer.py)."""
from __future__ import annotations

import sys
from pathlib import Path

from .models import InputError


def write(answer: str, out_path: str | None = None, stream=None) -> None:
    stream = stream or sys.stdout
    text = answer if answer.endswith("\n") else answer + "\n"
    try:
        stream.write(text)
        stream.flush()
    except UnicodeEncodeError:
        # Old Windows consoles: write UTF-8 bytes directly.
        stream.buffer.write(text.encode("utf-8"))
        stream.flush()
    if out_path:
        p = Path(out_path)
        if p.exists():
            print(f"redact-ask: overwriting {p}", file=sys.stderr)
        try:
            p.write_text(text, encoding="utf-8")
        except OSError as e:
            raise InputError(f"Couldn't write {p}: {e}") from e
