"""[17] Show the answer on stdout (and in --out FILE), show previews, and ask for confirmations
(SPEC: output_writer.py)."""
from __future__ import annotations

import sys
from pathlib import Path

from .models import InputError, UsageError


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


def confirm(message: str) -> str:
    """Read a visible answer from the console itself (not stdin), so piped input can't answer it."""
    try:
        if sys.platform == "win32":
            with open("CONIN$", "r", encoding="utf-8", errors="replace") as r, \
                    open("CONOUT$", "w", encoding="utf-8") as w:
                w.write(message)
                w.flush()
                return r.readline().strip()
        with open("/dev/tty", "r+", encoding="utf-8", errors="replace") as tty:
            tty.write(message)
            tty.flush()
            return tty.readline().strip()
    except OSError as e:
        raise UsageError("No terminal available to confirm; run from a terminal or drop --preview.") from e


def show_preview(prompt: str, stream=None) -> None:
    """Print exactly what would be sent, between markers (to stderr, so stdout stays the answer)."""
    stream = stream or sys.stderr
    bar = "-" * 30
    stream.write(f"{bar} text to be sent {bar}\n{prompt.rstrip()}\n{bar}{'-' * 17}{bar}\n")
    stream.flush()
