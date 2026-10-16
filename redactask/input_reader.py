"""[3] Get the text from the command line, a file (--file) or stdin (SPEC: input_reader.py).

Only checks size and binary content. Never writes the text anywhere.
"""
from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path

from .models import InputError, UsageError

# Separates the input from the question in the text that goes through the pipeline.
QUESTION_MARKER = "\n\n### QUESTION\n"


@dataclass
class InputText:
    text: str               # input + QUESTION_MARKER + question
    question_offset: int    # where the question starts in text
    source: str             # "text" | "file:<name>" | "stdin" | "none"
    warnings: list[str]


def _decode(data: bytes, warnings: list[str]) -> str:
    if b"\x00" in data:
        raise InputError("Input looks binary (contains NUL bytes); only text is supported.")
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
        warnings.append("Input was not valid UTF-8; invalid bytes were replaced with U+FFFD.")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _check_size(data: bytes, max_lines: int, max_bytes: int) -> None:
    if len(data) > max_bytes:
        raise InputError(f"Input is {len(data):,} bytes; the limit is {max_bytes:,} (max_bytes in config).")
    lines = data.count(b"\n") + (0 if data.endswith(b"\n") or not data else 1)
    if lines > max_lines:
        raise InputError(f"Input is {lines:,} lines; the limit is {max_lines:,} (max_lines in config).")


def read(question: str, file: str | None, text: str | None, max_lines: int, max_bytes: int,
         stdin=None) -> InputText:
    """Read exactly one input source and append the question.

    Sources: text passed on the command line (the default), --file PATH, or piped stdin.
    stdin is only used when it is not a terminal; an empty pipe counts as "no input".
    The clipboard is never read.
    """
    stdin = stdin if stdin is not None else sys.stdin
    piped = stdin is not None and not _isatty(stdin)
    if file is not None and text is not None:
        raise UsageError("Use only one input source: text or --file, not both.")

    warnings: list[str] = []
    data: bytes | None = None
    source = "none"
    if file is not None:
        p = Path(file)
        if not p.is_file():
            raise InputError(f"File not found: {file}")
        try:
            data = p.read_bytes()
        except OSError as e:
            raise InputError(f"Can't read {file}: {e}") from e
        if not data.strip():
            raise InputError(f"{file} is empty.")
        source = f"file:{p.name}"
    elif text is not None:
        if not text.strip():
            raise InputError("The text to analyze is empty.")
        data = text.encode("utf-8")
        source = "text"
    elif piped:
        raw = stdin.buffer.read() if hasattr(stdin, "buffer") else stdin.read()
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if raw.startswith(b"\xef\xbb\xbf"):   # PowerShell may prefix piped text with a UTF-8 BOM
            raw = raw[3:]
        if raw.strip():
            data = raw
            source = "stdin"
    if source not in ("stdin", "none"):
        if piped and _has_data(stdin):
            raise UsageError("Use only one input source: text/--file or piped input, not both.")

    if not question or not question.strip():
        raise UsageError("A question is required.")

    body = ""
    if data is not None:
        _check_size(data, max_lines, max_bytes)
        body = _decode(data, warnings).rstrip("\n")
    q = question.replace("\r\n", "\n").strip()
    combined = body + QUESTION_MARKER + q
    return InputText(text=combined, question_offset=len(body) + len(QUESTION_MARKER), source=source,
                     warnings=warnings)


def _isatty(stream) -> bool:
    try:
        return stream.isatty()
    except (AttributeError, ValueError):
        return True


def _has_data(stream) -> bool:
    """Best-effort, non-consuming check whether piped stdin already has data waiting.

    Used only to reject "file AND pipe" mistakes. On Windows this uses PeekNamedPipe. On Linux
    a pipe at EOF also looks readable to select(), so there is no reliable non-consuming check;
    the piped data is simply ignored when text or --file is given.
    """
    if sys.platform != "win32":
        return False
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
        handle = msvcrt.get_osfhandle(stream.fileno())
        avail = wintypes.DWORD()
        ok = ctypes.windll.kernel32.PeekNamedPipe(handle, None, 0, None, ctypes.byref(avail), None)
        return bool(ok) and avail.value > 0
    except Exception:
        return False
