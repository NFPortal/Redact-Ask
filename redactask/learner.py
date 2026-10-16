"""[18] Offer new values found by GLiNER / the LLM for the list files (SPEC: learner.py).

Runs after the answer is printed. Reads answers from the terminal directly (CONIN$ / /dev/tty)
so it works when the input was piped. Never changes findings or the mapping.
"""
from __future__ import annotations

import sys
from pathlib import Path

from .lists_detector import ListData
from .models import CATALOG, Finding

MODEL_DETECTORS = ("gliner", "llm")


def candidates(findings: list[Finding], lists: ListData) -> list[Finding]:
    """Model-found values whose type has a list file and that aren't already listed."""
    out: dict[tuple[str, str], Finding] = {}
    for f in findings:
        detectors = set(f.detector.split("+"))
        if not detectors & set(MODEL_DETECTORS) or detectors & {"lists", "rules", "secrets"}:
            continue
        info = CATALOG.get(f.type)
        if not info or not info.list_file:
            continue
        value = f.value.strip()
        if len(value) < 2 or lists.contains(f.type, value):
            continue
        out.setdefault((f.type, value.casefold()), f)
    return list(out.values())


def _open_tty():
    """(reader, writer) for the real terminal, or (None, None) if there isn't one.

    Piped input is fine (we read the console directly), but if stderr isn't a terminal the
    run is scripted (e.g. 2>&1 | grep), so nobody is there to answer and we don't prompt.
    """
    try:
        if not sys.stderr.isatty():
            return None, None
    except (AttributeError, ValueError):
        return None, None
    try:
        if sys.platform == "win32":
            return open("CONIN$", "r", encoding="utf-8", errors="replace"), open("CONOUT$", "w", encoding="utf-8")
        tty = open("/dev/tty", "r+", encoding="utf-8", errors="replace")
        return tty, tty
    except OSError:
        return None, None


def _context(text: str, f: Finding, width: int = 30) -> str:
    s = max(0, f.start - width)
    e = min(len(text), f.end + width)
    snippet = text[s:f.start] + "[" + text[f.start:f.end] + "]" + text[f.end:e]
    return snippet.replace("\n", " ⏎ ")


def append_values(lists_dir: Path, type_: str, values: list[str]) -> None:
    path = lists_dir / CATALOG[type_].list_file
    lines = path.read_text(encoding="utf-8").splitlines() if path.exists() else []
    comments = [l for l in lines if l.strip().startswith("#") or not l.strip()]
    existing = {l.strip() for l in lines if l.strip() and not l.strip().startswith("#")}
    lowered = {v.casefold() for v in existing}
    for v in values:
        if v.casefold() not in lowered:
            existing.add(v)
            lowered.add(v.casefold())
    body = sorted(existing, key=str.casefold)
    path.write_text("\n".join([*comments, *body]) + "\n", encoding="utf-8")


def run(text: str, findings: list[Finding], lists: ListData, lists_dir: Path) -> int:
    """Ask about each candidate; returns how many values were added."""
    cands = candidates(findings, lists)
    if not cands:
        return 0
    reader, writer = _open_tty()
    if reader is None:
        print(f"redact-ask: {len(cands)} new value(s) found but no terminal is available to approve them; skipped.",
              file=sys.stderr)
        return 0
    approved: dict[str, list[str]] = {}
    try:
        writer.write(f"\nredact-ask found {len(cands)} value(s) not in your lists. Add them so they're always redacted?\n"
                     f"  y = yes, n = no, a = yes to all remaining, s = skip all remaining\n")
        accept_all = False
        for f in sorted(cands, key=lambda f: f.start):
            if not accept_all:
                writer.write(f"  {f.type:<9} {f.value!r}   …{_context(text, f)}…\n  add? [y/n/a/s] ")
                writer.flush()
                answer = (reader.readline() or "s").strip().lower()
                if answer.startswith("s"):
                    break
                if answer.startswith("a"):
                    accept_all = True
                elif not answer.startswith("y"):
                    continue
            approved.setdefault(f.type, []).append(f.value.strip())
        added = 0
        for type_, values in approved.items():
            append_values(lists_dir, type_, values)
            added += len(values)
        if added:
            writer.write(f"  added {added} value(s) to your lists.\n")
            writer.flush()
        return added
    finally:
        if reader is not writer:
            writer.close()
        reader.close()
