"""[13] Fail-closed check of the redacted text before anything is sent (SPEC: final_scan.py).

Fast and deterministic: re-runs the rules, secrets and lists detectors, and searches for every
real value already in the session mapping. Never runs GLiNER or the LLM; never modifies text.
"""
from __future__ import annotations

import base64
import binascii
import re
from dataclasses import replace

from . import lists_detector, rules_detector, secrets_detector
from .lists_detector import ListData
from .models import CATALOG, Finding, Mapping, PLACEHOLDER_RE, inside_any, placeholder_spans

DETECTOR = "final_scan"
MIN_LEAK_LENGTH = 3


def _type_for_prefix(prefix: str) -> str:
    if prefix in CATALOG:
        return prefix
    return next((t for t, i in CATALOG.items() if i.prefix == prefix), "SECRET")


def _mapping_leaks(text: str, mapping: Mapping) -> list[Finding]:
    """Any real value from the mapping that still appears in the text is a leak."""
    values: dict[str, set[str]] = {}
    for ph, real in mapping.reverse.items():
        m = PLACEHOLDER_RE.fullmatch(ph)
        if not m or m.group(1) == "LITERAL" or len(real) < MIN_LEAK_LENGTH:
            continue
        values.setdefault(_type_for_prefix(m.group(1)), set()).add(real)
    if not values:
        return []
    return lists_detector.detect(text, ListData(values=values))


_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


def _decodings(raw: bytes) -> list[str]:
    """Readable text hidden in a blob: UTF-16LE (Windows event data) and UTF-8/Latin-1."""
    out = []
    for enc in ("utf-16-le", "utf-8", "latin-1"):
        try:
            s = raw.decode(enc, errors="ignore")
        except Exception:
            continue
        # keep runs of printable characters; a blob that hides a hostname yields readable runs
        runs = [r for r in re.findall(r"[\x20-\x7e]{4,}", s)]
        if runs:
            out.append("\n".join(runs))
    return out


def _encoded_leaks(text: str, mapping: Mapping, config, lists: ListData, automaton) -> list[Finding]:
    """Hex or base64 blobs whose decoded content contains a real value or a detectable secret.

    Example: a Windows event's <Binary> field holds the server name as UTF-16 hex.
    The whole blob is reported so it gets replaced by an <ENCODED_n> placeholder.
    """
    out = []
    for pattern, decode in ((_HEX_RE, bytes.fromhex), (_B64_RE, _b64)):
        for m in pattern.finditer(text):
            try:
                raw = decode(m.group(0))
            except (ValueError, binascii.Error):
                continue
            for decoded in _decodings(raw):
                hits = _mapping_leaks(decoded, mapping)
                hits += [f for f in rules_detector.detect(decoded, config, lists.subnets)
                         if config.type_enabled(f.type)]
                hits += secrets_detector.detect(decoded)
                hits += lists_detector.detect(decoded, lists, automaton)
                if hits:
                    out.append(Finding(m.start(), m.end(), m.group(0), "ENCODED", DETECTOR, 1.0))
                    break
    return out


def _b64(s: str) -> bytes:
    return base64.b64decode(s + "=" * (-len(s) % 4), validate=True)


def scan(text: str, mapping: Mapping, config, lists: ListData, automaton=None) -> list[Finding]:
    found: list[Finding] = []
    found += rules_detector.detect(text, config, lists.subnets)
    found += secrets_detector.detect(text)
    found += lists_detector.detect(text, lists, automaton)
    found += _mapping_leaks(text, mapping)
    found += _encoded_leaks(text, mapping, config, lists, automaton)

    ph = placeholder_spans(text)
    out = []
    for f in found:
        if not config.type_enabled(f.type):
            continue
        if inside_any(f.start, f.end, ph):
            continue
        out.append(replace(f, detector=DETECTOR))
    return out


def describe(text: str, findings: list[Finding]) -> list[str]:
    """Line/column/type for each leftover, for the abort message (values stay local)."""
    lines = []
    for f in sorted(findings, key=lambda f: f.start):
        line = text.count("\n", 0, f.start) + 1
        col = f.start - (text.rfind("\n", 0, f.start) + 1) + 1
        lines.append(f"line {line}, column {col}: {f.type}")
    return lines
