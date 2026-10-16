"""[13] Fail-closed check of the redacted text before anything is sent (SPEC: final_scan.py).

Fast and deterministic: re-runs the rules, secrets and lists detectors, and searches for every
real value already in the session mapping. Never runs GLiNER or the LLM; never modifies text.
"""
from __future__ import annotations

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


def scan(text: str, mapping: Mapping, config, lists: ListData, automaton=None) -> list[Finding]:
    found: list[Finding] = []
    found += rules_detector.detect(text, config, lists.subnets)
    found += secrets_detector.detect(text)
    found += lists_detector.detect(text, lists, automaton)
    found += _mapping_leaks(text, mapping)

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
