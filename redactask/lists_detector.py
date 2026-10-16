"""[6] Known values from the user's list files (SPEC: lists_detector.py).

Case-insensitive, whole-word matching where . _ - \\ / and any other non-alphanumeric
character count as separators. Never modifies the list files (that is learner.py).
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from pathlib import Path

import ahocorasick

from .models import CATALOG, Finding, list_backed_types

DETECTOR = "lists"


@dataclass
class ListData:
    values: dict[str, set[str]] = field(default_factory=dict)   # TYPE -> values (original case)
    subnets: list = field(default_factory=list)                 # ipaddress networks
    warnings: list[str] = field(default_factory=list)

    def contains(self, type_: str, value: str) -> bool:
        low = value.casefold()
        return any(v.casefold() == low for v in self.values.get(type_, ()))


def _read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            out.append(line)
    return out


def load(lists_dir: Path) -> ListData:
    data = ListData()
    for type_, filename in list_backed_types().items():
        data.values.setdefault(type_, set()).update(_read_lines(lists_dir / filename))
    for line in _read_lines(lists_dir / "custom.txt"):
        type_, _, value = line.partition(" ")
        type_ = type_.upper()
        value = value.strip()
        if type_ not in CATALOG or not value:
            data.warnings.append(f"custom.txt: ignored line '{line}' (expected 'TYPE value' with a known TYPE).")
            continue
        data.values.setdefault(type_, set()).add(value)
    for line in _read_lines(lists_dir / "subnets.txt"):
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            data.warnings.append(f"subnets.txt: '{line}' is not a valid CIDR range; ignored.")
            continue
        data.subnets.append(net)
        data.values.setdefault("SUBNET", set()).add(str(net))
    return data


def _lower_same_length(text: str) -> str:
    """Lowercase without changing string length, so offsets still match the original text."""
    return "".join(ch.lower() if len(ch.lower()) == 1 else ch for ch in text)


def _is_boundary(ch: str) -> bool:
    return not ch.isalnum()


def build_automaton(values: dict[str, set[str]]):
    auto = ahocorasick.Automaton()
    entries: dict[str, list[str]] = {}
    for type_, vals in values.items():
        for v in vals:
            key = _lower_same_length(v)
            if len(key) < 2:
                continue
            entries.setdefault(key, [])
            if type_ not in entries[key]:
                entries[key].append(type_)
    if not entries:
        return None
    for key, types in entries.items():
        auto.add_word(key, (key, types))
    auto.make_automaton()
    return auto


def detect(text: str, data: ListData, automaton=None) -> list[Finding]:
    auto = automaton if automaton is not None else build_automaton(data.values)
    if auto is None:
        return []
    low = _lower_same_length(text)
    out: list[Finding] = []
    for end_idx, (key, types) in auto.iter(low):
        start = end_idx - len(key) + 1
        end = end_idx + 1
        # Whole-word check only where the value itself starts/ends with a word character.
        if key[0].isalnum() and start > 0 and not _is_boundary(text[start - 1]):
            continue
        if key[-1].isalnum() and end < len(text) and not _is_boundary(text[end]):
            continue
        for type_ in types:
            out.append(Finding(start, end, text[start:end], type_, DETECTOR, 1.0))
    return out
