"""[10] Replace findings with placeholders (SPEC: masker.py).

Same real value -> same placeholder for the whole session. Does not load or save the
mapping (that is session_store.py).
"""
from __future__ import annotations

from .models import CATALOG, Finding, Mapping, PLACEHOLDER_LIKE_RE


def _key(type_: str, value: str) -> str:
    info = CATALOG.get(type_)
    prefix = info.prefix if info else type_
    norm = value.casefold() if (info is None or info.case_insensitive) else value
    return f"{prefix}:{norm}"


def _prefix_ci(prefix: str) -> bool:
    info = CATALOG.get(prefix) or next((i for i in CATALOG.values() if i.prefix == prefix), None)
    return info is None or info.case_insensitive


def placeholder_for(mapping: Mapping, type_: str, value: str) -> str:
    """Existing placeholder for this value, or a new <PREFIX_N>."""
    key = _key(type_, value)
    ph = mapping.forward.get(key)
    if ph:
        return ph
    # The same value seen earlier under another type keeps its first placeholder (SPEC edge case).
    # Exact same text always matches; a case-only difference matches only when both types
    # ignore case (names, hosts), never for secrets (Secret1 and secret1 are different passwords).
    info = CATALOG.get(type_)
    new_ci = info is None or info.case_insensitive
    loose = value.casefold()
    for k, existing in mapping.forward.items():
        real = mapping.reverse.get(existing, "")
        if real == value or (new_ci and _prefix_ci(k.split(":", 1)[0]) and real.casefold() == loose):
            mapping.forward[key] = existing
            return existing
    prefix = info.prefix if info else type_
    n = mapping.counters.get(prefix, 0) + 1
    mapping.counters[prefix] = n
    ph = f"<{prefix}_{n}>"
    mapping.forward[key] = ph
    mapping.reverse[ph] = value
    return ph


def escape_literals(text: str, mapping: Mapping) -> str:
    """Input text that already looks like a placeholder (<USER_1>) becomes <LITERAL_n>,
    so it can't be confused with a real placeholder. unmasker restores it."""
    out, last = [], 0
    for m in PLACEHOLDER_LIKE_RE.finditer(text):
        out.append(text[last:m.start()])
        out.append(placeholder_for(mapping, "LITERAL", m.group(0)))
        last = m.end()
    out.append(text[last:])
    return "".join(out)


def mask(text: str, findings: list[Finding], mapping: Mapping) -> str:
    """Replace merged (non-overlapping) findings in one pass over the text."""
    # Assign numbers in reading order so placeholders count up through the text.
    replacements: list[tuple[int, int, str]] = []
    for f in sorted(findings, key=lambda f: f.start):
        value = text[f.start:f.end]
        ph = placeholder_for(mapping, f.type, value)
        if f.type == "IP_PRIVATE" and f.subnet:
            sub = placeholder_for(mapping, "SUBNET", f.subnet)
            ph = f"{ph[:-1]} in {sub[1:-1]}>"          # <IP_3 in SUBNET_1>
        replacements.append((f.start, f.end, ph))
    out, last = [], 0
    for start, end, ph in replacements:
        out.append(text[last:start])
        out.append(ph)
        last = end
    out.append(text[last:])
    return "".join(out)
