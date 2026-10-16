"""[9] Combine Findings from all detectors into a sorted, non-overlapping list (SPEC: merger.py).

Overlaps are resolved by keeping the union span (over-redact) and the highest-priority type.
Never changes text.
"""
from __future__ import annotations

from .rules_detector import COMMON_WORDS
from .models import CATALOG, Finding, inside_any, placeholder_spans, priority

MIN_LENGTH = 2
# Broad "whatever value is here" types: a more specific finding inside them decides the type.
GENERIC = {"ENV_VALUE", "SQL_VALUE", "HIGH_ENTROPY", "PATH", "CUSTOMER_ID"}


def _pick_type(a: Finding, b: Finding) -> Finding:
    """Which finding's type the merged span gets.

    - One fully contains the other: the container wins (an IMAGE containing a HOST stays IMAGE),
      unless the container is a generic type, or the inner one is a secret and the container
      isn't (a secret is never downgraded).
    - Partial overlap or same span: the higher-priority type wins.
    """
    by_priority = min((a, b), key=lambda x: (priority(x.type), -(x.end - x.start)))
    if (a.start, a.end) == (b.start, b.end):
        # Same text: a rule/list/secret match knows more than a model guess (TABLE beats GLiNER's DB),
        # unless the model's type is a secret.
        a_model = a.detector.split("+")[0] in ("gliner", "llm")
        b_model = b.detector.split("+")[0] in ("gliner", "llm")
        if a_model != b_model:
            rule, model = (b, a) if a_model else (a, b)
            if not (CATALOG.get(model.type) and CATALOG[model.type].group == "secrets"):
                return rule
        return by_priority
    if a.start <= b.start and a.end >= b.end:
        outer, inner = a, b
    elif b.start <= a.start and b.end >= a.end:
        outer, inner = b, a
    else:
        return by_priority
    if outer.type in GENERIC:
        return by_priority
    if CATALOG.get(inner.type) and CATALOG[inner.type].group == "secrets" and \
            (not CATALOG.get(outer.type) or CATALOG[outer.type].group != "secrets"):
        return inner
    return outer


def merge(text: str, findings: list[Finding], config) -> list[Finding]:
    ph = placeholder_spans(text)
    kept: list[Finding] = []
    for f in findings:
        if not config.type_enabled(f.type):
            continue
        if f.end - f.start < MIN_LENGTH or not text[f.start:f.end].strip():
            continue
        # "AND", "SELECT", "error"... are never sensitive on their own (secrets excepted).
        info = CATALOG.get(f.type)
        if (info is None or info.group != "secrets") and text[f.start:f.end].strip().casefold() in COMMON_WORDS:
            continue
        # Findings inside (or overlapping) an existing placeholder are already redacted.
        if inside_any(f.start, f.end, ph):
            continue
        kept.append(f)

    kept.sort(key=lambda f: (f.start, -f.end))
    merged: list[Finding] = []
    for f in kept:
        if merged and f.start < merged[-1].end:
            prev = merged.pop()
            start, end = prev.start, max(prev.end, f.end)
            best = _pick_type(prev, f)
            subnet = best.subnet if best.type == "IP_PRIVATE" and (best.start, best.end) == (start, end) else None
            merged.append(Finding(start, end, text[start:end], best.type,
                                  prev.detector if prev.detector == f.detector else f"{prev.detector}+{f.detector}",
                                  max(prev.confidence, f.confidence), subnet))
        else:
            merged.append(f)
    return merged
