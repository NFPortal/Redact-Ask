"""Planted-secrets corpus (SPEC success criteria).

- Rule-based, secret and list-backed values: 100% must be redacted.
- GLiNER-only values (names, organisations, projects, places): at least 95% across the corpus.
"""
import json

import pytest

import redact_ask
from conftest import CORPUS, requires_gliner
from redactask.lists_detector import ListData
from redactask.models import Mapping

EXPECTED = {k: v for k, v in json.loads((CORPUS / "expected.json").read_text(encoding="utf-8")).items()
            if not k.startswith("_")}


def redacted(name, cfg, use_gliner):
    text = (CORPUS / name).read_text(encoding="utf-8")
    result, _ = redact_ask.redact(text + "\n\n### QUESTION\nq", Mapping(), cfg, ListData(), use_gliner=use_gliner)
    return result.redacted_text


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_rule_based_values_all_redacted(name, cfg):
    out = redacted(name, cfg, use_gliner=False)
    missed = [v for v in EXPECTED[name]["rule"] if v in out]
    assert not missed, f"{name}: not redacted: {missed}"


@requires_gliner
@pytest.mark.slow
def test_gliner_catch_rate_at_least_95_percent(cfg):
    total = caught = 0
    missed = []
    for name, exp in EXPECTED.items():
        out = redacted(name, cfg, use_gliner=True)
        assert not [v for v in exp["rule"] if v in out]
        for v in exp["model"]:
            total += 1
            if v in out:
                missed.append(f"{name}: {v}")
            else:
                caught += 1
    rate = caught / total
    print(f"\nGLiNER catch rate: {caught}/{total} = {rate:.0%}; missed: {missed}")
    assert rate >= 0.95, missed
