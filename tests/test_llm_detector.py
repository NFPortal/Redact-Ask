import json

import pytest

from redactask import config, llm_detector
from redactask.models import DetectorError


def test_refuses_non_localhost():
    c = config.LlmConfig(url="http://gpu-box.example.com:11434")
    with pytest.raises(DetectorError, match="localhost"):
        llm_detector.detect("text", c)


def test_discards_values_not_in_text(monkeypatch):
    reply = json.dumps({"items": [{"text": "Priya", "type": "PERSON"},
                                  {"text": "Invented Person", "type": "PERSON"},
                                  {"text": "atlas", "type": "HOST"}]})
    monkeypatch.setattr(llm_detector, "_call", lambda url, model, prompt: reply)
    fs = llm_detector.detect("Priya restarted atlas and atlas-db", config.LlmConfig())
    vals = [(f.type, f.value) for f in fs]
    assert ("PERSON", "Priya") in vals
    assert vals.count(("HOST", "atlas")) == 2
    assert not any(v == "Invented Person" for _, v in vals)


def test_invalid_json_fails_closed(monkeypatch):
    calls = []
    monkeypatch.setattr(llm_detector, "_call", lambda *a: calls.append(1) or "not json")
    with pytest.raises(DetectorError, match="JSON"):
        llm_detector.detect("some text", config.LlmConfig())
    assert len(calls) == 2          # one retry
