"""[8] Optional local LLM pass through Ollama, only with --deep (SPEC: llm_detector.py).

The model only proposes values; any value that doesn't occur verbatim in the text is
discarded, and the model's text is never used as output.
"""
from __future__ import annotations

import json
import re
import urllib.error
import urllib.request

from .config import is_localhost_url
from .gliner_detector import chunk_text
from .models import CATALOG, DetectorError, Finding, PLACEHOLDER_RE

DETECTOR = "llm"
CHUNK_WORDS = 600
TIMEOUT = 180

PROMPT = """You find sensitive values in logs, code and configuration so they can be redacted.
Return ONLY a JSON object: {{"items": [{{"text": "<exact substring>", "type": "<TYPE>"}}]}}
Use these types: {types}.
Rules:
- "text" must be copied exactly, character for character, from the input.
- Include people's names, usernames, internal hostnames, internal domains, company and client names,
  project names, database/table/column names, addresses, phone numbers, emails, account or customer
  numbers, and any secrets (passwords, keys, tokens).
- Ignore anything that looks like <TYPE_N>; it is already redacted.
- If nothing is sensitive, return {{"items": []}}.

Input:
<<<
{chunk}
>>>"""

TYPES = ["PERSON", "USER", "HOST", "DOMAIN", "ORG_NAME", "PROJECT", "DB", "TABLE", "COLUMN", "ADDRESS",
         "PHONE", "EMAIL", "CUSTOMER_ID", "PASSWORD", "API_KEY", "TOKEN", "SECRET", "IP", "URL", "PATH"]


def _call(url: str, model: str, prompt: str) -> str:
    body = json.dumps({
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "format": "json",
        "stream": False,
        "think": False,
        "options": {"temperature": 0},
    }).encode("utf-8")
    req = urllib.request.Request(url.rstrip("/") + "/api/chat", data=body,
                                 headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", "replace")[:200]
        raise DetectorError(f"Ollama returned HTTP {e.code}: {detail}. Is the model '{model}' pulled "
                            f"(ollama pull {model})?") from e
    except (urllib.error.URLError, OSError) as e:
        raise DetectorError(f"Can't reach Ollama at {url} ({e}). Start Ollama or run without --deep.") from e
    return data.get("message", {}).get("content", "")


def _parse(content: str) -> list[dict] | None:
    try:
        obj = json.loads(content)
    except json.JSONDecodeError:
        return None
    items = obj.get("items") if isinstance(obj, dict) else obj
    if not isinstance(items, list):
        return None
    return [i for i in items if isinstance(i, dict) and isinstance(i.get("text"), str)]


def detect(text: str, cfg) -> list[Finding]:
    if not is_localhost_url(cfg.url):
        raise DetectorError(f"[llm] url must be localhost (got {cfg.url}); text must not leave this machine.")
    out: list[Finding] = []
    for offset, chunk in chunk_text(text, max_words=CHUNK_WORDS, overlap_lines=1):
        prompt = PROMPT.format(types=", ".join(TYPES), chunk=chunk)
        items = _parse(_call(cfg.url, cfg.model, prompt))
        if items is None:   # one retry, then fail closed
            items = _parse(_call(cfg.url, cfg.model, prompt))
        if items is None:
            raise DetectorError("The local LLM did not return valid JSON (after one retry).")
        for item in items:
            value = item["text"].strip()
            if len(value) < 2 or PLACEHOLDER_RE.search(value):
                continue
            type_ = str(item.get("type", "")).upper()
            if type_ not in CATALOG or type_ == "LITERAL":
                type_ = "SECRET" if type_ in ("KEY", "CREDENTIAL") else "PERSON" if type_ == "NAME" else "ORG_NAME"
            # Keep only values that really occur in the chunk; locate every occurrence.
            for m in re.finditer(re.escape(value), chunk):
                out.append(Finding(offset + m.start(), offset + m.end(), value, type_, DETECTOR, 0.5))
    return out
