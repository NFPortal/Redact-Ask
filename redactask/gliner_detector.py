"""[7] Model-based entities with GLiNER (SPEC: gliner_detector.py).

Runs locally on the GPU (or CPU). The only network access is downloading the model
weights on the very first run; text is never sent anywhere.
"""
from __future__ import annotations

import os
import re
import sys
import warnings

from .models import DetectorError, Finding

DETECTOR = "gliner"

# GLiNER label -> catalog type. Labels follow the nvidia/gliner-pii (Nemotron-PII) naming,
# plus plain-English labels that GLiNER handles zero-shot.
LABELS: dict[str, str] = {
    "first_name": "PERSON",
    "last_name": "PERSON",
    "person": "PERSON",
    "user_name": "USER",
    "company_name": "ORG_NAME",
    "organization": "ORG_NAME",
    "hostname": "HOST",
    "server name": "HOST",
    "project name": "PROJECT",
    "street_address": "ADDRESS",
    "city": "ADDRESS",
    "phone_number": "PHONE",
    "database name": "DB",
    "table name": "TABLE",
    "password": "PASSWORD",
    "api_key": "API_KEY",
    "account_number": "CUSTOMER_ID",
}

_KEY_PREFIX_RE = re.compile(r"[\w.\-\"']+[ \t]*[=:][ \t]*[\"']?")
CHUNK_WORDS = 200     # model max_len is 384 words; leave room for the label prompt
OVERLAP_LINES = 2

_model = None
_model_device = None


def _device(pref: str) -> str:
    import torch
    if pref == "cpu":
        return "cpu"
    if torch.cuda.is_available():
        return "cuda"
    if pref == "cuda":
        print("redact-ask: CUDA requested but not available; GLiNER is running on the CPU (slower).", file=sys.stderr)
    else:
        print("redact-ask: no NVIDIA GPU found; GLiNER is running on the CPU (slower).", file=sys.stderr)
    return "cpu"


def load_model(cfg):
    """Load once per process. Offline after the first download."""
    global _model, _model_device
    if _model is not None:
        return _model
    os.environ.setdefault("HF_HUB_DISABLE_TELEMETRY", "1")
    os.environ.setdefault("TRANSFORMERS_VERBOSITY", "error")
    warnings.filterwarnings("ignore")
    try:
        from gliner import GLiNER
    except ImportError as e:
        raise DetectorError("The 'gliner' package is not installed (pip install -r requirements.txt).") from e
    try:
        model = GLiNER.from_pretrained(cfg.model, local_files_only=True)
    except Exception:
        if not cfg.allow_download:
            raise DetectorError(f"GLiNER model '{cfg.model}' is not downloaded and allow_download is false. "
                                f"Download it once with: python -c \"from gliner import GLiNER; "
                                f"GLiNER.from_pretrained('{cfg.model}')\"")
        print(f"redact-ask: downloading GLiNER model '{cfg.model}' (first run only)...", file=sys.stderr)
        try:
            model = GLiNER.from_pretrained(cfg.model)
        except Exception as e:
            raise DetectorError(f"Couldn't load or download GLiNER model '{cfg.model}': {e}") from e
    os.environ["HF_HUB_OFFLINE"] = "1"
    _model_device = _device(cfg.device)
    _model = model.to(_model_device)
    _model.eval()
    return _model


def chunk_text(text: str, max_words: int = CHUNK_WORDS, overlap_lines: int = OVERLAP_LINES) -> list[tuple[int, str]]:
    """Split into (offset, chunk) pieces on line boundaries, with a few overlapping lines."""
    lines = text.split("\n")
    offsets, pos = [], 0
    for line in lines:
        offsets.append(pos)
        pos += len(line) + 1
    chunks: list[tuple[int, str]] = []
    i = 0
    while i < len(lines):
        words, j = 0, i
        while j < len(lines):
            w = len(lines[j].split())
            if words and words + w > max_words:
                break
            words += w
            j += 1
            if w > max_words:   # one very long line: split it by words
                break
        if j == i + 1 and len(lines[i].split()) > max_words:
            chunks.extend(_split_long_line(lines[i], offsets[i], max_words))
        else:
            start = offsets[i]
            end = offsets[j - 1] + len(lines[j - 1])
            if text[start:end].strip():
                chunks.append((start, text[start:end]))
        if j >= len(lines):
            break
        i = max(j - overlap_lines, i + 1)
    return chunks


def _split_long_line(line: str, base: int, max_words: int) -> list[tuple[int, str]]:
    import re
    spans = [m.span() for m in re.finditer(r"\S+", line)]
    out = []
    step = max(1, max_words - 20)
    for k in range(0, len(spans), step):
        part = spans[k:k + max_words]
        s, e = part[0][0], part[-1][1]
        out.append((base + s, line[s:e]))
    return out


def _merge_adjacent(text: str, findings: list[Finding]) -> list[Finding]:
    """Join first_name + last_name style neighbours ("Priya" "Natarajan") into one finding."""
    findings = sorted(findings, key=lambda f: (f.start, f.end))
    out: list[Finding] = []
    for f in findings:
        if out and out[-1].type == f.type and f.type in ("PERSON", "ADDRESS") \
                and 0 <= f.start - out[-1].end <= 2 and text[out[-1].end:f.start].strip(" ,") == "":
            prev = out.pop()
            out.append(Finding(prev.start, f.end, text[prev.start:f.end], f.type, DETECTOR,
                               min(prev.confidence, f.confidence)))
        else:
            out.append(f)
    return out


def detect(text: str, cfg) -> list[Finding]:
    if not text.strip():
        return []
    model = load_model(cfg)
    chunks = chunk_text(text)
    labels = list(LABELS)
    try:
        import torch
        with torch.inference_mode():
            results = model.inference([c for _, c in chunks], labels, threshold=cfg.threshold, batch_size=8)
    except Exception as e:
        raise DetectorError(f"GLiNER failed: {e}") from e

    seen: set[tuple[int, int, str]] = set()
    found: list[Finding] = []
    for (offset, _), ents in zip(chunks, results):
        for ent in ents:
            type_ = LABELS.get(ent["label"])
            if type_ is None:
                continue
            start, end = offset + ent["start"], offset + ent["end"]
            while end > start and text[end - 1] in " \t;,.:\"')]}":
                end -= 1
            while start < end and text[start] in " \t\"'([{":
                start += 1
            # GLiNER splits words on whitespace, so "SMTP_PASSWORD=MailRelay#2026" is one word.
            # Keep only the value after a key= / key: prefix.
            km = _KEY_PREFIX_RE.match(text, start, end)
            if km and km.end() < end:
                start = km.end()
            if end - start < 2:
                continue
            key = (start, end, type_)
            if key in seen:
                continue
            seen.add(key)
            found.append(Finding(start, end, text[start:end], type_, DETECTOR, float(ent["score"])))
    return _merge_adjacent(text, found)
