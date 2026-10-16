import pytest

from conftest import requires_gliner
from redactask import gliner_detector


def test_chunks_cover_text_with_correct_offsets():
    text = "\n".join(f"line {i} " + "word " * 30 for i in range(40))
    chunks = gliner_detector.chunk_text(text, max_words=100, overlap_lines=2)
    assert len(chunks) > 1
    for off, chunk in chunks:
        assert text[off:off + len(chunk)] == chunk
        assert len(chunk.split()) <= 100
    covered = set()
    for off, chunk in chunks:
        covered.update(range(off, off + len(chunk)))
    assert all(i in covered for i, ch in enumerate(text) if ch != "\n")


def test_very_long_line_is_split():
    text = "w " * 1000
    chunks = gliner_detector.chunk_text(text, max_words=200)
    assert len(chunks) >= 5 and all(len(c.split()) <= 200 for _, c in chunks)


@requires_gliner
@pytest.mark.slow
def test_finds_names_and_trims_key_prefix(cfg):
    text = ("Escalated to Priya Natarajan at Halvorsen Logistics.\n"
            "SMTP_PASSWORD=MailRelay#2026\n")
    fs = gliner_detector.detect(text, cfg.gliner)
    vals = {(f.type, f.value) for f in fs}
    assert ("PERSON", "Priya Natarajan") in vals          # first + last name joined
    assert any(t == "ORG_NAME" and "Halvorsen" in v for t, v in vals)
    assert not any("SMTP_PASSWORD" in v for _, v in vals)


@requires_gliner
@pytest.mark.slow
def test_log_phrases_are_not_passwords(cfg):
    text = ("Oct 16 08:12:44 web-prod-03 sshd[2230]: Failed password for jdoe from 10.9.8.7 port 40112 ssh2\n"
            "Oct 16 08:12:50 web-prod-03 sshd[2231]: Failed password for jdoe from 10.9.8.7 port 40118 ssh2\n")
    assert not any(f.type == "PASSWORD" for f in gliner_detector.detect(text, cfg.gliner))
