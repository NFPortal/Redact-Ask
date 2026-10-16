import json
import os
import sys
from datetime import timedelta

import pytest

from redactask import audit_log, config, final_scan, key_manager, masker, output_writer
from redactask.lists_detector import ListData
from redactask.models import Mapping, StorageError, now
from redactask.session_store import SessionStore


def store(expiry=14):
    d = config.dirs()
    key, _ = key_manager.get_key(d.config)
    return SessionStore(d.sessions, d.workdirs, key, expiry)


# ---- key_manager -----------------------------------------------------------
def test_passphrase_key_is_derived_not_stored(isolated_home):
    d = config.dirs()
    k1, created = key_manager.get_key(d.config)
    assert created
    key_manager._cache.clear()
    k2, created2 = key_manager.get_key(d.config)
    assert k1 == k2 and not created2
    stored = b"".join(f.read_bytes() for f in d.config.iterdir() if f.is_file())
    assert k1 not in stored and b"test-passphrase" not in stored
    assert sorted(f.name for f in d.config.iterdir() if f.name.startswith("key")) == ["key.check", "key.salt"]


def test_wrong_passphrase_rejected(isolated_home, monkeypatch):
    d = config.dirs()
    key_manager.get_key(d.config)
    key_manager._cache.clear()
    monkeypatch.setattr(key_manager, "_prompt", lambda m: "not-the-passphrase")
    with pytest.raises(StorageError, match="Wrong passphrase"):
        key_manager.get_key(d.config)


def test_new_passphrase_must_match_and_be_long_enough(isolated_home, monkeypatch):
    answers = iter(["short", "long-enough-1", "different-2", "long-enough-1", "long-enough-1"])
    monkeypatch.setattr(key_manager, "_prompt", lambda m: next(answers))
    key, created = key_manager.get_key(config.dirs().config)
    assert created and key


def test_legacy_sessions_are_migrated(isolated_home):
    from cryptography.fernet import Fernet
    d = config.dirs()
    old_key = Fernet.generate_key()
    old_store = SessionStore(d.sessions, d.workdirs, old_key, 14)
    sess = old_store.load("legacy")
    masker.placeholder_for(sess.mapping, "USER", "olduser")
    old_store.save(sess)
    s = store()
    assert s.migrate(old_key) == 1
    assert s.load("legacy").mapping.reverse["<USER_1>"] == "olduser"
    assert s.migrate(old_key) == 0


# ---- session_store ---------------------------------------------------------
def test_session_roundtrip_is_encrypted(isolated_home):
    s = store()
    sess = s.load("proj-x")
    masker.placeholder_for(sess.mapping, "USER", "jdoe-secret-user")
    sess.conversations["claude"] = "abc"
    s.save(sess)
    raw = b"".join(p.read_bytes() for p in config.dirs().sessions.glob("*"))
    assert b"jdoe-secret-user" not in raw and b"proj-x" not in raw
    again = store().load("proj-x")
    assert again.mapping.reverse["<USER_1>"] == "jdoe-secret-user"
    assert again.conversations == {"claude": "abc"}


def test_folder_sessions_and_named_sessions_are_separate(isolated_home):
    assert SessionStore.session_name(None, "C:/a") != SessionStore.session_name("named")
    assert SessionStore.session_id("folder:/a") != SessionStore.session_id("folder:/b")


def test_expiry_and_clear(isolated_home):
    s = store(expiry=1)
    old = s.load("old")
    s.save(old)
    data = s.load("old")
    data.last_used = now() - timedelta(days=3)
    # write with an old timestamp directly
    blob = s.fernet.encrypt(json.dumps(data.to_dict()).encode())
    s._path(data.id).write_bytes(blob)
    s.save(s.load("fresh"))
    assert s.expire() == 1
    assert [r["name"] for r in s.list()] == ["fresh"]
    assert s.clear("fresh") == 1 and s.list() == []


def test_wrong_key_is_an_error_not_an_overwrite(isolated_home):
    s = store()
    s.save(s.load("p"))
    from cryptography.fernet import Fernet
    d = config.dirs()
    other = SessionStore(d.sessions, d.workdirs, Fernet.generate_key(), 14)
    with pytest.raises(StorageError, match="decrypted"):
        other.load("p")


# ---- final_scan ------------------------------------------------------------
def test_final_scan_finds_mapping_leaks_and_ignores_placeholders(cfg):
    m = Mapping()
    masker.placeholder_for(m, "PERSON", "Ingrid Halvorsen")
    text = "<PERSON_1> paged ingrid halvorsen; <IP_1 in SUBNET_1> ok"
    left = final_scan.scan(text, m, cfg, ListData())
    assert [(f.type, f.value) for f in left] == [("PERSON", "ingrid halvorsen")]
    assert final_scan.describe(text, left) == ["line 1, column 18: PERSON"]


def test_final_scan_catches_rule_leftovers(cfg):
    left = final_scan.scan("token=ghp_IWPU7wVJZKPqqeTi8d5ku0fmC8I1q4dJjBwM", Mapping(), cfg, ListData())
    assert left


# ---- audit_log -------------------------------------------------------------
def test_audit_entries_and_retention(isolated_home):
    a = audit_log.AuditLog(config.dirs().audit, 14)
    rid = a.start("redacted <USER_1>", "claude", None, "f" * 64, {"USER": 1}, 0, "stdin")
    a.finish(rid, "done", redacted_answer="answer <USER_1>")
    lines = [json.loads(l) for l in a.path.read_text(encoding="utf-8").splitlines()]
    assert [l["status"] for l in lines] == ["sending", "done"]
    assert lines[0]["sent_text"] == "redacted <USER_1>" and lines[1]["answer"] == "answer <USER_1>"
    old = dict(lines[0], time=(now() - timedelta(days=30)).isoformat())
    a.path.write_text(json.dumps(old) + "\n" + json.dumps(lines[1]) + "\n", encoding="utf-8")
    assert a.expire() == 1


def test_final_scan_catches_values_hidden_in_hex_and_base64(cfg):
    """Windows events carry the server name as UTF-16 hex in <Binary>; it must not slip through."""
    import base64 as b64
    from redactask.models import Mapping as M
    m = M()
    masker.placeholder_for(m, "HOST", "SRV-FAKE0042")
    blob = ("AC450000140000001600000" + "0" + "SRV-FAKE0042\\BARTENDER".encode("utf-16-le").hex().upper() + "0000")
    text = f"Computer: <HOST_1>\n<Binary>{blob}</Binary>\nother: {b64.b64encode(b'user=srv-fake0042 ok').decode()}"
    left = final_scan.scan(text, m, cfg, ListData())
    assert [f.type for f in left] == ["ENCODED", "ENCODED"]
    # harmless blobs are left alone
    assert final_scan.scan("<Binary>" + ("00" * 40) + "</Binary>", M(), cfg, ListData()) == []


def test_reset_passphrase_command(isolated_home, monkeypatch, capsys):
    import redact_ask
    s = store()
    s.save(s.load("old-session"))
    old_check = (config.dirs().config / "key.check").read_bytes()
    monkeypatch.setattr(output_writer, "confirm", lambda m: "nope")
    assert redact_ask.main(["reset-passphrase"]) == 0
    assert list(config.dirs().sessions.glob("*.session"))            # cancelled: nothing changed
    monkeypatch.setattr(output_writer, "confirm", lambda m: "RESET")
    monkeypatch.setattr(key_manager, "_prompt", lambda m: "brand-new-passphrase")
    assert redact_ask.main(["reset-passphrase"]) == 0
    assert "Deleted 1 session(s)" in capsys.readouterr().out
    assert not config.dirs().sessions.exists()
    assert (config.dirs().config / "key.check").read_bytes() != old_check
    key_manager._cache.clear()
    key, created = key_manager.get_key(config.dirs().config)   # new passphrase unlocks
    assert not created
