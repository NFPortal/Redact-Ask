import json
import os
import sys
from datetime import timedelta

import pytest

from redactask import audit_log, config, final_scan, key_manager, masker
from redactask.lists_detector import ListData
from redactask.models import Mapping, StorageError, now
from redactask.session_store import SessionStore


def store(expiry=14):
    d = config.dirs()
    return SessionStore(d.sessions, d.workdirs, key_manager.get_key(d.config), expiry)


# ---- key_manager -----------------------------------------------------------
def test_key_file_fallback_is_stable_and_private(isolated_home):
    d = config.dirs()
    k1 = key_manager.get_key(d.config)
    k2 = key_manager.get_key(d.config)
    assert k1 == k2
    if sys.platform != "win32":
        assert oct((d.config / "key").stat().st_mode & 0o777) == "0o600"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permissions")
def test_key_file_with_wide_permissions_refused(isolated_home):
    d = config.dirs()
    key_manager.get_key(d.config)
    os.chmod(d.config / "key", 0o644)
    with pytest.raises(StorageError, match="600"):
        key_manager.get_key(d.config)


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
    (config.dirs().config / "key").write_bytes(Fernet.generate_key())
    with pytest.raises(StorageError, match="decrypted"):
        store().load("p")


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
