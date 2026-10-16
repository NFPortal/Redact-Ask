"""Whole-pipeline tests with a fake cloud CLI (nothing leaves the machine)."""
import io
import json
import sys
from pathlib import Path

import pytest

import redact_ask
from conftest import CORPUS
from redactask import cloud_runner, config, gliner_detector, learner, output_writer

HERE = Path(__file__).resolve().parent
REAL_VALUES = ["mlopez", "10.20.4.17", "web-prod-03", "203.0.113.250"]


@pytest.fixture
def fake_cli(tmp_path, monkeypatch):
    """Point cloud_runner at tests/fake_cli.py and record every call."""
    if sys.platform == "win32":
        wrapper = tmp_path / "fake.cmd"
        wrapper.write_text(f'@"{sys.executable}" "{HERE / "fake_cli.py"}" %*\n', encoding="utf-8")
    else:
        wrapper = tmp_path / "fake.sh"
        wrapper.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{HERE / "fake_cli.py"}" "$@"\n')
        wrapper.chmod(0o755)
    log = tmp_path / "calls.jsonl"
    monkeypatch.setenv("FAKE_CLI_LOG", str(log))
    monkeypatch.setattr(cloud_runner, "_exe", lambda tool: str(wrapper))
    monkeypatch.setattr(gliner_detector, "detect", lambda text, cfg: [])   # keep e2e fast
    monkeypatch.setattr(learner, "_open_tty", lambda: (None, None))
    monkeypatch.setattr(output_writer, "confirm", lambda m: "y")      # preview is on by default

    class TtyStdin(io.StringIO):
        def isatty(self):
            return True
    monkeypatch.setattr(sys, "stdin", TtyStdin())

    def calls():
        if not log.exists():
            return []
        return [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines()]
    return calls


def run(argv, capsys):
    try:
        code = redact_ask.main(argv)
    except SystemExit as e:          # argparse usage errors
        code = e.code
    out = capsys.readouterr()
    return code, out.out, out.err


def test_round_trip_restores_values_and_sends_only_redacted(fake_cli, capsys, tmp_path):
    log = CORPUS / "syslog_auth.log"
    code, out, err = run(["--file", str(log), "-q", "What happened?", "--session", "t1", "--restore"], capsys)
    assert code == 0, err
    [call] = fake_cli()
    for v in REAL_VALUES:
        assert v not in call["stdin"]
    assert "<USER_1>" in call["stdin"] and "### QUESTION\nWhat happened?" in call["stdin"]
    assert call["cwd_files"] == []                           # empty working folder
    assert "--tools" in call["argv"] and "WebSearch,WebFetch" in call["argv"]
    assert "--safe-mode" in call["argv"]                      # isolated context by default
    assert out.strip() == "Looks like mlopez failed from 10.20.4.17."


def test_follow_up_resumes_conversation_and_keeps_placeholders(fake_cli, capsys):
    run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "first", "--session", "t2"], capsys)
    code, out, _ = run(["-q", "who is mlopez?", "--session", "t2"], capsys)
    first, second = fake_cli()
    assert code == 0
    sid = first["argv"][first["argv"].index("--session-id") + 1]
    assert second["argv"][second["argv"].index("--resume") + 1] == sid
    assert "<USER_1>" in second["stdin"] and "mlopez" not in second["stdin"]


def test_copilot_target_and_model(fake_cli, capsys, monkeypatch):
    monkeypatch.setenv("FAKE_CLI_ANSWER", "user <USER_1>")
    code, out, _ = run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--to", "copilot:gpt-5", "--session", "t3", "--restore"], capsys)
    [call] = fake_cli()
    assert code == 0 and out.strip() == "user mlopez"
    a = call["argv"]
    assert a[a.index("--available-tools") + 1] == "web_fetch" and "--no-custom-instructions" in a
    assert a[a.index("--model") + 1] == "gpt-5"
    assert call["stdin"].startswith(cloud_runner.INSTRUCTIONS)


def test_no_real_values_written_to_disk(fake_cli, capsys, isolated_home):
    run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--session", "t4", "--restore", "--out", str(isolated_home / "answer.txt")], capsys)
    for p in isolated_home.rglob("*"):
        if p.is_file() and p.name != "answer.txt":           # --out is the user's restored answer
            data = p.read_bytes()
            for v in REAL_VALUES:
                assert v.encode() not in data, f"{v} found in {p}"
    assert "mlopez" in (isolated_home / "answer.txt").read_text(encoding="utf-8")


def test_nothing_sent_when_scan_aborts(fake_cli, capsys, monkeypatch):
    from redactask import final_scan
    from redactask.models import Finding
    monkeypatch.setattr(final_scan, "scan", lambda text, *a, **k: [Finding(0, 3, text[:3], "SECRET", "final_scan")])
    code, out, err = run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q"], capsys)
    assert code == 4 and "nothing was sent" in err
    assert fake_cli() == []


def test_nothing_sent_when_detector_fails(fake_cli, capsys, monkeypatch):
    from redactask.models import DetectorError

    def boom(text, cfg):
        raise DetectorError("GLiNER failed: test")
    monkeypatch.setattr(gliner_detector, "detect", boom)
    code, _, err = run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q"], capsys)
    assert code == 7 and fake_cli() == []


def test_cloud_failure_is_logged(fake_cli, capsys, monkeypatch, isolated_home):
    monkeypatch.setenv("FAKE_CLI_FAIL", "1")
    code, _, err = run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--to", "copilot"], capsys)
    assert code == 5
    statuses = [json.loads(l)["status"] for l in (config.dirs().audit / "audit.jsonl").read_text().splitlines()]
    assert statuses == ["sending", "error"]


def test_sessions_commands(fake_cli, capsys):
    run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--session", "listed"], capsys)
    code, out, _ = run(["sessions", "list"], capsys)
    assert code == 0 and "listed" in out and "USER" in out and "mlopez" not in out
    code, out, _ = run(["sessions", "clear", "listed"], capsys)
    assert "Cleared 1" in out


def test_learner_appends_approved_values(isolated_home):
    from redactask.lists_detector import ListData
    from redactask.models import Finding
    config.load()
    d = config.dirs()
    text = "ping Samuel and Stormcrow"
    fs = [Finding(5, 11, "Samuel", "PERSON", "gliner", 0.9), Finding(16, 25, "Stormcrow", "PROJECT", "gliner", 0.5),
          Finding(0, 4, "ping", "USER", "rules")]
    cands = learner.candidates(fs, ListData())
    assert {c.value for c in cands} == {"Samuel", "Stormcrow"}
    learner.append_values(d.lists, "PERSON", ["Samuel", "samuel"])
    lines = (d.lists / "people.txt").read_text(encoding="utf-8").splitlines()
    assert lines.count("Samuel") == 1 and not any(l == "samuel" for l in lines)


def test_output_writer_out_file(tmp_path):
    buf = io.StringIO()
    output_writer.write("hello", str(tmp_path / "o.txt"), stream=buf)
    assert buf.getvalue() == "hello\n" and (tmp_path / "o.txt").read_text() == "hello\n"


def test_claude_command_full_context_keeps_tool_limits():
    cmd = cloud_runner.claude_command("claude", "full", "opus", "id-1", resume=True)
    assert "--safe-mode" not in cmd and "--append-system-prompt" in cmd
    assert cmd[cmd.index("--tools") + 1] == "WebSearch,WebFetch" and "--strict-mcp-config" in cmd
    assert cmd[cmd.index("--resume") + 1] == "id-1" and cmd[cmd.index("--model") + 1] == "opus"


def test_pasted_text_argument(fake_cli, capsys):
    text = "Accepted password for mlopez from 10.20.4.17 port 22"
    code, out, err = run([text, "-q", "who logged in?", "--session", "t9"], capsys)
    [call] = fake_cli()
    assert code == 0 and "mlopez" not in call["stdin"] and "10.20.4.17" not in call["stdin"]


def test_default_output_is_the_raw_model_answer(fake_cli, capsys):
    code, out, _ = run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--session", "t10"], capsys)
    assert code == 0 and out.strip() == "Looks like <USER_1> failed from <IP_1>."



def test_text_without_query_is_never_sent(fake_cli, capsys):
    """Anything typed without -q is the text to analyze, never the question; a typo of a command
    ("rt-passphrase") therefore fails instead of being sent."""
    for argv in (["rt-passphrase"], ["session", "list"], ["some pasted log text"]):
        code, _, err = run(argv, capsys)
        assert code == 2 and "-q" in err
    assert fake_cli() == []


def test_dry_run_shows_redacted_text_and_sends_nothing(fake_cli, capsys):
    code, out, err = run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--dry-run", "--session", "d1"], capsys)
    assert code == 0 and "<USER_1>" in out and "mlopez" not in out and "nothing was sent" in err
    assert fake_cli() == []


def test_preview_declined_sends_nothing_and_is_logged(fake_cli, capsys, monkeypatch, isolated_home):
    monkeypatch.setattr(output_writer, "confirm", lambda m: "n")
    code, out, err = run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--preview", "--session", "p1"], capsys)
    assert code == 0 and "text to be sent" in err and "<USER_1>" in err and "cancelled" in err
    assert fake_cli() == []
    lines = (config.dirs().audit / "audit.jsonl").read_text(encoding="utf-8").splitlines()
    assert [json.loads(l)["status"] for l in lines] == ["cancelled"]


def test_preview_accepted_sends(fake_cli, capsys, monkeypatch):
    monkeypatch.setattr(output_writer, "confirm", lambda m: "y")
    code, out, _ = run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--preview", "--session", "p2"], capsys)
    assert code == 0 and len(fake_cli()) == 1


def test_preview_is_on_by_default_and_can_be_turned_off(fake_cli, capsys, monkeypatch, isolated_home):
    asked = []
    monkeypatch.setattr(output_writer, "confirm", lambda m: asked.append(m) or "n")
    run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--session", "p3"], capsys)
    assert asked and fake_cli() == []                     # default: asked, declined, nothing sent
    cfg_path = config.dirs().config / "config.toml"
    cfg_path.write_text(cfg_path.read_text(encoding="utf-8").replace("preview = true", "preview = false"),
                        encoding="utf-8")
    asked.clear()
    run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--session", "p4"], capsys)
    assert not asked and len(fake_cli()) == 1             # preview = false: sent without asking


def test_default_preview_skipped_when_nothing_redacted(fake_cli, capsys, monkeypatch):
    asked = []
    monkeypatch.setattr(output_writer, "confirm", lambda m: asked.append(m) or "n")
    code, _, _ = run(["the build is slow", "-q", "why?", "--session", "p6"], capsys)
    assert code == 0 and not asked and len(fake_cli()) == 1          # nothing redacted: sent without asking
    run(["the build is slow", "-q", "why?", "--preview", "--session", "p7"], capsys)
    assert asked and len(fake_cli()) == 1                            # explicit --preview still asks


def test_preview_flag_still_asks_when_config_is_false(fake_cli, capsys, monkeypatch, isolated_home):
    config.load()
    cfg_path = config.dirs().config / "config.toml"
    cfg_path.write_text(cfg_path.read_text(encoding="utf-8").replace("preview = true", "preview = false"),
                        encoding="utf-8")
    asked = []
    monkeypatch.setattr(output_writer, "confirm", lambda m: asked.append(m) or "n")
    code, _, err = run(["--file", str(CORPUS / "syslog_auth.log"), "-q", "q", "--preview", "--session", "p5"], capsys)
    assert code == 0 and asked and "text to be sent" in err and fake_cli() == []
