"""--local-tools: hook_server [19], hook_client [20], and the whole run with a fake Claude CLI."""
import json
import subprocess
import sys
import time

import pytest

from conftest import CORPUS
from redactask import cloud_runner, config, hook_client, hook_server
from redactask.models import ScanAbort
from test_end_to_end import fake_cli, run  # noqa: F401  (fixture)

ENV_VALUES = ["Xq7!vR2pLm9w", "AKIAZ4X7Q2M5KD3LT7VB", "sk_live_T467cBsVjdODwyenwQRPMqTn",
              "ghp_IWPU7wVJZKPqqeTi8d5ku0fmC8I1q4dJjBwM", "MailRelay#2026", "ops-alerts@contoso.com"]


def bash_event(stdout: str, **extra) -> dict:
    return {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "cat x"},
            "tool_response": {"stdout": stdout, "stderr": "", "interrupted": False, "isImage": False, **extra}}


def call_client(event: dict, env: dict) -> dict | None:
    """Run hook_client.py the way Claude Code does and return its JSON output."""
    proc = subprocess.run([sys.executable, "-I", str(cloud_runner.HOOK_CLIENT)], input=json.dumps(event).encode(),
                          capture_output=True, env={"SYSTEMROOT": "C:\\Windows", **env}, timeout=60)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def stopped(out) -> bool:
    return out is not None and out.get("continue") is False and out["stopReason"] == hook_client.STOP_REASON


@pytest.fixture
def server():
    with hook_server.HookServer(lambda s: s.replace("hunter2", "<PASSWORD_1>"), 100, 10_000, 5) as srv:
        yield srv


# --- hook_client ------------------------------------------------------------
def test_client_and_server_share_names():
    assert (hook_client.URL_ENV, hook_client.TOKEN_ENV, hook_client.TIMEOUT_ENV, hook_client.TOKEN_HEADER) == \
           (hook_server.URL_ENV, hook_server.TOKEN_ENV, hook_server.TIMEOUT_ENV, hook_server.TOKEN_HEADER)


def test_collect_and_rebuild_keep_the_structure():
    read = {"type": "text", "file": {"filePath": "C:\\x\\a.env", "content": "pw=hunter2", "numLines": 1}}
    grep = {"mode": "content", "numFiles": 0, "filenames": ["a", "b"], "content": "a:1:pw=hunter2"}
    strings = []
    hook_client.collect(read, strings)
    assert strings == ["C:\\x\\a.env", "pw=hunter2"]                     # "type": "text" is skipped
    assert hook_client.rebuild(read, ["P", "C"]) == {"type": "text", "file": {"filePath": "P", "content": "C",
                                                                               "numLines": 1}}
    strings = []
    hook_client.collect(grep, strings)
    assert strings == ["a", "b", "a:1:pw=hunter2"]                       # "mode": "content" is skipped
    assert hook_client.rebuild(grep, ["A", "B", "C"]) == {**grep, "filenames": ["A", "B"], "content": "C"}


def test_client_redacts_through_the_server(server):
    out = call_client(bash_event("pw=hunter2\n"), server.env())
    updated = out["hookSpecificOutput"]["updatedToolOutput"]
    assert out["hookSpecificOutput"]["hookEventName"] == "PostToolUse"
    assert updated == {"stdout": "pw=<PASSWORD_1>\n", "stderr": "", "interrupted": False, "isImage": False}
    assert [o.tool for o in server.outputs] == ["Bash"] and "hunter2" not in json.dumps(server.outputs[0].redacted)


def test_client_stops_when_the_server_is_unreachable(server):
    env = {**server.env(), hook_server.URL_ENV: "http://127.0.0.1:9/redact"}
    assert stopped(call_client(bash_event("pw=hunter2"), env))


def test_client_stops_without_server_settings():
    assert stopped(call_client(bash_event("pw=hunter2"), {}))


def test_client_stops_on_bad_token(server):
    assert stopped(call_client(bash_event("pw=hunter2"), {**server.env(), hook_server.TOKEN_ENV: "wrong"}))


def test_client_stops_on_redaction_error():
    def boom(s):
        raise ScanAbort("line 1, column 4: SECRET")
    with hook_server.HookServer(boom, 100, 10_000, 5) as srv:
        assert stopped(call_client(bash_event("pw=hunter2"), srv.env()))
        assert srv.errors == ["Bash: line 1, column 4: SECRET"]


def test_client_gives_up_before_claude_codes_timeout():
    """A hook that Claude Code times out lets the raw output through, so the client must stop first."""
    def slow(s):
        time.sleep(5)
        return s
    with hook_server.HookServer(slow, 100, 10_000, 1) as srv:
        start = time.monotonic()
        assert stopped(call_client(bash_event("pw=hunter2"), srv.env()))
        assert time.monotonic() - start < 5


@pytest.mark.parametrize("response", [
    {"stdout": "iVBORw0KGgo=", "stderr": "", "interrupted": False, "isImage": True},
    {"type": "image", "file": {"base64": "iVBORw0KGgo=", "type": "image/png"}},
])
def test_client_stops_on_output_that_isnt_text(server, response):
    event = {"hook_event_name": "PostToolUse", "tool_name": "Read", "tool_input": {}, "tool_response": response}
    assert stopped(call_client(event, server.env())) and server.outputs == []


def test_read_of_images_and_pdfs_is_denied_before_it_runs(server):
    for path, denied in (("C:/x/shot.PNG", True), ("report.pdf", True), ("app.env", False)):
        event = {"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": {"file_path": path}}
        out = call_client(event, server.env())
        assert (out is not None and out["hookSpecificOutput"]["permissionDecision"] == "deny") is denied


# --- hook_server --------------------------------------------------------------
def test_truncate_to_input_limits():
    assert hook_server.truncate("a\nb\nc", 2, 100).startswith("a\nb\n[redact-ask: output truncated at 2 lines")
    assert hook_server.truncate("é" * 10, 100, 5).startswith("éé\n[redact-ask: output truncated at 5 bytes")
    assert hook_server.truncate("short", 100, 100) == "short"


# --- cloud_runner -------------------------------------------------------------
def test_claude_command_with_local_tools(tmp_path):
    local = cloud_runner.LocalRun(tmp_path, {}, 120)
    cmd = cloud_runner.claude_command("claude", "isolated", None, "id-1", resume=False, local=local)
    assert "--safe-mode" not in cmd                       # it would turn the redaction hook off
    assert cmd[cmd.index("--setting-sources") + 1] == ""
    assert cmd[cmd.index("--tools") + 1] == "Read,Grep,Glob,Bash,WebSearch,WebFetch"
    assert "Edit" not in cmd[cmd.index("--allowedTools") + 1]
    assert cmd[cmd.index("--system-prompt") + 1] == cloud_runner.LOCAL_INSTRUCTIONS
    settings = json.loads(cmd[cmd.index("--settings") + 1])
    [post] = settings["hooks"]["PostToolUse"]
    assert post["matcher"] == "*" and post["hooks"][0]["onFailure"] == "block"
    assert post["hooks"][0]["timeout"] == 120 + cloud_runner.HOOK_TIMEOUT_MARGIN
    assert settings["hooks"]["PreToolUse"][0]["matcher"] == "Read"
    assert settings["includeGitInstructions"] is False and settings["autoMemoryEnabled"] is False


def test_config_local_tools_options():
    c = config.from_dict({"local_tools": True, "hook_timeout_seconds": 30})
    assert c.local_tools is True and c.hook_timeout_seconds == 30
    for bad in ({"local_tools": "yes"}, {"hook_timeout_seconds": 0}):
        with pytest.raises(Exception):
            config.from_dict(bad)


# --- whole run ----------------------------------------------------------------
@pytest.fixture
def project(tmp_path, monkeypatch):
    folder = tmp_path / "project"
    folder.mkdir()
    (folder / "app.env").write_text((CORPUS / "app.env").read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.chdir(folder)
    monkeypatch.setenv("FAKE_TOOL_FILE", str(folder / "app.env"))
    return folder


def test_local_tools_run_redacts_tool_output(fake_cli, capsys, project, isolated_home):
    code, out, err = run(["-q", "what is in app.env?", "--local-tools", "--session", "L1"], capsys)
    assert code == 0, err
    [call] = fake_cli()
    assert call["cwd"] == str(project) and call["cwd_files"] == ["app.env"]      # user's folder, not emptied
    seen = call["hook"]["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    for v in ENV_VALUES:
        assert v not in seen and v not in out
    assert "<API_KEY_" in seen or "<CLOUD_SECRET_" in seen or "<SECRET_" in seen
    assert "local tools in" in err
    # what the model received is in the audit log, redacted
    lines = [json.loads(l) for l in (config.dirs().audit / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert [l["status"] for l in lines] == ["sending", "tool_output", "done"]
    assert lines[1]["tool"] == "Bash" and lines[1]["sent_text"][0] == seen


def test_restore_puts_back_values_found_by_tools(fake_cli, capsys, project):
    code, out, _ = run(["-q", "what is in app.env?", "--local-tools", "--session", "L2", "--restore"], capsys)
    assert code == 0 and "AKIAZ4X7Q2M5KD3LT7VB" in out                      # mapping saved from the hook
    code, out, _ = run(["-q", "and again", "--local-tools", "--session", "L2"], capsys)
    first, second = fake_cli()
    same = first["hook"]["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    assert second["hook"]["hookSpecificOutput"]["updatedToolOutput"]["stdout"] == same   # same placeholders


def test_hook_failure_stops_the_run(fake_cli, capsys, project, monkeypatch, isolated_home):
    from redactask import final_scan
    real_scan = final_scan.scan

    def scan(text, *a, **k):          # the prompt passes; text from app.env never does
        if "APP_ENV" in text:
            raise ScanAbort("line 1, column 1: SECRET")
        return real_scan(text, *a, **k)
    monkeypatch.setattr(final_scan, "scan", scan)
    code, out, err = run(["-q", "what is in app.env?", "--local-tools", "--session", "L3"], capsys)
    [call] = fake_cli()
    assert code == 5 and stopped(call["hook"]) and out == ""
    assert "stopped the run" in err and "line 1, column 1: SECRET" in err
    lines = [json.loads(l) for l in (config.dirs().audit / "audit.jsonl").read_text(encoding="utf-8").splitlines()]
    assert lines[-1]["status"] == "error"


def test_local_tools_needs_claude(fake_cli, capsys, project):
    code, _, err = run(["-q", "q", "--local-tools", "--to", "copilot"], capsys)
    assert code == 2 and "Claude Code only" in err and fake_cli() == []


def test_without_local_tools_nothing_changes(fake_cli, capsys, project):
    code, _, _ = run(["-q", "q", "--session", "L4"], capsys)
    [call] = fake_cli()
    assert code == 0 and "--settings" not in call["argv"] and "--safe-mode" in call["argv"]
    assert call["cwd_files"] == [] and call["hook"] is None
