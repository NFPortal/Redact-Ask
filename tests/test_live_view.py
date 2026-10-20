"""[21] live_view: the model's thinking, text and tool calls shown while the cloud CLI works."""
import io

from redactask import cloud_runner, config, live_view
from test_end_to_end import fake_cli, run  # noqa: F401  (fixture)


def view(color=False):
    buf = io.StringIO()
    return live_view.View(stream=buf, color=color), buf


def delta(msg, index, kind, text=None, parent=None):
    """A Claude Code stream_event for one content block of a partial message."""
    if text is None:
        event = {"type": "content_block_start", "index": index, "content_block": {"type": kind}}
    elif text == "":
        event = {"type": "content_block_stop", "index": index}
    else:
        key = "thinking" if kind == "thinking" else "text"
        event = {"type": "content_block_delta", "index": index, "delta": {"type": f"{key}_delta", key: text}}
    return {"type": "stream_event", "event": event, "api_message_id": msg, "parent_tool_use_id": parent}


def assistant(msg, content, parent=None):
    return {"type": "assistant", "message": {"id": msg, "content": content}, "parent_tool_use_id": parent}


def tool_result(tid, content, parent=None, error=False):
    return {"type": "user", "parent_tool_use_id": parent, "message": {"content": [
        {"type": "tool_result", "tool_use_id": tid, "content": content, "is_error": error}]}}


def test_claude_stream_shows_thinking_text_tools_and_subagents():
    v, buf = view()
    events = live_view.ClaudeEvents(v)
    for ev in [
        {"type": "system", "subtype": "init"},
        delta("m1", 0, "thinking"), delta("m1", 0, "thinking", "Check the "), delta("m1", 0, "thinking", "log.\nThen grep."),
        assistant("m1", [{"type": "thinking", "thinking": "Check the log.\nThen grep."}]),
        delta("m1", 0, "thinking", ""),
        assistant("m1", [{"type": "tool_use", "id": "t1", "name": "Grep", "input": {"pattern": "ERROR", "path": "."}}]),
        tool_result("t1", "a.log:1:ERROR <USER_1>\na.log:2:ERROR\na.log:3:x\na.log:4:y"),
        assistant("m2", [{"type": "tool_use", "id": "a1", "name": "Agent",
                          "input": {"description": "Find config", "subagent_type": "Explore", "prompt": "..."}}]),
        {"type": "system", "subtype": "task_started", "tool_use_id": "a1", "description": "Find config"},
        {"type": "user", "parent_tool_use_id": "a1", "message": {"content": [{"type": "text", "text": "..."}]}},
        assistant("s1", [{"type": "tool_use", "id": "t2", "name": "Read", "input": {"file_path": "app.env"}}], "a1"),
        tool_result("t2", "", "a1", error=True),
        assistant("s2", [{"type": "text", "text": "Found it."}], "a1"),
        tool_result("a1", [{"type": "text", "text": "report"}]),
        delta("m3", 0, "text"), delta("m3", 0, "text", "The answer "), delta("m3", 0, "text", "is <HOST_1>."),
        assistant("m3", [{"type": "text", "text": "The answer is <HOST_1>."}]),
        delta("m3", 0, "text", ""),
        {"type": "result", "result": "The answer is <HOST_1>.", "num_turns": 3, "total_cost_usd": 0.01},
    ]:
        events.feed(ev)
    out = buf.getvalue()
    assert "○ Check the log.\n  Then grep.\n" in out                  # thinking, streamed once
    assert out.count("Check the log.") == 1
    assert "● Grep(ERROR, in .)\n" in out
    assert "└ a.log:1:ERROR <USER_1>\n  a.log:2:ERROR\n  a.log:3:x\n  … +1 lines\n" in out
    assert "● Agent(Explore: Find config)\n" in out
    assert "│ ● Read(app.env)\n" in out and "│ └ (no output)\n" in out    # subagent calls are nested
    assert "│ ● Found it.\n" in out
    assert "└ Agent finished\n" in out
    assert out.count("The answer is <HOST_1>.") == 1
    assert "■ Done · 3 turns · $0.0100" in out
    assert events.result["result"] == "The answer is <HOST_1>."


def test_claude_thinking_without_text_is_still_shown():
    v, buf = view()
    events = live_view.ClaudeEvents(v)
    events.feed(delta("m1", 0, "thinking"))
    events.feed(delta("m1", 0, "thinking", ""))  # stop
    events.feed(assistant("m1", [{"type": "thinking", "thinking": ""}]))
    assert "○ Thinking…" in buf.getvalue()


def test_terminal_control_characters_are_never_written():
    v, buf = view()
    events = live_view.ClaudeEvents(v)
    events.feed(assistant("m1", [{"type": "text", "text": "hi \x1b]0;pwned\x07\x1b[2Jthere"}]))
    events.feed(assistant("m1", [{"type": "tool_use", "id": "t", "name": "Bash", "input": {"command": "x\x1b[31m"}}]))
    out = buf.getvalue()
    assert "\x1b" not in out and "\x07" not in out and "hi ]0;pwned[2Jthere" in out


def test_colors_only_when_asked():
    v, buf = view(color=True)
    v.tool_call("Bash", {"command": "ls"}, 0)
    assert "\x1b[1mBash\x1b[0m" in buf.getvalue()
    assert live_view.supports_color(io.StringIO()) is False          # not a terminal


def test_disabled_view_writes_nothing():
    buf = io.StringIO()
    events = live_view.ClaudeEvents(live_view.View(enabled=False, stream=buf))
    events.feed(assistant("m1", [{"type": "text", "text": "hello"}]))
    events.feed({"type": "result", "result": "hello"})
    assert buf.getvalue() == "" and events.result["result"] == "hello"


def test_copilot_stream_and_answer():
    v, buf = view()
    events = live_view.CopilotEvents(v)
    for ev in [
        {"type": "assistant.reasoning_delta", "data": {"reasoningId": "r1", "deltaContent": "Need "}},
        {"type": "assistant.reasoning_delta", "data": {"reasoningId": "r1", "deltaContent": "the page."}},
        {"type": "assistant.message", "data": {"messageId": "m0", "content": "",
                                               "toolRequests": [{"toolCallId": "c1", "name": "web_fetch"}]}},
        {"type": "tool.execution_start", "data": {"toolCallId": "c1", "toolName": "web_fetch",
                                                  "arguments": {"url": "https://example.com"}}},
        {"type": "tool.execution_complete", "data": {"toolCallId": "c1", "success": False,
                                                     "error": {"message": "Permission denied"}}},
        {"type": "assistant.reasoning", "data": {"reasoningId": "r1", "content": "Need the page."}},
        {"type": "assistant.message_delta", "data": {"messageId": "m1", "deltaContent": "Couldn't "}},
        {"type": "assistant.message_delta", "data": {"messageId": "m1", "deltaContent": "fetch it."}},
        {"type": "assistant.message", "data": {"messageId": "m1", "content": "Couldn't fetch it."}},
        {"type": "result", "exitCode": 0, "usage": {"premiumRequests": 1}},
    ]:
        events.feed(ev)
    out = buf.getvalue()
    assert "○ Need the page.\n" in out and out.count("Need the page.") == 1
    assert "● web_fetch(https://example.com)\n" in out
    assert "└ Permission denied\n" in out
    assert out.count("Couldn't fetch it.") == 1
    assert "■ Done · 1 premium request" in out
    assert events.answer == "Couldn't fetch it."


# --- commands and whole runs ---------------------------------------------------------------------
def test_commands_ask_for_event_streams():
    cmd = cloud_runner.claude_command("claude", "isolated", None, "id-1", resume=False)
    assert cmd[cmd.index("--output-format") + 1] == "stream-json" and "--verbose" in cmd
    assert "--include-partial-messages" in cmd and cmd[cmd.index("--thinking-display") + 1] == "summarized"
    old = cloud_runner.claude_command("claude", "isolated", None, "id-1", resume=False, live=False)
    assert "--include-partial-messages" not in old and "stream-json" in old
    cmd = cloud_runner.copilot_command("copilot", "isolated", None, "id-1")
    assert cmd[cmd.index("--output-format") + 1] == "json"


def test_live_view_on_stderr_answer_alone_on_stdout(fake_cli, capsys):
    code, out, err = run(["some log text", "-q", "why?", "--session", "v1"], capsys)
    assert code == 0, err
    assert out == "Looks like <USER_1> failed from <IP_1>.\n"
    assert "● Looks like <USER_1> failed from <IP_1>." in err and "■ Done · 1 turn" in err


def test_live_view_can_be_turned_off(fake_cli, capsys, monkeypatch):
    code, out, err = run(["some log text", "-q", "why?", "--session", "v2", "--no-live"], capsys)
    assert code == 0 and "■" not in err and out.startswith("Looks like")
    monkeypatch.setattr(config, "load", lambda: config.from_dict({"live_view": False}))
    code, _, err = run(["some log text", "-q", "why?", "--session", "v3"], capsys)
    assert code == 0 and "■" not in err
    code, _, err = run(["some log text", "-q", "why?", "--session", "v4", "--live"], capsys)
    assert code == 0 and "■ Done" in err


def test_copilot_run_uses_the_json_stream(fake_cli, capsys):
    code, out, err = run(["some log text", "-q", "why?", "--session", "v5", "--to", "copilot"], capsys)
    assert code == 0, err
    assert out == "Looks like <USER_1> failed from <IP_1>.\n"
    assert "○ Looking at the log." in err


def test_older_clis_still_answer(fake_cli, capsys, monkeypatch):
    monkeypatch.setenv("FAKE_CLI_OLD", "1")
    code, out, err = run(["some log text", "-q", "why?", "--session", "v6"], capsys)
    assert code == 0 and out.startswith("Looks like"), err
    [call] = fake_cli()                       # the first try was refused before it was logged
    assert "--include-partial-messages" not in call["argv"] and "stream-json" in call["argv"]
    code, out, err = run(["some log text", "-q", "why?", "--session", "v7", "--to", "copilot"], capsys)
    assert code == 0 and out.startswith("Looks like"), err
    assert "--output-format" not in fake_cli()[-1]["argv"]


def test_local_tools_run_shows_redacted_tool_output(fake_cli, capsys, tmp_path, monkeypatch):
    folder = tmp_path / "p"
    folder.mkdir()
    (folder / "app.env").write_text("DB_PASSWORD=Xq7!vR2pLm9w\n", encoding="utf-8")
    monkeypatch.chdir(folder)
    monkeypatch.setenv("FAKE_TOOL_FILE", str(folder / "app.env"))
    code, out, err = run(["-q", "what is in app.env?", "--local-tools", "--session", "v8"], capsys)
    assert code == 0, err
    assert "● Bash(cat x)" in err and "└ DB_PASSWORD=<" in err
    assert "Xq7!vR2pLm9w" not in err and "Xq7!vR2pLm9w" not in out


def test_streamed_blocks_keep_inner_blank_lines_but_not_trailing_ones():
    v, buf = view()
    v.open("k", "text", 0)
    for piece in ["\nFirst", " line.\n\n", "Second.\n\n"]:
        v.chunk("k", piece)
    v.close("k")
    v.line("tool", "next", 0)
    assert buf.getvalue() == "● First line.\n\n  Second.\n● next\n"
