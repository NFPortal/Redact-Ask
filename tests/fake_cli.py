"""Stand-in for `claude` / `copilot` in tests. Records what it received; never calls anything.

With --settings (a --local-tools run) and FAKE_TOOL_FILE set, it simulates one Bash call
(`cat FAKE_TOOL_FILE`) by running the PostToolUse hook command from the settings, as Claude Code
would, and records what the hook gave back. The answer then includes the tool output the model saw.

Output is the event stream each CLI writes: Claude Code stream-json, Copilot CLI --output-format json.
With FAKE_CLI_OLD=1 it behaves like an older CLI that doesn't know the live-view options.
"""
import json
import os
import subprocess
import sys

NEW_OPTIONS = ("--include-partial-messages", "--forward-subagent-text", "--thinking-display")


def emit(event):
    print(json.dumps(event), flush=True)


def claude_stream(answer, sid, hook, stopped):
    emit({"type": "system", "subtype": "init", "session_id": sid})
    if hook is not None:
        emit({"type": "assistant", "parent_tool_use_id": None, "message": {"id": "msg_1", "content": [
            {"type": "thinking", "thinking": "Looking at the file."},
            {"type": "tool_use", "id": "tu_1", "name": "Bash", "input": {"command": "cat x"}}]}})
        output = "" if stopped else hook["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
        emit({"type": "user", "parent_tool_use_id": None, "message": {"content": [
            {"type": "tool_result", "tool_use_id": "tu_1", "content": output}]}})
    if stopped:
        emit({"type": "result", "is_error": False, "result": "", "terminal_reason": "hook_stopped"})
        return
    emit({"type": "assistant", "parent_tool_use_id": None,
          "message": {"id": "msg_2", "content": [{"type": "text", "text": answer}]}})
    emit({"type": "result", "is_error": False, "result": answer, "session_id": sid, "num_turns": 1})


def copilot_stream(answer, sid):
    emit({"type": "assistant.reasoning", "data": {"reasoningId": "r1", "content": "Looking at the log."}})
    emit({"type": "assistant.message", "data": {"messageId": "m1", "content": answer}})
    emit({"type": "result", "sessionId": sid, "exitCode": 0, "usage": {"premiumRequests": 1}})


def run_hook(argv):
    """The PostToolUse hook's JSON output for one simulated Bash call (None if it printed nothing)."""
    settings = json.loads(argv[argv.index("--settings") + 1])
    command = settings["hooks"]["PostToolUse"][0]["hooks"][0]["command"]
    with open(os.environ["FAKE_TOOL_FILE"], encoding="utf-8") as f:
        content = f.read()
    event = {"hook_event_name": "PostToolUse", "tool_name": "Bash", "tool_input": {"command": "cat x"},
             "tool_response": {"stdout": content, "stderr": "", "interrupted": False, "isImage": False}}
    proc = subprocess.run(command, shell=True, input=json.dumps(event).encode("utf-8"), capture_output=True)
    return json.loads(proc.stdout) if proc.stdout.strip() else None


def main():
    argv = sys.argv[1:]
    old = os.environ.get("FAKE_CLI_OLD") == "1"
    unknown = [a for a in argv if a in NEW_OPTIONS] if old else []
    if old and "json" in argv:         # copilot before --output-format json
        unknown.append("--output-format")
    if unknown:
        print(f"error: unknown option '{unknown[0]}'", file=sys.stderr)
        return 1
    prompt = sys.stdin.buffer.read().decode("utf-8")
    hook = run_hook(argv) if "--settings" in argv and os.environ.get("FAKE_TOOL_FILE") else None
    log = os.environ.get("FAKE_CLI_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "cwd_files": os.listdir("."),
                                "stdin": prompt, "hook": hook}) + "\n")
    if os.environ.get("FAKE_CLI_FAIL") == "1":
        print("simulated failure", file=sys.stderr)
        return 1
    stopped = hook is not None and hook.get("continue") is False
    answer = os.environ.get("FAKE_CLI_ANSWER", "Looks like <USER_1> failed from <IP_1>.")
    if hook is not None and not stopped:
        answer += "\nTool output seen:\n" + hook["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    sid = None
    for flag in ("--session-id", "--resume"):
        if flag in argv:
            sid = argv[argv.index(flag) + 1]
    if "stream-json" in argv:          # claude
        claude_stream(answer, sid, hook, stopped)
    elif "json" in argv:               # copilot --output-format json
        copilot_stream(answer, sid)
    else:                              # older copilot -s
        print(answer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
