"""Stand-in for `claude` / `copilot` in tests. Records what it received; never calls anything.

With --settings (a --local-tools run) and FAKE_TOOL_FILE set, it simulates one Bash call
(`cat FAKE_TOOL_FILE`) by running the PostToolUse hook command from the settings, as Claude Code
would, and records what the hook gave back. The answer then includes the tool output the model saw.
"""
import json
import os
import subprocess
import sys


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
    if hook is not None and hook.get("continue") is False:
        print(json.dumps({"type": "result", "is_error": False, "result": "", "terminal_reason": "hook_stopped"}))
        return 0
    answer = os.environ.get("FAKE_CLI_ANSWER", "Looks like <USER_1> failed from <IP_1>.")
    if hook is not None:
        answer += "\nTool output seen:\n" + hook["hookSpecificOutput"]["updatedToolOutput"]["stdout"]
    sid = None
    for flag in ("--session-id", "--resume"):
        if flag in argv:
            sid = argv[argv.index(flag) + 1]
    if "--output-format" in argv:      # claude
        print(json.dumps({"type": "result", "is_error": False, "result": answer, "session_id": sid}))
    else:                              # copilot -s
        print(answer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
