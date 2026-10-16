"""Stand-in for `claude` / `copilot` in tests. Records what it received; never calls anything."""
import json
import os
import sys


def main():
    argv = sys.argv[1:]
    prompt = sys.stdin.buffer.read().decode("utf-8")
    log = os.environ.get("FAKE_CLI_LOG")
    if log:
        with open(log, "a", encoding="utf-8") as f:
            f.write(json.dumps({"argv": argv, "cwd": os.getcwd(), "cwd_files": os.listdir("."),
                                "stdin": prompt}) + "\n")
    if os.environ.get("FAKE_CLI_FAIL") == "1":
        print("simulated failure", file=sys.stderr)
        return 1
    answer = os.environ.get("FAKE_CLI_ANSWER", "Looks like <USER_1> failed from <IP_1>.")
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
