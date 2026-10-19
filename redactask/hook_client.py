"""[20] Claude Code hook for --local-tools runs (SPEC: hook_client.py).

Claude Code runs this script (standard library only, so it starts fast) for:
  - PostToolUse (every tool): send each string in the tool's output to hook_server.py and give
    Claude the redacted copy (`updatedToolOutput`, same structure as the original).
  - PreToolUse (Read): refuse to open images and PDFs, whose content can't be redacted as text.

Fail closed: if anything goes wrong (server unreachable, redaction error, timeout, output that
isn't text) the hook stops the whole run with `continue: false`, so the unredacted output never
reaches the model. Checked against Claude Code 2.1.303: a hook that *times out* lets the original
output through even with onFailure "block", so this script gives up on its own well before
Claude Code's hook timeout.

The stop reason stays in the conversation, so it never contains tool output or error details.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request

URL_ENV = "REDACT_ASK_HOOK_URL"
TOKEN_ENV = "REDACT_ASK_HOOK_TOKEN"
TIMEOUT_ENV = "REDACT_ASK_HOOK_TIMEOUT"
TOKEN_HEADER = "X-Redact-Ask-Token"

# Read can return these as images or documents; there is no text to redact.
BINARY_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".webp", ".bmp", ".ico", ".tif", ".tiff", ".heic",
                     ".pdf"}
# Short enum values in the tool's output structure, never sensitive (e.g. Read's "type": "text").
SKIP_KEYS = {"type", "mode"}

STOP_REASON = "redact-ask stopped the run: a tool's output could not be redacted, so it was withheld."


def _stop() -> dict:
    return {"continue": False, "stopReason": STOP_REASON, "suppressOutput": True}


def _is_binary(value) -> bool:
    """True if the output holds non-text content (an image or document)."""
    if isinstance(value, dict):
        if value.get("isImage") is True or "base64" in value:
            return True
        if value.get("type") in ("image", "document", "pdf"):
            return True
        return any(_is_binary(v) for v in value.values())
    if isinstance(value, list):
        return any(_is_binary(v) for v in value)
    return False


def collect(value, out: list[str], key: str | None = None) -> None:
    """Every string in the output, in a fixed walk order (rebuild uses the same order)."""
    if isinstance(value, str):
        if key not in SKIP_KEYS:
            out.append(value)
    elif isinstance(value, list):
        for v in value:
            collect(v, out)
    elif isinstance(value, dict):
        for k, v in value.items():
            collect(v, out, k)


def rebuild(value, redacted: list[str], key: str | None = None):
    """Same structure as value, with each collected string replaced by the next redacted one."""
    if isinstance(value, str):
        return value if key in SKIP_KEYS else redacted.pop(0)
    if isinstance(value, list):
        return [rebuild(v, redacted) for v in value]
    if isinstance(value, dict):
        return {k: rebuild(v, redacted, k) for k, v in value.items()}
    return value


def _redact(tool: str, strings: list[str]) -> list[str]:
    url, token = os.environ[URL_ENV], os.environ[TOKEN_ENV]
    timeout = float(os.environ.get(TIMEOUT_ENV, "120"))
    body = json.dumps({"tool": tool, "strings": strings}).encode("utf-8")
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json", TOKEN_HEADER: token})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        out = json.loads(resp.read().decode("utf-8"))["strings"]
    if not isinstance(out, list) or len(out) != len(strings) or not all(isinstance(s, str) for s in out):
        raise ValueError("bad reply from the redaction server")
    return out


def post_tool_use(event: dict) -> dict:
    response = event.get("tool_response")
    if _is_binary(response):
        return _stop()
    strings: list[str] = []
    collect(response, strings)
    redacted = _redact(event.get("tool_name", "?"), strings)
    return {"hookSpecificOutput": {"hookEventName": "PostToolUse",
                                   "updatedToolOutput": rebuild(response, list(redacted))}}


def pre_tool_use(event: dict) -> dict | None:
    if event.get("tool_name") != "Read":
        return None
    path = str((event.get("tool_input") or {}).get("file_path", ""))
    if os.path.splitext(path)[1].lower() in BINARY_EXTENSIONS:
        return {"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": "deny",
            "permissionDecisionReason": "redact-ask: images and PDFs can't be redacted, so they can't be read "
                                        "in this session. Work from text files instead."}}
    return None


def handle(event: dict) -> dict | None:
    name = event.get("hook_event_name")
    if name == "PostToolUse":
        return post_tool_use(event)
    if name == "PreToolUse":
        return pre_tool_use(event)
    return None


def main() -> int:
    try:
        event = json.loads(sys.stdin.buffer.read().decode("utf-8"))
        result = handle(event)
    except Exception as e:      # timeouts, a stopped server, HTTP errors, malformed input, bugs
        print(f"redact-ask hook: {type(e).__name__}", file=sys.stderr)
        result = _stop()
    if result is not None:
        sys.stdout.write(json.dumps(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
