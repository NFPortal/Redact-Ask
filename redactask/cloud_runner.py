"""[15] Send redacted text to Claude Code or Copilot CLI (SPEC: cloud_runner.py).

The only script that sends data off the machine. It receives only redacted text and never
sees the mapping or real values. The CLI runs in an empty per-session folder with web
tools only, and the prompt goes through stdin.

With --local-tools (Claude only), the CLI instead runs in the user's current folder with
read-only local tools, and a PostToolUse hook (hook_client.py, talking to hook_server.py)
redacts every tool result before the model sees it.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path

from .models import CloudError


class HookStopped(CloudError):
    """The redaction hook ended the run (fail closed); never retried as a new conversation."""


INSTRUCTIONS = (
    "You are helping analyze logs, code or configuration that were redacted on the user's machine before "
    "being sent to you. Values written like <USER_1>, <HOST_2>, <API_KEY_1> or <IP_3 in SUBNET_1> are "
    "placeholders: each one always stands for the same real value, and the same value always gets the same "
    "placeholder. The user will see the real values substituted into your answer. When you refer to a "
    "redacted value, write its placeholder exactly as it appears (for an IP, <IP_3> is enough). Never try to "
    "guess the real values. You have no access to the user's files or shell. Answer the question that "
    "follows '### QUESTION', using the text above it."
)

LOCAL_INSTRUCTIONS = (
    "You are helping analyze logs, code or configuration on the user's machine. Everything you see, "
    "including the output of every tool you run, was redacted on the user's machine first. Values written "
    "like <USER_1>, <HOST_2>, <API_KEY_1> or <IP_3 in SUBNET_1> are placeholders: each one always stands "
    "for the same real value, and the same value always gets the same placeholder. The user will see the "
    "real values substituted into your answer. When you refer to a redacted value, write its placeholder "
    "exactly as it appears (for an IP, <IP_3> is enough). Never try to guess or recover the real values. "
    "You can read files, search and run read-only shell commands in the working folder. The files hold "
    "the real values, not the placeholders, so searching for a placeholder finds nothing: search by key "
    "name or pattern instead (for example 'API_KEY=' rather than '<API_KEY_1>'). A path with a "
    "placeholder in it can't be opened. Images and PDFs can't be read. Do not modify files. Answer the "
    "question that follows '### QUESTION', using the text above it and what you find."
)

CLAUDE_WEB_TOOLS = "WebSearch,WebFetch"
CLAUDE_LOCAL_TOOLS = "Read,Grep,Glob,Bash,WebSearch,WebFetch"
COPILOT_WEB_TOOLS = ["web_fetch"]
HOOK_CLIENT = Path(__file__).resolve().parent / "hook_client.py"
HOOK_TIMEOUT_MARGIN = 60   # seconds Claude Code waits beyond the client's own timeout (Python start-up)


@dataclass
class LocalRun:
    """--local-tools: where the CLI runs and what the redaction hook needs."""
    cwd: Path                  # the user's folder; never emptied
    env: dict[str, str]        # hook_server env(): URL, token and timeout for hook_client.py
    hook_timeout: int          # seconds; hook_client.py gives up after this and stops the run


@dataclass
class CloudResult:
    answer: str
    conversation_id: str
    new_conversation: bool
    warnings: list[str]


def build_prompt(redacted_text: str, tool: str) -> str:
    """The exact text sent on stdin (logged by audit_log before sending)."""
    if tool == "copilot":
        # Copilot CLI has no system-prompt option; the fixed instructions go first in the message.
        return f"{INSTRUCTIONS}\n\n{redacted_text}"
    return redacted_text


def _exe(tool: str) -> str:
    path = shutil.which(tool)
    if not path:
        hint = ("Install Claude Code and run 'claude' once to log in." if tool == "claude"
                else "Install it with 'npm install -g @github/copilot' and run 'copilot' once to log in.")
        raise CloudError(f"'{tool}' was not found on PATH. {hint}")
    return path


def _prepare_workdir(workdir: Path) -> None:
    """The working folder must exist and be empty, so there is nothing local for the CLI to see."""
    workdir.mkdir(parents=True, exist_ok=True)
    for child in workdir.iterdir():
        if child.is_dir():
            shutil.rmtree(child, ignore_errors=True)
        else:
            child.unlink(missing_ok=True)


def hook_settings(hook_timeout: int) -> str:
    """--settings JSON for a --local-tools run: the redaction hooks, plus no git status or memory."""
    command = {"type": "command",
               "command": f'"{Path(sys.executable).as_posix()}" -I "{HOOK_CLIENT.as_posix()}"',
               "timeout": hook_timeout + HOOK_TIMEOUT_MARGIN, "onFailure": "block"}
    return json.dumps({
        "hooks": {"PostToolUse": [{"matcher": "*", "hooks": [command]}],
                  "PreToolUse": [{"matcher": "Read", "hooks": [command]}]},
        "includeGitInstructions": False,
        "autoMemoryEnabled": False,
    })


def claude_command(exe: str, context: str, model: str | None, conversation_id: str, resume: bool,
                   local: LocalRun | None = None) -> list[str]:
    tools = CLAUDE_LOCAL_TOOLS if local else CLAUDE_WEB_TOOLS
    instructions = LOCAL_INSTRUCTIONS if local else INSTRUCTIONS
    cmd = [exe, "-p", "--output-format", "json",
           "--tools", tools, "--allowedTools", tools,
           "--strict-mcp-config", "--disable-slash-commands"]
    if context == "isolated" and local:
        # --safe-mode would also turn off the redaction hook, so it is left out; --setting-sources ""
        # still keeps CLAUDE.md, memories, plugins and user/project settings and hooks out.
        cmd += ["--setting-sources", "", "--system-prompt", instructions]
    elif context == "isolated":
        # No CLAUDE.md, memories, hooks, plugins, user/project settings or MCP servers; login only.
        cmd += ["--safe-mode", "--setting-sources", "", "--system-prompt", instructions]
    else:
        cmd += ["--append-system-prompt", instructions]
    if local:
        cmd += ["--settings", hook_settings(local.hook_timeout)]
    if model:
        cmd += ["--model", model]
    cmd += ["--resume", conversation_id] if resume else ["--session-id", conversation_id]
    return cmd


def copilot_command(exe: str, context: str, model: str | None, conversation_id: str) -> list[str]:
    cmd = [exe, "-s", "--no-auto-update", "--no-ask-user", "--no-remote", "--disallow-temp-dir",
           "--available-tools", *COPILOT_WEB_TOOLS, "--allow-tool", *COPILOT_WEB_TOOLS,
           "--session-id", conversation_id]
    if context == "isolated":
        cmd += ["--no-custom-instructions", "--disable-builtin-mcps"]
    if model:
        cmd += ["--model", model]
    return cmd


def _run(cmd: list[str], prompt: str, workdir: Path, timeout: int,
         env: dict[str, str] | None = None) -> subprocess.CompletedProcess:
    try:
        return subprocess.run(cmd, input=prompt.encode("utf-8"), cwd=workdir, capture_output=True,
                              timeout=timeout, env={**os.environ, **env} if env else None)
    except subprocess.TimeoutExpired as e:
        raise CloudError(f"The cloud CLI did not answer within {timeout} s (cloud_timeout_seconds).") from e
    except OSError as e:
        raise CloudError(f"Couldn't start {cmd[0]}: {e}") from e


def _decode(b: bytes) -> str:
    return b.decode("utf-8", errors="replace").strip()


def _run_claude(prompt, context, model, conversation_id, workdir, timeout, local=None) -> tuple[str, str]:
    exe = _exe("claude")
    resume = conversation_id is not None
    cid = conversation_id or str(uuid.uuid4())
    proc = _run(claude_command(exe, context, model, cid, resume, local), prompt, workdir, timeout,
                local.env if local else None)
    out, err = _decode(proc.stdout), _decode(proc.stderr)
    try:
        data = json.loads(out.splitlines()[-1]) if out else {}
    except (json.JSONDecodeError, IndexError):
        data = {}
    if data.get("terminal_reason") == "hook_stopped":
        raise HookStopped("The redaction hook stopped the run: a tool's output couldn't be redacted, so it "
                          "was withheld from the model.")
    if proc.returncode != 0 or data.get("is_error") or "result" not in data:
        detail = data.get("result") or err or out or f"exit code {proc.returncode}"
        raise CloudError(f"Claude Code failed: {detail[:500]}")
    return data["result"], data.get("session_id") or cid


def _run_copilot(prompt, context, model, conversation_id, workdir, timeout, local=None) -> tuple[str, str]:
    if local:
        raise CloudError("--local-tools works with Claude Code only.")
    exe = _exe("copilot")
    cid = conversation_id or str(uuid.uuid4())
    proc = _run(copilot_command(exe, context, model, cid), prompt, workdir, timeout)
    out, err = _decode(proc.stdout), _decode(proc.stderr)
    if proc.returncode != 0 or not out:
        raise CloudError(f"Copilot CLI failed: {(err or out or f'exit code {proc.returncode}')[:500]}")
    return out, cid


def run(prompt: str, tool: str, model: str | None, conversation_id: str | None, workdir: Path,
        context: str, timeout: int, local: LocalRun | None = None) -> CloudResult:
    if local:
        workdir = local.cwd          # the user's folder: never emptied
    else:
        _prepare_workdir(workdir)
    runner = _run_claude if tool == "claude" else _run_copilot
    warnings: list[str] = []
    if conversation_id:
        try:
            answer, cid = runner(prompt, context, model, conversation_id, workdir, timeout, local)
            return CloudResult(answer, cid, False, warnings)
        except HookStopped:
            raise
        except CloudError as e:
            # The saved conversation may be gone (deleted on the cloud side or locally); start a new one.
            warnings.append(f"Couldn't continue the previous {tool} conversation ({e.message[:120]}); "
                            f"started a new one.")
    answer, cid = runner(prompt, context, model, None, workdir, timeout, local)
    return CloudResult(answer, cid, True, warnings)
