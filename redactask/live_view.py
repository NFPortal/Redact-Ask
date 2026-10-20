"""[21] Show what the cloud CLI is doing while it works (SPEC: live_view.py).

Reads the CLI's JSON event stream one line at a time (Claude Code `--output-format stream-json`,
Copilot CLI `--output-format json`), prints the model's thinking, text, tool calls, tool results and
subagents to stderr as they happen, and keeps the final answer and result for cloud_runner.

Everything shown is what the model saw or wrote, so it carries placeholders, never restored values.
Output goes to stderr, so stdout stays the answer alone. Colors are used only on a terminal that
supports them (any POSIX terminal; Windows Terminal, PowerShell and cmd once VT mode is on), and
never with NO_COLOR or TERM=dumb.
"""
from __future__ import annotations

import json
import os
import re
import sys
import time

# Control characters (escape sequences included) from model or tool output are never written to
# the terminal; tabs and newlines are kept.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")

RESET, BOLD, DIM, RED, GREEN, CYAN = "\x1b[0m", "\x1b[1m", "\x1b[2m", "\x1b[31m", "\x1b[32m", "\x1b[36m"
GLYPHS = {"tool": "●", "text": "●", "think": "○", "result": "└", "nest": "│", "done": "■"}
ASCII_GLYPHS = {"tool": "*", "text": "*", "think": "~", "result": "`-", "nest": "|", "done": "#"}

RESULT_LINES = 3          # tool result lines shown before "… +N lines"
LINE_CHARS = 160          # longest tool call / result line shown

AGENT_TOOLS = ("Agent", "Task")
TOOL_ARG = {"Bash": "command", "Read": "file_path", "Grep": "pattern", "Glob": "pattern", "WebFetch": "url",
            "WebSearch": "query", "web_fetch": "url", "Write": "file_path", "Edit": "file_path"}


def clean(text: str) -> str:
    return _CONTROL_RE.sub("", text.replace("\r\n", "\n"))


def _enable_windows_vt(stream) -> bool:
    """Turn on ANSI escape handling for this console (Windows 10+); False if it can't be."""
    try:
        import ctypes
        import msvcrt
        kernel32 = ctypes.windll.kernel32
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        return bool(mode.value & 0x4 or kernel32.SetConsoleMode(handle, mode.value | 0x4))
    except Exception:
        return False


def supports_color(stream) -> bool:
    if os.environ.get("NO_COLOR") or os.environ.get("TERM") == "dumb":
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    try:
        if not stream.isatty():
            return False
    except (AttributeError, ValueError):
        return False
    return _enable_windows_vt(stream) if sys.platform == "win32" else True


def _can_encode(stream, text: str) -> bool:
    encoding = getattr(stream, "encoding", None)
    if not encoding:
        return True               # an in-memory text stream
    try:
        text.encode(encoding)
        return True
    except (LookupError, UnicodeEncodeError):
        return False


class View:
    """Writes the live transcript. A disabled View writes nothing (the stream is still parsed)."""

    def __init__(self, enabled: bool = True, stream=None, color: bool | None = None):
        self.enabled = enabled
        self.stream = stream or sys.stderr
        self.color = supports_color(self.stream) if color is None else color
        self.glyphs = GLYPHS if _can_encode(self.stream, "".join(GLYPHS.values())) else ASCII_GLYPHS
        self.started = time.monotonic()
        self._block = None        # (key, depth, style) of the block being streamed
        self._block_written = False
        self._at_line_start = True
        self.written: set = set()  # keys of streamed blocks that had any text

    # -- low level -------------------------------------------------------------------------------
    def _style(self, text: str, style: str) -> str:
        return f"{style}{text}{RESET}" if self.color and style and text else text

    def _write(self, text: str) -> None:
        if not self.enabled or not text:
            return
        try:
            self.stream.write(text)
        except UnicodeEncodeError:
            self.stream.write(text.encode("ascii", "replace").decode("ascii"))
        self.stream.flush()
        self._at_line_start = text.endswith("\n")

    def _indent(self, depth: int) -> str:
        return self._style(f"{self.glyphs['nest']} ", DIM) * depth + "  "

    def _lines(self, glyph: str, text: str, depth: int, style: str, glyph_style: str) -> str:
        indent = self._indent(depth)
        first = self._style(f"{self.glyphs['nest']} ", DIM) * depth + self._style(glyph, glyph_style) + " "
        lines = text.split("\n")
        out = first + self._style(lines[0], style) + "\n"
        return out + "".join(indent + self._style(l, style) + "\n" for l in lines[1:])

    # -- blocks streamed piece by piece (thinking, text) -------------------------------------------
    def open(self, key, kind: str, depth: int) -> None:
        """Start a streamed block; nothing is written until its first non-empty piece."""
        self.close()
        self._block = (key, depth, kind)
        self._block_written = False
        self._held = ""

    def is_open(self, key) -> bool:
        return self._block is not None and self._block[0] == key

    def chunk(self, key, text: str) -> None:
        if self._block is None or self._block[0] != key:
            return
        # Newlines at the end wait for more text, so a block never ends with blank lines.
        text = self._held + clean(text)
        body = text.rstrip("\n")
        self._held, text = text[len(body):], body
        _, depth, kind = self._block
        style = DIM if kind == "think" else ""
        if not self._block_written:
            text = text.lstrip("\n")
        if not text:
            return
        if not self._block_written:
            self._block_written = True
            self.written.add(key)
            self._newline()
            glyph_style = DIM if kind == "think" else ""
            self._write(self._style(f"{self.glyphs['nest']} ", DIM) * depth
                        + self._style(self.glyphs[kind], glyph_style) + " ")
        indent = self._indent(depth)
        parts = text.split("\n")
        out = self._style(parts[0], style)
        for p in parts[1:]:
            out += "\n" + (indent + self._style(p, style) if p else "")
        if self._at_line_start and parts[0]:
            out = indent + out
        self._write(out)

    def close(self, key=None) -> bool:
        """End the streamed block (only if it is `key`, when given). True if any of it was written."""
        if self._block is None or (key is not None and self._block[0] != key):
            return False
        written = self._block[0] in self.written
        self._block = None
        self._newline()
        return written

    def _newline(self) -> None:
        if not self._at_line_start:
            self._write("\n")

    # -- whole lines -----------------------------------------------------------------------------
    def line(self, kind: str, text: str, depth: int = 0, style: str = "", glyph_style: str | None = None,
             cleaned: bool = False) -> None:
        """One event (a tool call, a result, a status). An open streamed block is ended first, so a
        line from a subagent or a tool never lands in the middle of the model's text.
        `cleaned`: the text was already passed through clean() (and may carry our own styling)."""
        if self._block is not None and self._block_written:
            self._newline()
            self._block_written = False      # if more of the block arrives, it starts a new line
        self._newline()
        glyph = self.glyphs[kind]
        self._write(self._lines(glyph, text if cleaned else clean(text), depth, style,
                                style if glyph_style is None else glyph_style))

    def tool_call(self, name: str, args, depth: int) -> None:
        label = self._style(clean(name), BOLD)
        summary = tool_summary(name, args)          # cleaned by _short()
        self.line("tool", f"{label}({summary})" if summary else label, depth, "",
                  CYAN if name in AGENT_TOOLS else GREEN, cleaned=True)

    def tool_result(self, text: str, depth: int, error: bool = False) -> None:
        self.line("result", result_summary(text), depth, RED if error else DIM)

    def done(self, text: str, error: bool = False) -> None:
        self.close()
        elapsed = f"{time.monotonic() - self.started:.1f}s"
        self.line("done", f"{text} · {elapsed}" if text else elapsed, 0, RED if error else DIM,
                  RED if error else GREEN)


def _short(text: str, limit: int = LINE_CHARS) -> str:
    text = " ".join(clean(text).split())
    return text if len(text) <= limit else text[:limit - 1] + "…"


def tool_summary(name: str, args) -> str:
    """`Bash(ls -la)`, `Read(app.env)`, `Agent(Explore: find the config)`."""
    if not isinstance(args, dict):
        return _short(str(args)) if args else ""
    if name in AGENT_TOOLS:
        kind = args.get("subagent_type")
        desc = args.get("description") or args.get("prompt") or ""
        return _short(f"{kind}: {desc}" if kind else desc)
    key = TOOL_ARG.get(name)
    if key and isinstance(args.get(key), str):
        extra = f", in {args['path']}" if name in ("Grep", "Glob") and isinstance(args.get("path"), str) else ""
        return _short(args[key] + extra)
    for v in args.values():
        if isinstance(v, str) and v:
            return _short(v)
    return _short(json.dumps(args, ensure_ascii=False)) if args else ""


def content_text(content) -> str:
    """Text of a tool result: a string, a list of {type: text} blocks, or a dict with content."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = [content_text(b.get("text", b.get("content", "")) if isinstance(b, dict) else b) for b in content]
        return "\n".join(p for p in parts if p)
    if isinstance(content, dict):
        for key in ("content", "text", "result", "message", "detailedContent"):
            if key in content:
                return content_text(content[key])
        return json.dumps(content, ensure_ascii=False)
    return "" if content is None else str(content)


def result_summary(text: str) -> str:
    lines = [l for l in clean(text).split("\n") if l.strip()]
    if not lines:
        return "(no output)"
    shown = [_short(l) for l in lines[:RESULT_LINES]]
    if len(lines) > RESULT_LINES:
        shown.append(f"… +{len(lines) - RESULT_LINES} lines")
    return "\n".join(shown)


class ClaudeEvents:
    """Claude Code stream-json: system, stream_event (partial messages), assistant, user, result."""

    def __init__(self, view: View):
        self.view = view
        self.result: dict | None = None
        self._blocks: dict = {}                   # (message id, index) -> "thinking" | "text"
        self._shown: set = set()                  # (message id, block type) already streamed as deltas
        self._tools: dict[str, int] = {}          # tool_use_id -> depth of the call
        self._agents: dict[str, int] = {}         # Agent tool_use_id -> depth of the call

    def _depth(self, parent) -> int:
        return self._agents.get(parent, -1) + 1 if parent else 0

    def feed(self, ev: dict) -> None:
        kind = ev.get("type")
        if kind == "stream_event":
            self._delta(ev)
        elif kind == "assistant":
            self._assistant(ev)
        elif kind == "user":
            self._user(ev)
        elif kind == "system":
            self._system(ev)
        elif kind == "result":
            self.result = ev
            self._done(ev)

    def _delta(self, ev: dict) -> None:
        e = ev.get("event") or {}
        msg_id = ev.get("api_message_id") or ""
        key = (msg_id, e.get("index"))
        if e.get("type") == "content_block_start":
            block = (e.get("content_block") or {}).get("type")
            if block in ("thinking", "text"):
                self._blocks[key] = block
                self.view.open(key, "think" if block == "thinking" else "text",
                               self._depth(ev.get("parent_tool_use_id")))
        elif e.get("type") == "content_block_delta":
            d = e.get("delta") or {}
            self.view.chunk(key, d.get("thinking") or d.get("text") or "")
            if key in self.view.written:
                self._shown.add((msg_id, self._blocks.get(key)))
        elif e.get("type") == "content_block_stop":
            self.view.close(key)

    def _assistant(self, ev: dict) -> None:
        msg = ev.get("message") or {}
        depth = self._depth(ev.get("parent_tool_use_id"))
        for b in msg.get("content") or []:
            kind = b.get("type")
            if kind == "tool_use":
                self._tools[b.get("id")] = depth
                if b.get("name") in AGENT_TOOLS:
                    self._agents[b.get("id")] = depth
                self.view.tool_call(b.get("name") or "?", b.get("input"), depth)
            elif (msg.get("id"), kind) in self._shown:
                continue                      # already shown piece by piece
            elif kind == "thinking":
                self.view.line("think", b.get("thinking") or "Thinking…", depth, DIM)
            elif kind == "redacted_thinking":
                self.view.line("think", "Thinking…", depth, DIM)
            elif kind == "text" and (b.get("text") or "").strip():
                self.view.line("text", b["text"].strip("\n"), depth)

    def _user(self, ev: dict) -> None:
        content = (ev.get("message") or {}).get("content")
        for b in content if isinstance(content, list) else []:
            if b.get("type") != "tool_result":
                continue          # a subagent's prompt; its Agent call is already shown
            tid = b.get("tool_use_id")
            depth = self._tools.get(tid, self._depth(ev.get("parent_tool_use_id")))
            text = content_text(b.get("content"))
            if tid in self._agents:
                text = "Agent finished" + (": " + text.split("\n", 1)[0] if b.get("is_error") else "")
            self.view.tool_result(text, depth, bool(b.get("is_error")))

    def _system(self, ev: dict) -> None:
        sub = ev.get("subtype")
        tid = ev.get("tool_use_id")
        if sub == "task_started" and tid not in self._agents:
            self.view.line("tool", f"Started: {_short(ev.get('description') or 'background task')}", 0, "", CYAN)
        elif sub == "task_progress" and ev.get("description"):
            self.view.line("result", _short(ev["description"]), self._agents.get(tid, -1) + 1, DIM)
        elif sub == "compact_boundary":
            self.view.line("result", "Conversation compacted", 0, DIM)
        elif sub == "api_retry":
            self.view.line("result", "API request failed; retrying…", 0, DIM)

    def _done(self, ev: dict) -> None:
        parts = []
        if ev.get("num_turns"):
            parts.append(f"{ev['num_turns']} turn{'s' if ev['num_turns'] != 1 else ''}")
        if isinstance(ev.get("total_cost_usd"), (int, float)):
            parts.append(f"${ev['total_cost_usd']:.4f}")
        failed = bool(ev.get("is_error")) or ev.get("terminal_reason") == "hook_stopped"
        self.view.done(" · ".join(["Failed" if failed else "Done", *parts]), failed)


class CopilotEvents:
    """Copilot CLI --output-format json: assistant.*, tool.execution_*, subagent.*, result."""

    def __init__(self, view: View):
        self.view = view
        self.answer = ""
        self.result: dict | None = None
        self.errors: list[str] = []
        self._tools: dict[str, int] = {}
        self._agents: dict[str, int] = {}

    def _depth(self, data: dict) -> int:
        parent = data.get("parentToolCallId")
        return self._agents.get(parent, -1) + 1 if parent else 0

    def feed(self, ev: dict) -> None:
        kind = ev.get("type") or ""
        data = ev.get("data") if isinstance(ev.get("data"), dict) else {}
        depth = self._depth(data)
        if kind == "assistant.reasoning_delta":
            self._piece(("r", data.get("reasoningId")), "think", depth, data.get("deltaContent"))
        elif kind == "assistant.reasoning":
            self.view.close(("r", data.get("reasoningId")))
            if ("r", data.get("reasoningId")) not in self.view.written and data.get("content"):
                self.view.line("think", data["content"], depth, DIM)
        elif kind == "assistant.message_delta":
            self._piece(("m", data.get("messageId")), "text", depth, data.get("deltaContent"))
        elif kind == "assistant.message":
            self.view.close(("m", data.get("messageId")))
            content = data.get("content") or ""
            if ("m", data.get("messageId")) not in self.view.written and content.strip():
                self.view.line("text", content.strip("\n"), depth)
            if content.strip() and not data.get("parentToolCallId"):
                self.answer = content.strip()
        elif kind == "tool.execution_start":
            self.view.close()
            name = data.get("toolName") or "?"
            self._tools[data.get("toolCallId")] = depth
            if name == "task":
                self._agents[data.get("toolCallId")] = depth
            self.view.tool_call(name, data.get("arguments"), depth)
        elif kind == "tool.execution_complete":
            depth = self._tools.get(data.get("toolCallId"), depth)
            if data.get("success") is False:
                self.view.tool_result(content_text(data.get("error")) or "failed", depth, error=True)
            else:
                self.view.tool_result(content_text(data.get("result")), depth)
        elif kind.startswith("subagent."):
            name = data.get("agentDisplayName") or data.get("agentName") or data.get("description") or "agent"
            state = kind.split(".", 1)[1].replace("_", " ")
            self.view.line("tool", f"Agent {_short(name)}: {state}", depth, "", CYAN)
        elif kind == "session.error":
            message = data.get("message") or "error"
            self.errors.append(message)
            self.view.line("result", message, depth, RED)
        elif kind == "result":
            self.result = ev
            usage = ev.get("usage") or {}
            failed = bool(ev.get("exitCode"))
            premium = usage.get("premiumRequests")
            extra = [f"{premium} premium request{'s' if premium != 1 else ''}"] if premium is not None else []
            self.view.done(" · ".join(["Failed" if failed else "Done", *extra]), failed)

    def _piece(self, key, kind: str, depth: int, text) -> None:
        if not self.view.is_open(key):
            self.view.open(key, kind, depth)
        self.view.chunk(key, text or "")
