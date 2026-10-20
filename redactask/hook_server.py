"""[19] Redact tool output for Claude Code's hook while a --local-tools run is in progress (SPEC: hook_server.py).

Runs inside redact_ask.py for exactly one cloud call: a localhost HTTP server on a random port,
protected by a random token. hook_client.py (run by Claude Code after every tool call) sends it
the strings in the tool's output and gets them back redacted with the session's mapping, so a
value has the same placeholder in the prompt, in tool output and in follow-ups.

It only ever returns redacted text; there is no way to ask it for the mapping or a real value.
"""
from __future__ import annotations

import hmac
import json
import secrets
import sys
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Callable

from .models import RedactAskError

URL_ENV = "REDACT_ASK_HOOK_URL"
TOKEN_ENV = "REDACT_ASK_HOOK_TOKEN"
TIMEOUT_ENV = "REDACT_ASK_HOOK_TIMEOUT"
TOKEN_HEADER = "X-Redact-Ask-Token"
TRUNCATED = "\n[redact-ask: output truncated at {limit}; narrow the command or read a smaller range]"


@dataclass
class ToolOutput:
    """One redacted tool result, for the audit log (redacted text only)."""
    tool: str
    redacted: list[str]


@dataclass
class _State:
    outputs: list[ToolOutput] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


def truncate(text: str, max_lines: int, max_bytes: int) -> str:
    """Cut text to the input limits (lines, then UTF-8 bytes) and say so at the end."""
    lines = text.split("\n")
    if len(lines) > max_lines:
        text = "\n".join(lines[:max_lines]) + TRUNCATED.format(limit=f"{max_lines:,} lines")
    data = text.encode("utf-8")
    if len(data) > max_bytes:
        text = data[:max_bytes].decode("utf-8", errors="ignore") + TRUNCATED.format(limit=f"{max_bytes:,} bytes")
    return text


class HookServer:
    """Context manager: start the server, hand env() to the cloud CLI, stop it afterwards.

    redact_fn takes one string and returns it redacted (it raises on failure, e.g. ScanAbort).
    Calls are serialised with a lock because they all update the same mapping.
    """

    def __init__(self, redact_fn: Callable[[str], str], max_lines: int, max_bytes: int, timeout: int):
        self.redact_fn = redact_fn
        self.max_lines = max_lines
        self.max_bytes = max_bytes
        self.timeout = timeout
        self.token = secrets.token_urlsafe(32)
        self.state = _State()
        self._lock = threading.Lock()
        self._httpd: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None

    # -- lifecycle -----------------------------------------------------------
    def __enter__(self) -> "HookServer":
        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), self._handler())
        self._httpd.daemon_threads = True
        self._thread = threading.Thread(target=self._httpd.serve_forever, name="redact-ask-hook", daemon=True)
        self._thread.start()
        return self

    def __exit__(self, *exc) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None

    @property
    def url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}/redact"

    def env(self) -> dict[str, str]:
        """Environment variables for the cloud CLI, passed on to hook_client.py."""
        return {URL_ENV: self.url, TOKEN_ENV: self.token, TIMEOUT_ENV: str(self.timeout)}

    @property
    def outputs(self) -> list[ToolOutput]:
        return self.state.outputs

    @property
    def errors(self) -> list[str]:
        return self.state.errors

    # -- work ----------------------------------------------------------------
    def redact_strings(self, tool: str, strings: list[str]) -> list[str]:
        with self._lock:
            out = [self.redact_fn(truncate(s, self.max_lines, self.max_bytes)) if s else s for s in strings]
            self.state.outputs.append(ToolOutput(tool, out))
            return out

    def _handler(self):
        server = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):          # keep stderr for redact-ask's own messages
                pass

            def _reply(self, status: int, body: dict) -> None:
                data = json.dumps(body, ensure_ascii=False).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_POST(self):
                if self.path != "/redact":
                    return self._reply(404, {"error": "not found"})
                token = self.headers.get(TOKEN_HEADER, "")
                if not hmac.compare_digest(token, server.token):
                    return self._reply(403, {"error": "bad token"})
                try:
                    body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                    strings = body["strings"]
                    if not isinstance(strings, list) or not all(isinstance(s, str) for s in strings):
                        raise ValueError("strings must be a list of strings")
                    tool = str(body.get("tool", "?"))
                except (ValueError, KeyError, TypeError) as e:
                    return self._reply(400, {"error": f"bad request: {e}"})
                try:
                    redacted = server.redact_strings(tool, strings)
                except RedactAskError as e:
                    server.state.errors.append(f"{tool}: {e.message}")
                    return self._reply(500, {"error": e.message})
                except Exception as e:               # anything else still fails closed in the client
                    server.state.errors.append(f"{tool}: {type(e).__name__}: {e}")
                    print(f"redact-ask: redacting {tool} output failed: {e}", file=sys.stderr)
                    return self._reply(500, {"error": f"{type(e).__name__}: {e}"})
                return self._reply(200, {"strings": redacted})

        return Handler
