"""[1] redact-ask entry point: redact text locally, ask Claude Code or Copilot CLI, restore real values.

Only parses arguments and calls the other scripts in the order of the SPEC data flow.

    python redact_ask.py ["text to analyze" | --file PATH] -q "question" [--to TARGET[:MODEL]]
                         [--session NAME] [--new-session] [--deep] [--restore] [--out FILE] [--local-tools]
    python redact_ask.py sessions list
    python redact_ask.py sessions clear [NAME | --all]
    python redact_ask.py reset-passphrase
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

from redactask import (audit_log, cloud_runner, config, final_scan, gliner_detector, hook_server, input_reader,
                       key_manager, learner, lists_detector, llm_detector, masker, merger, output_writer,
                       rules_detector, secrets_detector, unmasker)
from redactask.lists_detector import ListData
from redactask.models import (EXIT_OK, Finding, Mapping, PLACEHOLDER_RE, RedactAskError, RunResult, ScanAbort,
                              UsageError)
from redactask.session_store import SessionStore


def _err(msg: str) -> None:
    print(f"redact-ask: {msg}", file=sys.stderr)


# ---------------------------------------------------------------------------
# Pipeline (no network): detectors -> merger -> masker -> final_scan retry loop
# ---------------------------------------------------------------------------
def detect_all(text: str, cfg, lists: ListData, automaton, deep: bool, use_gliner: bool = True) -> list[Finding]:
    found: list[Finding] = []
    found += rules_detector.detect(text, cfg, lists.subnets)
    found += secrets_detector.detect(text)
    found += lists_detector.detect(text, lists, automaton)
    if use_gliner:
        found += gliner_detector.detect(text, cfg.gliner)
    if deep:
        found += llm_detector.detect(text, cfg.llm)
    return found


def redact(text: str, mapping: Mapping, cfg, lists: ListData, deep: bool = False,
           use_gliner: bool = True) -> tuple[RunResult, str]:
    """Return (RunResult, escaped original text). Raises ScanAbort if the final scan keeps failing."""
    escaped = masker.escape_literals(text, mapping)
    automaton = lists_detector.build_automaton(lists.values)
    findings = merger.merge(escaped, detect_all(escaped, cfg, lists, automaton, deep, use_gliner), cfg)
    redacted = masker.mask(escaped, findings, mapping)

    retries = 0
    while True:
        leftovers = final_scan.scan(redacted, mapping, cfg, lists, automaton)
        if not leftovers:
            break
        if retries >= cfg.max_scan_retries:
            where = "\n  ".join(final_scan.describe(redacted, leftovers))
            raise ScanAbort(f"The final scan still found sensitive values after {retries} re-redaction "
                            f"pass(es); nothing was sent.\n  {where}")
        retries += 1
        redacted = masker.mask(redacted, merger.merge(redacted, leftovers, cfg), mapping)
    return RunResult(redacted_text=redacted, findings=findings, retries=retries), escaped


def placeholder_counts(redacted: str) -> dict[str, int]:
    seen = {m.group(0).split(" in ")[0].rstrip(">") + ">" for m in PLACEHOLDER_RE.finditer(redacted)}
    counts = Counter(PLACEHOLDER_RE.fullmatch(p).group(1) for p in seen if PLACEHOLDER_RE.fullmatch(p))
    counts.pop("LITERAL", None)
    return dict(sorted(counts.items()))


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------
def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="redact_ask.py",
        description="Redact logs/code locally, ask Claude Code or Copilot CLI, and restore the real values.",
        epilog="Sessions: python redact_ask.py sessions list | sessions clear [NAME | --all]\n"
               "Forgot the passphrase: python redact_ask.py reset-passphrase",
        formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("text", nargs="?", metavar="TEXT",
                   help="text to analyze, pasted in quotes (or use --file or pipe it in)")
    p.add_argument("-q", "--query", metavar="QUESTION", help="the question to ask (required)")
    p.add_argument("--file", metavar="PATH", help="read the text to analyze from a file instead")
    p.add_argument("--to", metavar="TARGET[:MODEL]", help="claude | copilot, optionally with a model (claude:opus)")
    p.add_argument("--session", metavar="NAME", help="named session (default: one per current folder)")
    p.add_argument("--new-session", action="store_true", help="forget this session's mapping and conversation")
    p.add_argument("--deep", action="store_true", help="also run the local LLM detector (Ollama)")
    p.add_argument("--restore", action="store_true",
                   help="show the answer with placeholders replaced by the real values (default: as the model wrote it)")
    p.add_argument("--out", metavar="FILE", help="also write the answer to FILE")
    p.add_argument("--preview", action="store_true",
                   help="show the redacted text and ask before sending (or set preview = true in config)")
    p.add_argument("--dry-run", action="store_true", help="show the redacted text and stop; nothing is sent")
    p.add_argument("--local-tools", action="store_true",
                   help="let Claude read files and run read-only commands in the current folder; every tool "
                        "result is redacted before Claude sees it (or set local_tools = true in config)")
    return p


def _open_store(cfg) -> SessionStore:
    d = config.dirs()
    key, _ = key_manager.get_key(d.config)
    store = SessionStore(d.sessions, d.workdirs, key, cfg.session_expiry_days)
    old = key_manager.legacy_key(d.config)
    if old:
        # Older versions kept a key in Windows Credential Manager / a key file. Move those
        # sessions to the passphrase key, then delete the stored key.
        moved = store.migrate(old)
        key_manager.delete_legacy(d.config)
        _err(f"moved {moved} session(s) to passphrase encryption and deleted the old stored key.")
    return store


def cmd_reset_passphrase(argv: list[str]) -> int:
    """Forgotten passphrase: delete all sessions (unreadable without it) and create a new one."""
    if argv:
        raise UsageError("reset-passphrase takes no arguments.")
    d = config.dirs()
    _err("this deletes ALL saved sessions (placeholder mappings and conversation links) and sets a new\n"
         "passphrase. Your config, lists and audit log are kept.")
    if output_writer.confirm("Type RESET to continue: ") != "RESET":
        print("Cancelled; nothing was changed.")
        return EXIT_OK
    n = SessionStore.wipe(d.sessions, d.workdirs)
    key_manager.reset(d.config)
    print(f"Deleted {n} session(s) and set a new passphrase.")
    return EXIT_OK


def cmd_sessions(argv: list[str]) -> int:
    p = argparse.ArgumentParser(prog="redact_ask.py sessions")
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    c = sub.add_parser("clear")
    c.add_argument("name", nargs="?")
    c.add_argument("--all", action="store_true")
    a = p.parse_args(argv)
    cfg = config.load()
    store = _open_store(cfg)
    store.expire()
    if a.cmd == "list":
        rows = store.list()
        if not rows:
            print("No sessions.")
        for r in rows:
            counts = ", ".join(f"{k} {v}" for k, v in r["counts"].items() if k != "LITERAL") or "no values"
            targets = ", ".join(r.get("targets", [])) or "-"
            print(f"{r['name']}\n    last used {r['last_used']}   conversations: {targets}   values: {counts}")
        return EXIT_OK
    if not a.all and not a.name:
        raise UsageError("sessions clear needs a session NAME or --all.")
    n = store.clear(a.name, all_=a.all)
    print(f"Cleared {n} session(s).")
    return EXIT_OK


def run_with_local_tools(prompt: str, tool: str, model: str | None, session, store: SessionStore, cfg,
                         lists: ListData, deep: bool, audit: audit_log.AuditLog,
                         run_id: str) -> cloud_runner.CloudResult:
    """[19] [20] Claude works in the current folder; every tool result is redacted with this session's
    mapping by hook_server before the model sees it."""
    def redact_tool_output(text: str) -> str:
        return redact(text, session.mapping, cfg, lists, deep)[0].redacted_text

    server = hook_server.HookServer(redact_tool_output, cfg.max_lines, cfg.max_bytes, cfg.hook_timeout_seconds)
    try:
        with server:
            local = cloud_runner.LocalRun(Path.cwd(), server.env(), cfg.hook_timeout_seconds)
            try:
                return cloud_runner.run(prompt, tool, model, session.conversations.get(tool),
                                        store.workdir(session.id), cfg.context, cfg.cloud_timeout_seconds, local)
            except cloud_runner.HookStopped as e:
                if server.errors:
                    raise cloud_runner.HookStopped(f"{e.message} Cause: {server.errors[-1]}") from e
                raise
    finally:
        for out in server.outputs:
            audit.tool_output(run_id, out.tool, out.redacted)
        # Placeholders made for tool output were sent: keep them for --restore and follow-ups.
        store.save(session)


def cmd_ask(argv: list[str]) -> int:
    a = _parser().parse_args(argv)
    if not a.query or not a.query.strip():
        raise UsageError('a question is required: -q "your question". Text without -q is the text to analyze, '
                         'never the question. Commands: sessions, reset-passphrase.')
    text, question = a.text, a.query

    cfg = config.load()
    for w in cfg.warnings:
        _err(w)
    tool, model = config.parse_target(a.to or cfg.default_target)
    deep = a.deep or cfg.llm.enabled_by_default
    local_tools = a.local_tools or cfg.local_tools
    if local_tools and tool != "claude":
        raise UsageError("--local-tools works with Claude Code only (--to claude).")
    d = config.dirs()

    # [3] input
    inp = input_reader.read(question, a.file, text, cfg.max_lines, cfg.max_bytes)
    for w in inp.warnings:
        _err(w)

    # [11] [12] session + housekeeping
    store = _open_store(cfg)
    store.expire()
    audit = audit_log.AuditLog(d.audit, cfg.session_expiry_days)
    audit.expire()
    session = store.load(SessionStore.session_name(a.session))
    if a.new_session:
        session = store.reset(session)
    if inp.source == "none" and not session.conversations.get(tool):
        _err("no text to analyze was received (no text argument, --file or piped input), and there's no "
             "earlier conversation in this session; sending only the question.")

    # [6] lists, then [4]-[10] + [13]
    lists = lists_detector.load(d.lists)
    for w in lists.warnings:
        _err(w)
    result, escaped = redact(inp.text, session.mapping, cfg, lists, deep)
    store.save(session)

    counts = placeholder_counts(result.redacted_text)
    summary = ", ".join(f"{k} {v}" for k, v in counts.items()) or "nothing"
    _err(f"redacted {sum(counts.values())} value(s) ({summary})"
         f"{f'; {result.retries} re-scan pass(es)' if result.retries else ''}; sending to "
         f"{tool}{':' + model if model else ''} ({cfg.context} context"
         f"{f'; local tools in {Path.cwd()}, output redacted' if local_tools else ''})...")

    # [14] [15] send (after an optional preview)
    prompt = cloud_runner.build_prompt(result.redacted_text, tool)
    if a.dry_run:
        output_writer.write(prompt)
        _err("dry run: nothing was sent.")
        return EXIT_OK
    if a.preview or (cfg.preview and counts):     # the default preview is skipped when nothing was redacted
        output_writer.show_preview(prompt)
        if output_writer.confirm(f"Send this to {tool}? [y/N] ").lower() not in ("y", "yes"):
            run_id = audit.start(prompt, tool, model, session.id, counts, result.retries, inp.source,
                                 status="cancelled")
            _err("cancelled; nothing was sent.")
            return EXIT_OK
    run_id = audit.start(prompt, tool, model, session.id, counts, result.retries, inp.source)
    try:
        if local_tools:
            cloud = run_with_local_tools(prompt, tool, model, session, store, cfg, lists, deep, audit, run_id)
        else:
            cloud = cloud_runner.run(prompt, tool, model, session.conversations.get(tool), store.workdir(session.id),
                                     cfg.context, cfg.cloud_timeout_seconds)
    except RedactAskError as e:
        audit.finish(run_id, "error", error=e.message)
        raise
    audit.finish(run_id, "done", redacted_answer=cloud.answer)
    for w in cloud.warnings:
        _err(w)
    session.conversations[tool] = cloud.conversation_id
    store.save(session)

    # [16] [17] show the answer as the model wrote it, or with real values restored (--restore)
    answer = cloud.answer
    if a.restore:
        restored = unmasker.unmask(cloud.answer, session.mapping)
        for ph in restored.unknown:
            _err(f"the answer mentions {ph}, which isn't a known placeholder; left as-is.")
        answer = restored.text
    output_writer.write(answer, a.out)

    # [18] grow the lists
    learner.run(escaped, result.findings, lists, d.lists)
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    try:
        if argv and argv[0] == "sessions":
            return cmd_sessions(argv[1:])
        if argv and argv[0] == "reset-passphrase":
            return cmd_reset_passphrase(argv[1:])
        return cmd_ask(argv)
    except RedactAskError as e:
        _err(e.message)
        return e.code
    except KeyboardInterrupt:
        _err("cancelled.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
