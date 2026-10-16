"""[1] redact-ask entry point: redact text locally, ask Claude Code or Copilot CLI, restore real values.

Only parses arguments and calls the other scripts in the order of the SPEC data flow.

    python redact_ask.py ["text to analyze"] "question" [--file PATH] [--to TARGET[:MODEL]]
                         [--session NAME] [--new-session] [--deep] [--restore] [--out FILE]
    python redact_ask.py sessions list
    python redact_ask.py sessions clear [NAME | --all]
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter

from redactask import (audit_log, cloud_runner, config, final_scan, gliner_detector, input_reader, key_manager,
                       learner, lists_detector, llm_detector, masker, merger, output_writer, rules_detector,
                       secrets_detector, unmasker)
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
        epilog="Sessions: python redact_ask.py sessions list | sessions clear [NAME | --all]")
    p.add_argument("args", nargs="+", metavar="[TEXT] QUESTION",
                   help="optional text to analyze (pasted in quotes), then the question")
    p.add_argument("--file", metavar="PATH", help="read the text to analyze from a file instead")
    p.add_argument("--to", metavar="TARGET[:MODEL]", help="claude | copilot, optionally with a model (claude:opus)")
    p.add_argument("--session", metavar="NAME", help="named session (default: one per current folder)")
    p.add_argument("--new-session", action="store_true", help="forget this session's mapping and conversation")
    p.add_argument("--deep", action="store_true", help="also run the local LLM detector (Ollama)")
    p.add_argument("--restore", action="store_true",
                   help="show the answer with placeholders replaced by the real values (default: as the model wrote it)")
    p.add_argument("--out", metavar="FILE", help="also write the answer to FILE")
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


def cmd_ask(argv: list[str]) -> int:
    a = _parser().parse_args(argv)
    if len(a.args) > 2:
        raise UsageError("Expected [\"text\"] \"question\" (or --file PATH \"question\"). Put each in quotes.")
    text, question = (a.args[0], a.args[1]) if len(a.args) == 2 else (None, a.args[0])

    cfg = config.load()
    for w in cfg.warnings:
        _err(w)
    tool, model = config.parse_target(a.to or cfg.default_target)
    deep = a.deep or cfg.llm.enabled_by_default
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
         f"{tool}{':' + model if model else ''} ({cfg.context} context)...")

    # [14] [15] send
    prompt = cloud_runner.build_prompt(result.redacted_text, tool)
    run_id = audit.start(prompt, tool, model, session.id, counts, result.retries, inp.source)
    try:
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
        return cmd_ask(argv)
    except RedactAskError as e:
        _err(e.message)
        return e.code
    except KeyboardInterrupt:
        _err("cancelled.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
