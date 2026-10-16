# redact-ask

Redacts logs, code and config on your machine and sends only the redacted text to Claude Code or
GitHub Copilot CLI. The answer is shown as the model wrote it (with placeholders); add `--restore`
to see it with the real values put back. See `SPEC.md` for the design.

## Setup (once)

Needs Python 3.11+, and `claude` and/or `copilot` installed and logged in.

```
cd "C:\Programming\Tools\Redact Ask"
python -m venv .venv
.venv\Scripts\python -m pip install torch --index-url https://download.pytorch.org/whl/cu128   # CPU: .../whl/cpu
.venv\Scripts\python -m pip install -r requirements.txt
```

On Debian use `.venv/bin/python`.
The GLiNER model (`nvidia/gliner-pii`) downloads on the first run; after that it works offline.

## Use

```
.venv\Scripts\python redact_ask.py "<paste the log or code here>" "Why are logins failing?"
.venv\Scripts\python redact_ask.py --file app.log "Why are logins failing?"
Get-Content app.log | .venv\Scripts\python redact_ask.py "Why are logins failing?"
.venv\Scripts\python redact_ask.py "Which host was that on?"          # follow-up, same conversation
.venv\Scripts\python redact_ask.py --file app.log "..." --to copilot:gpt-5 --out answer.md
.venv\Scripts\python redact_ask.py sessions list
.venv\Scripts\python redact_ask.py sessions clear <name> | --all
```

Options: `--to TARGET[:MODEL]`, `--session NAME`, `--new-session`, `--deep` (local Ollama pass),
`--restore`, `--out FILE`, `--file PATH`. The clipboard is never read.

## Passphrase

Session mappings are encrypted with a key derived from a passphrase you type at each run.
It is never stored, so nothing else running as you (including AI agents) can decrypt them.
The first run asks you to create it. If you forget it, delete the sessions folder and start over.

## Your files

| What | Windows | Debian |
|---|---|---|
| `config.toml` and `lists\*.txt` | `%APPDATA%\redact-ask\` | `~/.config/redact-ask/` |
| Encrypted sessions | `%LOCALAPPDATA%\redact-ask\sessions\` | `~/.local/share/redact-ask/sessions/` |
| Audit log (redacted only) | `%LOCALAPPDATA%\redact-ask\audit\audit.jsonl` | `~/.local/state/redact-ask/audit.jsonl` |

Add your usernames, hostnames, table names, project names, subnets, etc. to the list files so
they are always redacted. After each run you are offered newly found values to add.

## Tests

```
.venv\Scripts\python -m pytest            # unit, end-to-end (fake CLI) and corpus tests
.venv\Scripts\python -m pytest --cloud    # also live checks against the real CLIs
```
