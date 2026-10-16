# Disclosure
Hey everyone, just wanted to put put this up front; this tool was build entirely with AI. I just needed something that would allow me to query sensitive data without exposing any secrets so I made a quick tool for it. I make no promises that it will keep your secrets fully out of Claude's grubby little hands with its ability to go wherever it wants and grep what it wants, but this tool at least keeps the secrets from getting in via your prompts. The session history with the map from secret to placeholder is encrypted and needs to be unlocked with a password you set. This prevents your AI from just checking the file for the original secrets. I'll keep working on this as this is still an early alpha of the proof-of-concept but it's a pretty simple concept. If you want, you can take the spec and expand the idea to whatever your needs are. Again, this is just a tool I built to do something I needed and I don't believe tools to make lives easier should be closed source. That's all I got. Back to the slop.

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

`redact-ask` below is the PowerShell profile function; without it, use
`.venv\Scripts\python redact_ask.py`. The question always goes after `-q`; anything else you type is
the text to analyze.

```
redact-ask '<paste the log or code here>' -q "Why are logins failing?"
redact-ask --file app.log -q "Why are logins failing?"
Get-Clipboard -Raw | redact-ask -q "Why are logins failing?"
redact-ask -q "Which host was that on?"          # follow-up, same conversation
redact-ask --file app.log -q "..." --to copilot:gpt-5 --out answer.md
redact-ask --file app.log -q "..." --preview      # show the redacted text, ask before sending (on by default)
redact-ask --file app.log -q "..." --dry-run      # show the redacted text only, send nothing
redact-ask sessions list
redact-ask sessions clear <name> | --all
redact-ask reset-passphrase
```

Options: `--to TARGET[:MODEL]`, `--session NAME`, `--new-session`, `--deep` (local Ollama pass),
`--restore`, `--out FILE`, `--file PATH`. The clipboard is never read.

## Passphrase

Session mappings are encrypted with a key derived from a passphrase you type at each run.
It is never stored, so nothing else running as you (including AI agents) can decrypt them.
The first run asks you to create it. If you forget it, run `redact-ask reset-passphrase`: it deletes
all saved sessions (they can't be read without the old passphrase) and asks for a new one.

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
