# Disclosure
Hey everyone, just wanted to put this up front; this tool was build entirely with AI. I just needed something that would allow me to query sensitive data without exposing any secrets so I made a quick tool for it. I make no promises that it will keep your secrets fully out of Claude's grubby little hands with its ability to go wherever it wants and grep what it wants, but this tool at least keeps the secrets from getting in via your prompts. The session history with the map from secret to placeholder is encrypted and needs to be unlocked with a password you set. This prevents your AI from just checking the file for the original secrets. I'll keep working on this as this is still an early alpha of the proof-of-concept but it's a pretty simple concept. If you want, you can take the spec and expand the idea to whatever your needs are. Again, this is just a tool I built to do something I needed and I don't believe tools to make lives easier should be closed source. That's all I got. Back to the slop.

# redact-ask

Redacts logs, code and config on your machine and sends only the redacted text to Claude Code or
GitHub Copilot CLI. The answer is shown as the model wrote it (with placeholders); add `--restore`
to see it with the real values put back. See `SPEC.md` for the design.

## Setup (once)

Needs Python 3.11+, and `claude` and/or `copilot` installed and logged in.

```
git clone https://github.com/NFPortal/Redact-Ask.git
cd Redact-Ask
python -m venv .venv
.venv\Scripts\python -m pip install torch --index-url https://download.pytorch.org/whl/cu128   # CPU: .../whl/cpu
.venv\Scripts\python -m pip install -r requirements.txt
```

On Debian use `.venv/bin/python`.
The GLiNER model (`nvidia/gliner-pii`) downloads on the first run; after that it works offline.

## Use

Run it with `.venv\Scripts\python redact_ask.py` (Debian: `.venv/bin/python redact_ask.py`). The
examples below use a `redact-ask` shortcut. On Windows, add this function to your PowerShell profile
(`notepad $PROFILE`), with the path changed to where you cloned the repo:

```powershell
function redact-ask {
    $dir = "C:\path\to\Redact-Ask"
    $py = "$dir\.venv\Scripts\python.exe"
    $script = "$dir\redact_ask.py"
    if ($MyInvocation.ExpectingInput) {
        # Forward piped text (e.g. Get-Clipboard -Raw | redact-ask -q "question") as UTF-8.
        $OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $input | & $py $script @args
    } else {
        & $py $script @args
    }
}
```

On Debian, add an alias to `~/.bashrc`:

```bash
alias redact-ask='~/Redact-Ask/.venv/bin/python ~/Redact-Ask/redact_ask.py'
```

The question always goes after `-q`; anything else you type is the text to analyze.

```
redact-ask '<paste the log or code here>' -q "Why are logins failing?"
redact-ask --file app.log -q "Why are logins failing?"
Get-Clipboard -Raw | redact-ask -q "Why are logins failing?"
redact-ask -q "Which host was that on?"          # follow-up, same conversation
redact-ask --file app.log -q "..." --to copilot:gpt-5 --out answer.md
redact-ask --file app.log -q "..." --preview      # show the redacted text, ask before sending (on by default)
redact-ask --file app.log -q "..." --dry-run      # show the redacted text only, send nothing
redact-ask -q "Why won't the app connect?" --local-tools   # Claude reads files here; output redacted
redact-ask --file app.log -q "..." --no-live      # only print the final answer
redact-ask sessions list
redact-ask sessions clear <name> | --all
redact-ask reset-passphrase
```

Options: `--to TARGET[:MODEL]`, `--session NAME`, `--new-session`, `--deep` (local Ollama pass),
`--restore`, `--out FILE`, `--file PATH`, `--local-tools`, `--live` / `--no-live`. The clipboard is never read.

## Live view

While the model works you see what it is doing, as in Claude Code: its thinking, its text as it is
written, each tool call and a short preview of the result, and any subagents (indented under the
call that started them). It ends with a summary line, then the answer is printed:

```
○ The log shows repeated auth failures for <USER_1>; I'll check the web for that error code.
● WebSearch(sshd "maximum authentication attempts exceeded")
└ Web search results for query: ...
● <USER_1> is hitting MaxAuthTries from <IP_1> ...
■ Done · 2 turns · $0.0123 · 9.4s
```

The live view goes to stderr, so stdout is still just the answer (`> answer.md` or a pipe gets the
answer alone). It works in any terminal: colors are used where the terminal supports them (Windows
Terminal, PowerShell and cmd on Windows 10+, any Linux terminal) and left out when output is
redirected, `NO_COLOR` is set or `TERM=dumb`. It shows what the model saw and wrote, so values are
placeholders even with `--restore`. Works with Claude Code and Copilot CLI. Turn it off with
`--no-live`, or with `live_view = false` in the config (`--live` turns it back on for one run).

## Local tools (`--local-tools`, Claude only)

Lets Claude look around the current folder itself (read files, search, run commands). Every
tool result goes through the same redaction before Claude sees it, so `cat .env` reaches it as
`API_KEY=<API_KEY_1>`. The hooks that do this exist only in the `claude` that redact-ask starts;
your normal Claude Code sessions are not changed. If a result can't be redacted, the run stops
instead of sending it. `--restore` puts real values back in the final answer only.

It keeps Claude from *seeing* secrets it comes across; it is not a guarantee against a model that
deliberately tries to extract them (for example with `base64` or by printing a value in pieces).
The working-folder path itself is visible to Claude. Set `local_tools = true` in the config to use
it on every run. See `SPEC.md` ([19], [20]) for details.

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
