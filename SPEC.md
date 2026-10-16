# Redact Ask — Specification

_Last updated: 2026-10-16_

## Goal
A local command-line tool that redacts sensitive data (credentials, identities, network and
infrastructure identifiers, database names, etc.) from logs, code and other text **before** it is
sent to a cloud AI CLI (Claude Code or GitHub Copilot CLI) for analysis, and can restore the real
values in the answer locally. Real values never leave the machine.

## Users & Workflow
- Single user (the author), technical, working in a terminal on **Windows 11** and **Debian**.
- Typical use: copy or point at a log/code snippet, ask a question, get an answer from Claude or
  Copilot (as written, with placeholders; `--restore` puts the real values back). Follow-up questions
  continue the same cloud conversation.
- Cloud access is through the user's existing **Claude Code** and **GitHub Copilot CLI**
  subscriptions, called in non-interactive mode (`claude -p`, `copilot -p`).

## Scope
### In scope
- Input as text passed on the command line (the default), a file (`--file PATH`), or piped stdin.
- Detection by regex rules, gitleaks secret rules, user-maintained lists, and GLiNER; optional local
  LLM pass (Ollama) behind a flag.
- Consistent, typed placeholders per session; encrypted mapping storage.
- Fail-closed final scan with automatic re-redaction (max 2 retries).
- Sending to Claude Code or Copilot CLI in an isolated temp folder with web tools only.
- Printing the answer as the model wrote it (placeholders); `--restore` restores real values; optional `--out` file.
- Audit log of what left the machine (redacted only).
- Post-run approval prompt to add newly detected values to the lists.
- Session management commands (list, clear, expiry).
- Planted-secrets test corpus.

### Out of scope
- Presidio (GLiNER is called directly; our own scripts merge and replace).
- (Preview was out of scope at first; now available with `--preview` / `--dry-run`.)
- Pip/pipx packaging (run from the project folder).
- Folder / multi-file input.
- Pulling lists from AD/LDAP or database schemas.
- Reading the clipboard (removed by user decision) and clipboard output (`--copy`).

### Later phase
- `redact_hook.py`: Claude Code and Copilot CLI hook tripwires that reuse the final scan to block
  prompts containing secrets and deny reads of sensitive paths in normal interactive sessions.

## Inputs & Outputs

### Command line
```
python redact_ask.py "text to analyze" -q "question" [options]
python redact_ask.py --file PATH -q "question" [options]
<command> | python redact_ask.py -q "question" [options]
python redact_ask.py -q "question" [options]           # follow-up / question only

Options:
  -q, --query QUESTION  The question (required). Text without -q is always the text to analyze,
                        never the question, so a mistyped command can't be sent as one.
  --to TARGET[:MODEL]   Override the configured target for this prompt
                        (claude | claude:opus | copilot | copilot:<model>)
  --session NAME        Use a named session (default: one per current folder)
  --new-session         Discard the current session's mapping and conversation, start fresh
  --deep                Also run the local LLM detector (Ollama)
  --file PATH           Read the text to analyze from a file
  --restore             Show the answer with placeholders replaced by the real values
  --out FILE            Also write the answer (raw, or restored with --restore) to FILE
  --preview             Show the exact redacted text and ask "Send? [y/N]" before sending
                        (on by default: config `preview = true`; set it to false to send without asking)
  --dry-run             Show the exact redacted text and stop; nothing is sent

python redact_ask.py sessions list
python redact_ask.py sessions clear [NAME | --all]
python redact_ask.py reset-passphrase    # forgot it: delete all sessions, set a new one
```
Exactly one input source (text argument, `--file`, or stdin) is allowed per run. The clipboard is never read. **The question text is
also redacted**: it is appended to the input as a separate section and goes through the whole
pipeline.

### Input limits
- Up to **5,000 lines or 1 MB**, whichever comes first (configurable). Larger input is refused.

### Output
- The model's answer on stdout, with placeholders by default or real values with `--restore`;
  optionally also written to `--out FILE`.
- Status and warnings on stderr (counts per type, retries, unknown placeholders).

### Files and locations (via `platformdirs`)
| What | Windows | Debian |
|---|---|---|
| Config `config.toml` | `%APPDATA%\redact-ask\` | `~/.config/redact-ask/` |
| Lists `lists/*.txt` | `%APPDATA%\redact-ask\lists\` | `~/.config/redact-ask/lists/` |
| Session mappings (encrypted) | `%LOCALAPPDATA%\redact-ask\sessions\` | `~/.local/share/redact-ask/sessions/` |
| Audit log `audit.jsonl` | `%LOCALAPPDATA%\redact-ask\audit\` | `~/.local/state/redact-ask/` |
| Passphrase salt and check value | `%APPDATA%\redact-ask\key.salt`, `key.check` | `~/.config/redact-ask/key.salt`, `key.check` |

Lists and mappings contain real sensitive values and are **never stored in the project folder**.

### Exit codes
| Code | Meaning |
|---|---|
| 0 | Success |
| 2 | Usage error (bad arguments, more than one input source) |
| 3 | Input error (too large, unreadable, binary, empty text) |
| 4 | Redaction aborted (final scan still failing after 2 retries; nothing sent) |
| 5 | Cloud CLI error (not installed, not logged in, timeout, non-zero exit) |
| 6 | Key or session storage error |
| 7 | Detector error (GLiNER or Ollama failed; nothing sent) |

## Text Data Flow

```
              question + input text
                       │
 [3] input_reader ─────┘  raw text (in memory only)
        │
        ├─► [4] rules_detector    ─┐
        ├─► [5] secrets_detector  ─┤
        ├─► [6] lists_detector    ─┼─► Findings
        ├─► [7] gliner_detector   ─┤
        └─► [8] llm_detector*     ─┘   (* only with --deep)
                       │
              [9] merger ── merged Findings
                       │
 [12] session_store ─► [10] masker ──► redacted text + updated mapping
   (uses [11] key_manager)  │
                       ▼
              [13] final_scan ── leftover Findings?
                 │ yes (≤2 times) → back to [9]/[10] with the new Findings
                 │ yes (3rd time) → abort, exit 4, nothing sent
                 ▼ no
              [12] session_store saves mapping
                       │
              [14] audit_log  (redacted text, status "sending")
                       │
              [15] cloud_runner ── answer with placeholders
                       │
              [14] audit_log  (redacted answer, status "done"/"error")
                       │
              [16] unmasker ── answer with real values
                       │
              [17] output_writer ── stdout / --out
                       │
              [18] learner ── approve new values → lists
```

Rules for the flow:
- **Raw text exists only in memory.** No script writes unredacted input to disk (no temp files).
- Only `cloud_runner` sends data off the machine, and it only ever receives the output of a passed
  `final_scan`.
- Any failure before `cloud_runner` (detector crash, key error, scan failure) means **nothing is
  sent**.
- Detectors [4]–[8] are independent: each takes the same text and returns its own Findings.

## Shared Data Structures (`redactask/models.py`)

```python
@dataclass(frozen=True)
class Finding:
    start: int            # character offset in the text, inclusive
    end: int              # character offset, exclusive
    value: str            # text[start:end]
    type: str             # entity type, e.g. "USER", "IP", "API_KEY" (see Redaction Catalog)
    detector: str         # "rules" | "secrets" | "lists" | "gliner" | "llm" | "final_scan"
    confidence: float     # 1.0 for rules/secrets/lists; model score for gliner/llm
    subnet: str | None    # for IP findings: the subnet it belongs to, e.g. "10.20.1.0/24"

@dataclass
class Mapping:
    forward: dict[str, str]    # real value -> placeholder, e.g. "jdoe" -> "<USER_1>"
    reverse: dict[str, str]    # placeholder -> real value
    counters: dict[str, int]   # per-type next number, e.g. {"USER": 2, "IP": 4}

@dataclass
class Session:
    id: str                       # sha256 of the session name or the absolute folder path
    name: str                     # human-readable name ("folder:<path>" or the --session name)
    mapping: Mapping
    conversations: dict[str, str] # target ("claude"/"copilot") -> cloud conversation/session ID
    created: datetime
    last_used: datetime

@dataclass
class RunResult:
    redacted_text: str
    findings: list[Finding]
    retries: int
```

## Scripts

Project layout:
```
Redact Ask/
  SPEC.md
  redact_ask.py              # [1] entry point
  config.example.toml
  requirements.txt
  redactask/
    models.py
    config.py                # [2]
    input_reader.py          # [3]
    rules_detector.py        # [4]
    secrets_detector.py      # [5]
    lists_detector.py        # [6]
    gliner_detector.py       # [7]
    llm_detector.py          # [8]
    merger.py                # [9]
    masker.py                # [10]
    key_manager.py           # [11]
    session_store.py         # [12]
    final_scan.py            # [13]
    audit_log.py             # [14]
    cloud_runner.py          # [15]
    unmasker.py              # [16]
    output_writer.py         # [17]
    learner.py               # [18]
    rules/gitleaks.toml      # vendored, pinned gitleaks rule set
  tests/
    corpus/                  # planted-secrets sample files + expected findings
    test_*.py                # one test file per script
```

Each script below lists its **input**, **output**, **responsibilities**, and what it **must not**
do. A script may only depend on `models.py`, `config.py`, and the scripts named in its section.

### [1] `redact_ask.py` — entry point / orchestrator
- **Input:** command-line arguments.
- **Output:** exit code; delegates all output to other scripts.
- **Responsibilities:**
  - Parse arguments; handle the `sessions list|clear` subcommands via `session_store`.
  - Call the scripts in the order of the data flow.
  - Run the final-scan retry loop: up to **2** re-redaction passes, then abort with exit 4.
  - Map exceptions from each stage to the exit codes above.
- **Must not:** contain detection, replacement, encryption, or subprocess logic.

### [2] `config.py` — settings
- **Input:** `config.toml` from the user config folder (created from `config.example.toml` on
  first run if missing).
- **Output:** a validated, typed `Config` object.
- **Settings:**
  ```toml
  default_target = "claude"          # or "copilot", optionally "claude:opus"
  max_lines = 5000
  max_bytes = 1_000_000
  session_expiry_days = 14
  max_scan_retries = 2
  cloud_timeout_seconds = 300
  context = "isolated"               # "isolated" | "full" — applies to Claude and Copilot (see [15])
  copilot_max_arg_chars = 30000      # only used if copilot -p can't read stdin (see [15])

  [types]                            # per-type on/off overrides for "your call" items
  BUCKET = false
  # every other type uses the default from the Redaction Catalog

  [paths]
  mode = "segments"                  # only sensitive path segments (agreed option a)

  [ip]
  private_subnet_prefix = 24         # used when no CIDR in the text covers an IP

  [gliner]
  model = "nvidia/gliner-pii"        # alternative: "urchade/gliner_multi_pii-v1"
  threshold = 0.3                    # low threshold = over-redact
  device = "auto"                    # auto | cuda | cpu

  [llm]
  enabled_by_default = false
  url = "http://localhost:11434"     # must be localhost
  model = "qwen3:8b"
  ```
- **Must not:** read lists, mappings, or keys.

### [3] `input_reader.py` — get the text
- **Input:** text passed on the command line, a file path (`--file`), or piped stdin, plus the question string.
- **Output:** one string: the input followed by the question in a clearly delimited section, with
  the offset where the question starts.
- **Responsibilities:**
  - Enforce exactly one source; enforce `max_lines` / `max_bytes`.
  - Decode as UTF-8; on invalid bytes, replace them and warn. Refuse input that looks binary
    (contains NUL bytes).
  - Normalize line endings to `\n`.
  - Text argument: empty or whitespace-only text → exit 3. Very large pasted text is limited by
    the OS command-line length (about 32,000 characters on Windows); use `--file` or a pipe for more.
  - Never reads the clipboard.
- **Must not:** write the text anywhere, or inspect its contents beyond size and binary checks.

### [4] `rules_detector.py` — fixed-format patterns
- **Input:** text, config.
- **Output:** `list[Finding]` with `detector="rules"`, `confidence=1.0`.
- **Responsibilities:** regexes for IPv4/IPv6 (classify public, private, loopback, link-local,
  multicast; attach `subnet` to private IPs: first a matching range from `lists/subnets.txt`, then
  a CIDR found in the text, otherwise `/private_subnet_prefix` (default /24)),
  CIDR ranges, MAC addresses, emails, phone numbers, SIDs, cloud account/tenant/subscription
  IDs and ARNs, `user=`/`DOMAIN\user`/UPN patterns, home-folder paths, URLs, certificates,
  credit cards (with Luhn check), IBANs, hostnames/FQDNs ending in internal suffixes
  (`.local`, `.lan`, `.internal`, `.corp`, `.home.arpa`, plus configured suffixes).
- **File paths (mode "segments"):** emit Findings only for the sensitive segments of a path
  (username in home folders, share names in UNC paths, any segment matching a list entry or a
  project/org name). Standard system segments (`C:\Windows`, `/var/log`, `/etc`, file names and
  extensions) are kept.
- **Must not:** detect API keys or tokens (that is [5]) or use the lists (that is [6]).

### [5] `secrets_detector.py` — credentials
- **Input:** text.
- **Output:** `list[Finding]` with `detector="secrets"`, `confidence=1.0`.
- **Responsibilities:**
  - Load the vendored, pinned `rules/gitleaks.toml`; compile its regexes in Python (use the
    `regex` module where Go/RE2 syntax differs) and apply their keyword prefilters.
  - **Every gitleaks rule must load.** A rule that doesn't compile in Python gets a hand-written
    replacement in `rules/overrides.toml` (same rule ID). A test fails if any rule is missing, so
    no rule is ever silently skipped.
  - Add rules gitleaks lacks: PEM/SSH/PGP/PuTTY private-key blocks, password hashes
    (bcrypt, NTLM, shadow), connection strings with credentials, credentials inside URLs,
    `Authorization:` headers, cookies/session IDs, `.env`-style `KEY=value` where the name contains
    KEY/SECRET/TOKEN/PASS/PWD, WireGuard keys, `otpauth://` seeds, SNMP/RADIUS secrets.
  - High-entropy check: strings of 20+ characters with Shannon entropy above a threshold that
    appear next to a secret-like word.
  - Redact only the secret value, not the surrounding key name (`PASSWORD=<PASSWORD_1>`).
- **Must not:** detect non-secret entities.

### [6] `lists_detector.py` — known values
- **Input:** text, the list files in `lists/`.
- **Output:** `list[Finding]` with `detector="lists"`, `confidence=1.0`.
- **List files** (one value per line, `#` comments allowed): `usernames.txt`, `hosts.txt`,
  `domains.txt`, `databases.txt`, `tables.txt`, `columns.txt`, `procedures.txt`, `projects.txt`,
  `orgs.txt`, `packages.txt`, `people.txt`, `custom.txt` (format `TYPE value`).
  `subnets.txt` (one CIDR per line, e.g. `10.20.0.0/16`) is read by [4] for subnet grouping and is
  also matched here as `SUBNET`.
- **Responsibilities:** case-insensitive, whole-word matching (word boundaries treat `.`, `_`, `-`,
  `\`, `/` as separators so `acme_billing.orders` matches table `orders`). Use an Aho-Corasick
  automaton (`pyahocorasick`) so large lists stay fast.
- **Must not:** modify the list files (that is [18]).

### [7] `gliner_detector.py` — model-based entities
- **Input:** text, config.
- **Output:** `list[Finding]` with `detector="gliner"` and the model's score as `confidence`.
- **Responsibilities:**
  - Use the `gliner` Python library with the model named in config (default
    **`nvidia/gliner-pii`**, 55+ entity types). Load it once per run; use CUDA if available,
    otherwise CPU with a one-time warning.
  - Split text into chunks that fit the model's context, with overlap; map chunk offsets back to
    the full text and drop duplicates from the overlap.
  - Labels: person, username, organization, hostname, project name, address, phone number,
    database name, table name, plus other catalog types the model supports.
  - Keep results at or above `threshold`.
- **Must not:** download anything except the model weights (first run only); after that run with
  `HF_HUB_OFFLINE=1`. Never send text over the network.

### [8] `llm_detector.py` — optional local LLM pass (`--deep`)
- **Input:** text, config.
- **Output:** `list[Finding]` with `detector="llm"`.
- **Responsibilities:**
  - Refuse to run if `llm.url` is not localhost/127.0.0.1/::1 (exit 7).
  - Send chunks to Ollama asking for JSON only: `[{"text": "...", "type": "..."}]`.
  - Validate the JSON; locate every returned `text` in the chunk. **Discard any value that does
    not occur verbatim** (stops the model from inventing values). Map to catalog types.
  - Invalid JSON after one retry → exit 7 (fail closed).
- **Must not:** use the model's text as output; it only produces Findings.

### [9] `merger.py` — combine Findings
- **Input:** Findings from all detectors (and from `final_scan` during retries).
- **Output:** a sorted, non-overlapping `list[Finding]`.
- **Responsibilities:**
  - Drop Findings whose type is turned off in config.
  - When Findings overlap, keep the **union span** (over-redact) and pick the type by priority:
    secrets > identity > network > infrastructure > programming > other.
  - Drop Findings that fall entirely inside an existing placeholder.
- **Must not:** change text.

### [10] `masker.py` — replace with placeholders
- **Input:** text, merged Findings, the session `Mapping`.
- **Output:** redacted text and the updated `Mapping`.
- **Responsibilities:**
  - Same real value → same placeholder for the whole session (`jdoe` is always `<USER_1>`).
    Matching is case-sensitive for secrets and case-insensitive for names/hosts.
  - New value → next number for its type: `<TYPE_N>`.
  - Private IPs carry their subnet: `<IP_3 in SUBNET_1>`, where the subnet has its own placeholder
    so the cloud model can see which hosts share a network.
  - Replace from the end of the text backwards so offsets stay valid.
- **Must not:** load or save the mapping (that is [12]).

### [11] `key_manager.py` — encryption key from a passphrase
- **Input:** a passphrase typed at the terminal on every run (once per process).
- **Output:** a Fernet key derived with scrypt (n=2^15, r=8, p=1) from the passphrase and a random salt.
- **Responsibilities:**
  - First run: ask for a new passphrase twice (at least 8 characters); store only the salt
    (`key.salt`) and a check value (`key.check`, used to recognise a wrong passphrase) in the
    config folder. **The key and the passphrase are never stored.**
  - Later runs: ask once; 3 wrong attempts → exit 6.
  - Read the passphrase from the console itself (Windows console / `/dev/tty`), never from stdin,
    an argument, a file or an environment variable, so piped input isn't consumed and no other
    program (including an AI agent running as the user) can supply or recover it.
  - One-time migration: if an older version left a key in Windows Credential Manager or a key
    file, re-encrypt those sessions with the passphrase key, then delete the stored key.
  - Never print or log the key or the passphrase.
- **Must not:** read or write session files (migration is done by [12] when [1] asks it to).

### [12] `session_store.py` — sessions and mappings
- **Input:** session name or current folder; key from [11].
- **Output:** a `Session` (new or loaded).
- **Responsibilities:**
  - Session ID = sha256 of the `--session` name, or of the absolute current folder path.
    File names use the ID, so folder paths are not visible on disk.
  - Load, decrypt, encrypt, and save session files (`cryptography` Fernet). Write atomically
    (temp file + rename) in the sessions folder.
  - Store the conversation ID per target for follow-ups.
  - Delete sessions unused for `session_expiry_days` (checked on every run).
  - `sessions list` (name, last used, counts per type; never real values) and `sessions clear`.
  - `--new-session`: clear the mapping and conversation IDs for this session.
  - A file that can't be decrypted → exit 6 with an explanation (never silently overwrite it).
- **Must not:** do detection or replacement.

### [13] `final_scan.py` — fail-closed check
- **Input:** redacted text, the session `Mapping`.
- **Output:** `list[Finding]` with `detector="final_scan"` (empty means pass).
- **Responsibilities:**
  - Run [4], [5], and [6] on the redacted text, ignoring placeholders.
  - Search the redacted text for **every real value in the mapping**; any match is a leak.
  - Decode hex and base64 blobs (UTF-16LE, UTF-8, Latin-1) and check the decoded text the same way;
    a blob that hides a real value or a detectable secret is reported as `ENCODED` and replaced whole.
    (Found in real use: a Windows event's `<Binary>` field held the server name as UTF-16 hex.)
  - Return all leftovers; `redact_ask.py` sends them back through [9] and [10] (max 2 retries).
  - On final failure the orchestrator prints line, column, and type of each leftover to stderr
    and exits 4.
- **Must not:** run GLiNER or the LLM (it must be fast and deterministic); must not modify text.
- Later phase: reused by `redact_hook.py`.

### [14] `audit_log.py` — record what was sent
- **Input:** redacted text, target, model, session ID, counts per type, retries, status, and the
  redacted answer.
- **Output:** one JSON line per run in `audit.jsonl`.
- **Responsibilities:** write a "sending" entry before the cloud call and complete it afterwards
  with the redacted answer and status (`done` / `error`).
- **Retention:** entries older than `session_expiry_days` (default 14) are deleted on every run, the
  same rule as sessions.
- **Must not:** ever receive the `Mapping` or any real value. Not encrypted (contains only
  redacted data).

### [15] `cloud_runner.py` — send to Claude or Copilot
- **Input:** redacted text, target and optional model, conversation ID (if any).
- **Output:** the answer text (with placeholders) and the new or continued conversation ID.
- **Responsibilities:**
  - Run the CLI in an **empty working folder kept per session** (`<data>/workdirs/<session id>`),
    emptied before every call and deleted with the session. It can't be a fresh temp folder:
    Claude Code stores conversations per working folder, so `--resume` only works from the same one.
  - Pass the redacted text through **stdin**, not as an argument (Windows argument length limit).
    Verified: both `claude -p` and `copilot` (no `-p`) read the prompt from stdin, so
    `copilot_max_arg_chars` is not needed (kept in config only as a fallback). Never enable file
    tools to work around a limit.
  - Flags (verified against Claude Code 2.1.301 and Copilot CLI 1.0.98):
    - Claude: `claude -p --output-format json --tools WebSearch,WebFetch --allowedTools
      WebSearch,WebFetch --strict-mcp-config --disable-slash-commands`, plus `--safe-mode
      --setting-sources "" --system-prompt <instructions>` when isolated (`--append-system-prompt`
      when full); `--session-id <new uuid>` for a new conversation, `--resume <id>` for follow-ups.
    - Copilot: `copilot -s --no-auto-update --no-ask-user --no-remote --disallow-temp-dir
      --available-tools web_fetch --allow-tool web_fetch --session-id <id>` (same flag for new and
      follow-up), plus `--no-custom-instructions --disable-builtin-mcps` when isolated. Copilot has
      no system-prompt option, so the fixed instructions are prepended to the message. Copilot
      CLI has no web search tool; only web fetch is available.
  - If resuming a saved conversation fails, start a new one and warn.
  - **Personal context** (`context` in config, one setting for both targets):
    - `isolated` (default): the cloud receives only a fixed redact-ask instruction, the redacted
      text and question, and the conversation history. User settings, global CLAUDE.md /
      Copilot custom instructions, memories, hooks, and MCP configuration are not loaded; only
      the login is used.
    - `full`: the CLI loads the user's normal setup as in an ordinary session. These files are
      sent **unredacted**; this is the user's choice. Tool restrictions (web only) still apply.
  - **Tools: web search and web fetch only.** Deny file reading and writing, shell, and all MCP
    servers.
    - Claude: `claude -p --output-format json` with `--allowedTools` for the web tools,
      `--disallowedTools` for everything else, an empty MCP config with `--strict-mcp-config`,
      `--model` when given, `--resume <id>` for follow-ups.
    - Copilot: `copilot -p` with its allow/deny tool options and model and resume options.
    - **Exact flags are verified against `claude --help` and `copilot --help` at build time.**
  - Parse the conversation ID from the CLI output; return it to be stored in the session.
  - If the target changes within a session, start a new conversation for that target.
  - Missing CLI, not logged in, non-zero exit, or `cloud_timeout_seconds` reached → exit 5.
- **Must not:** receive the `Mapping`, raw text, or real values.

### [16] `unmasker.py` — restore real values (only with `--restore`)
- **Input:** answer text, the session `Mapping`.
- **Output:** answer with real values.
- **Responsibilities:**
  - Replace exact placeholders (`<USER_1>`, `<IP_3 in SUBNET_1>`).
  - Also accept common variations the model may write: missing angle brackets (`USER_1`),
    backticks, different case.
  - Placeholders not in the mapping (the model invented one) are left as-is with a warning.
- **Must not:** write anything to disk.

### [17] `output_writer.py` — show the answer
- **Input:** the answer (raw, or restored with `--restore`), optional `--out` path.
- **Output:** stdout, and the file if requested (UTF-8, overwrites with a warning if it exists).
- **Must not:** write the answer anywhere else.

### [18] `learner.py` — grow the lists
- **Input:** Findings from [7] and [8] whose value is not already in a list and whose type has a
  list file.
- **Output:** approved values appended to the matching list file.
- **Responsibilities:**
  - After the answer is printed, show each candidate with its type and a few characters of
    context; ask `y / n / a(ll) / s(kip all)`.
  - Read the answer from the terminal directly (`CONIN$` on Windows, `/dev/tty` on Debian) so it
    works when the input was piped. If no terminal is available, **or stderr is not a terminal**
    (a scripted run such as `2>&1 | grep`, where nobody can answer), skip and print a note.
  - Ignore duplicates; keep list files sorted.
- **Must not:** run if nothing new was found; must not change Findings or the mapping.

## Redaction Catalog

Type names are the placeholder prefixes. Every type below is listed in `[types]` in the config with its
default, and any of them can be switched on or off (switching off an "always" type prints a warning on every run).

### Always redacted
| Type | Covers |
|---|---|
| `API_KEY` | Cloud and SaaS API keys (AWS key IDs, GitHub, Slack, Stripe, OpenAI, Anthropic, …) |
| `TOKEN` | Bearer/OAuth access and refresh tokens, JWTs, `Authorization:` headers |
| `PASSWORD` | Passwords in configs, URLs, CLI arguments, `password=` |
| `HASH` | Password hashes (bcrypt, NTLM, shadow entries) |
| `PRIVATE_KEY` | PEM, SSH, PGP, PuTTY private-key blocks |
| `CONN_STRING` | Database URIs / connection strings with credentials |
| `CLOUD_SECRET` | AWS secret keys, Azure storage keys and SAS tokens, GCP service-account JSON |
| `SIGNED_URL` | Pre-signed URLs; webhook URLs with embedded secrets (Slack, Discord, Teams) |
| `SESSION` | Session cookies, session IDs, CSRF tokens |
| `SECRET` | App secrets, encryption and signing keys, secret-named `.env` values |
| `VPN_KEY` | WireGuard private keys, VPN pre-shared keys, Wi-Fi passwords |
| `OTP_SEED` | TOTP/2FA seeds, recovery codes |
| `REGISTRY_AUTH` | npm/PyPI/NuGet tokens, Docker `config.json` auth, kubeconfig tokens |
| `GIT_CRED` | Credentials inside Git URLs |
| `NET_SECRET` | SNMP community strings, RADIUS shared secrets, BGP/OSPF passwords |
| `HIGH_ENTROPY` | Random-looking strings next to key/token/secret words |
| `ENCODED` | Hex/base64 blobs whose decoded content contains a sensitive value |
| `USER` | Usernames (system, `DOMAIN\user`, UPN, names in home paths) |
| `EMAIL` | Email addresses, including Git author emails |
| `PERSON` | People's names |
| `SID` | Windows SIDs |
| `PHONE`, `ADDRESS` | Phone numbers, physical addresses |
| `GOV_ID`, `CARD`, `BANK` | National ID numbers, credit cards, IBANs and bank accounts |
| `IP` (public) | Public IPv4/IPv6 |
| `MAC` | MAC addresses, BSSIDs |
| `HOST` | Internal hostnames/FQDNs, server, VM, and domain controller names |
| `DOMAIN` (internal) | Internal / AD domains |
| `CLOUD_ID` | AWS account IDs, Azure tenant/subscription IDs, GCP project IDs, ARNs, resource IDs |

### Configurable — on by default
| Type | Covers |
|---|---|
| `IP` (private) | 10.x, 172.16–31.x, 192.168.x — written as `<IP_n in SUBNET_m>` |
| `SUBNET` | CIDR ranges |
| `DOMAIN` (public, owned) | Public domains you own (from `domains.txt`) |
| `URL` | Internal URLs and API endpoints |
| `SSID` | Wi-Fi network names |
| `VPN_ID` | Tailnet names, ZeroTier network IDs, Cloudflare tunnel IDs, VPN endpoints |
| `CERT` | Certificate subjects, SANs, thumbprints, fingerprints |
| `CLUSTER` | Kubernetes cluster/namespace, Proxmox node, Swarm names |
| `IMAGE` | Images from private registries |
| `SERIAL` | Hardware serials, asset tags, BIOS/system UUIDs, disk serials |
| `LICENSE` | License and product keys |
| `MACHINE_ID` | `/etc/machine-id`, Windows MachineGuid, device IDs |
| `DB`, `TABLE`, `COLUMN` | Database, schema, table, column names |
| `PROC` | Stored procedures, views, triggers |
| `SQL_VALUE` | Literal values in SQL queries and INSERT rows |
| `ENV_VALUE` | All `.env` / config values, not only secret-named ones |
| `REPO`, `ORG` | Git remote URLs, repository and organization names |
| `PACKAGE` | Internal package/module names |
| `ORG_NAME` | Company, client, product names |
| `CUSTOMER_ID` | Customer, account, order, ticket numbers |
| `PATH` | Sensitive path segments only (mode "segments") |
| `PROJECT` | Project names (in paths and text) |

### Configurable — off by default
| Type | Covers |
|---|---|
| `BUCKET` | Storage bucket/container names (**turned off by user decision**) |
| `IP` (loopback, link-local, multicast) | `127.0.0.1`, `::1`, `169.254.x`, `224.x` |
| `PORT` | Port numbers |
| `VLAN` | VLAN IDs |
| `UUID` | Generic UUIDs/GUIDs (request IDs, container IDs) |
| `UID` | Unix UIDs/GIDs |
| `BRANCH` | Git branch names |
| `TIME` | Timestamps |
| `PROCESS` | Process/service names, PIDs |
| `GEO` | Time zones, locale, GPS/EXIF coordinates |
| `VERSION` | Software versions |

List-backed types (`USER`, `HOST`, `DOMAIN`, `DB`, `TABLE`, `COLUMN`, `PROC`, `PROJECT`, `ORG`,
`ORG_NAME`, `PACKAGE`, `PERSON`) are detected from **both** the lists and GLiNER.

## Success Criteria
- [ ] Every file in `tests/corpus/` is redacted with **100% of planted values caught** for the rule-based,
      secret, and list-backed types; the tests fail on any miss.
- [ ] GLiNER-backed types (names, unlisted hosts/projects) catch **at least 95%** of planted values
      in the corpus. Measure a baseline first, then lower `threshold` until the target is met.
- [ ] Every rule in the pinned gitleaks rule set loads (directly or via `rules/overrides.toml`).
- [ ] In `isolated` mode, no personal instructions, memories, or MCP servers are loaded (verified by
      putting a marker string in a test CLAUDE.md and checking the cloud never sees it).
- [ ] No unredacted text is ever written to disk (verified by a test that runs the pipeline with a
      watched temp/sessions folder).
- [ ] Nothing is sent when any stage before `cloud_runner` fails (one test per failure path).
- [ ] The same value gets the same placeholder across two runs in one session; a different session
      gets independent numbering.
- [ ] By default the answer is printed exactly as the model wrote it; with `--restore` it contains
      the original values for every known placeholder.
- [ ] Works on Windows 11 and Debian (passphrase prompt works in both).
- [ ] The cloud CLI cannot read local files or run commands (verified by asking it to read a known
      file and checking that it can't).
- [ ] A 5,000-line log is processed (excluding the cloud call) in under 30 s on the RTX PRO 2000
      laptop. _(Target to confirm after measuring.)_

## Decisions
| Decision | Rationale | Date |
|---|---|---|
| Custom CLI wrapper, not hooks or a proxy | Only option that guarantees redaction runs before anything is sent; hooks can block but not rewrite, and don't see tool output | 2026-10-16 |
| Python 3.11+, run from the project folder | GLiNER and the secret tooling are Python-native; no packaging needed | 2026-10-16 |
| Inputs: file, stdin, clipboard (no folders) — clipboard superseded by the next row | Matches the user's workflows | 2026-10-16 |
| Default input is text passed on the command line; files need `--file`; `--clip` removed and the clipboard is never read | User decision | 2026-10-16 |
| GLiNER called directly; no Presidio | Our scripts already merge and replace; fewer dependencies and a visible data flow | 2026-10-16 |
| Gitleaks rules run in Python, not the binary | Avoids writing unredacted text to a temp file for the binary | 2026-10-16 |
| Local LLM pass optional, off by default (`--deep`) | GLiNER first; LLM adds cost and latency | 2026-10-16 |
| Over-redact when unsure | A missed secret is worse than lost context | 2026-10-16 |
| Placeholders `<TYPE_N>`; private IPs `<IP_n in SUBNET_m>` | Easy to unmask; keeps network relationships visible | 2026-10-16 |
| Mapping persisted per session (default: per folder; `--session NAME`) | Consistent placeholders for follow-up questions | 2026-10-16 |
| Mappings encrypted (Fernet) with the key in the OS keyring; 600-mode key file fallback on headless Debian — superseded by the passphrase row below | Works on Windows and Debian; no passphrase to type | 2026-10-16 |
| Lists, mappings, config stored in user folders, never the project folder | They contain real sensitive values; avoid git commits and cloud tools reading them | 2026-10-16 |
| Sessions expire after 14 unused days (configurable) | Limit how long real values sit on disk | 2026-10-16 |
| No preview by default; send automatically when the final scan passes — superseded: preview is now on by default | User preference | 2026-10-16 |
| Final scan failure: re-redact and rescan, max 2 retries, then abort | Fixes simple misses automatically while staying fail-closed | 2026-10-16 |
| Follow-ups continue the same cloud conversation | Cloud model keeps context | 2026-10-16 |
| Default target in config; `--to target[:model]` overrides per prompt | User preference | 2026-10-16 |
| Cloud CLI runs in an empty temp folder with web search/fetch only | Local tools could read unredacted files and bypass redaction | 2026-10-16 |
| Real values restored in the answer; printed to stdout, optional `--out` — superseded by the next row | User preference | 2026-10-16 |
| Default output is the model's answer as written (placeholders); `--restore` shows real values | User decision | 2026-10-16 |
| New GLiNER/LLM values approved interactively before being added to lists | Lists stay accurate without manual editing | 2026-10-16 |
| Audit log stores redacted text and redacted answer plus metadata | Shows exactly what left the machine | 2026-10-16 |
| Input limit 5,000 lines / 1 MB | Keeps runs fast; matches typical use | 2026-10-16 |
| GLiNER falls back to CPU without an NVIDIA GPU | Works on Debian machines without a GPU | 2026-10-16 |
| Redaction catalog defaults accepted, except `BUCKET` off | User decision | 2026-10-16 |
| Paths: redact sensitive segments only (option a) | Keeps paths useful for debugging | 2026-10-16 |
| List-backed types use lists **and** GLiNER | Over-redact | 2026-10-16 |
| Hook tripwires (`redact_hook.py`) deferred to a later phase | Wrapper first | 2026-10-16 |
| Config is TOML in the user config folder | Assumed default; not explicitly chosen by the user | 2026-10-16 |
| Audit log also stores the redacted answer | Assumed default; not explicitly chosen by the user | 2026-10-16 |
| If `copilot -p` can't read stdin, cap Copilot input at the argument limit and refuse larger input | Keeps Copilot's file tools locked down | 2026-10-16 |
| Config toggle `context = "isolated" \| "full"`, default isolated, one setting for both targets | Personal CLAUDE.md, memories and instructions would otherwise bypass redaction; user can opt into normal behavior | 2026-10-16 |
| Gitleaks rules that don't compile in Python are rewritten by hand; a test blocks release if any rule is missing | Full secret coverage, nothing skipped silently | 2026-10-16 |
| GLiNER target: ≥95% of planted values, tuned after a baseline | Realistic for a model; misses become list entries via the approval prompt | 2026-10-16 |
| Audit log entries expire with the session rule (14 days) | One retention rule | 2026-10-16 |
| Subnet guess /24 for private IPs, overridden by `lists/subnets.txt` | Fits typical home/lab networks; real ranges win | 2026-10-16 |
| Final scan decodes hex/base64 blobs and redacts any that hide sensitive values (`ENCODED`) | A Windows event's binary data leaked a server name | 2026-10-16 |
| Session key derived from a passphrase typed each run; no stored key (Credential Manager / key file removed, old sessions migrated) | An AI agent running as the user decrypted the mapping while debugging; a stored key can't stop that | 2026-10-16 |
| `reset-passphrase` command deletes all sessions and sets a new passphrase, confirmed by typing RESET | Forgetting the passphrase shouldn't require manual file deletion | 2026-10-16 |
| The question must be given with `-q`/`--query`; a bare argument is only ever the text to analyze | A mistyped command (`rt-passphrase`) was treated as a question; no guessing which words are commands | 2026-10-16 |
| `--preview` (confirm before sending, answer read from the console; cancel logged as `cancelled`) and `--dry-run` (show and stop, nothing logged); `preview = true` in config makes preview the default | User wants to see the redacted text before it leaves the machine | 2026-10-16 |
| Preview on by default (`preview = true`) | User decision | 2026-10-16 |
| Every redaction type is listed in `[types]` with its default and can be turned on or off, including the former "always" types (turning one of those off prints a warning on every run); only the internal `LITERAL` escaping can't be turned off | User wants to allow everything or redact everything from the config | 2026-10-16 |
| `sessions show` (print the mapping) not added | User decision: no tool that prints real values | 2026-10-16 |
| Web search/fetch risk accepted | Only placeholders can leave via search queries | 2026-10-16 |
| Cloud CLI runs in a per-session empty folder instead of a fresh temp folder | Claude Code resumes conversations per working folder | 2026-10-16 |
| Learner doesn't prompt when stderr isn't a terminal | Scripted runs would otherwise hang waiting for an answer | 2026-10-16 |
| Merged overlaps: a containing finding keeps its type (IMAGE over HOST) unless it is generic (ENV_VALUE, SQL_VALUE, ...) or the inner one is a secret | Keeps placeholders meaningful while never downgrading a secret | 2026-10-16 |
| `REDACT_ASK_HOME` puts all user folders in one place; tests replace the passphrase prompt | Used by the tests so they never touch real data, the real keyring or a real terminal | 2026-10-16 |
| GLiNER model: `nvidia/gliner-pii` by default; `urchade/gliner_multi_pii-v1` kept as the alternative in config | Newest GLiNER PII model with the broadest type coverage (55+); best published results at threshold 0.3 | 2026-10-16 |

## Edge Cases & Failure Behavior
- **More than one input source** (text and `--file`, or either with piped stdin) → exit 2.
- **Empty input** → exit 3. **Question only, no input** → allowed; the question is still redacted.
- **Input too large** → exit 3 with the actual size and limit.
- **Invalid UTF-8** → replace bad bytes, warn; **binary** → exit 3.
- **GLiNER model missing and offline** → exit 7 with download instructions; nothing sent.
- **Ollama not running with `--deep`** → exit 7 (never silently skip a requested pass).
- **Wrong passphrase 3 times, or no terminal to ask for it** (e.g. run from a scheduled task) → exit 6;
  nothing is sent.
- **Forgotten passphrase** → sessions can't be recovered; `reset-passphrase` (after typing RESET at
  the console) deletes all sessions and working folders, removes `key.salt`/`key.check`, and asks for
  a new passphrase. Config, lists and the audit log are kept.
- **Session file can't be decrypted** (key changed) → exit 6; suggest `sessions clear NAME`.
- **Placeholder-like text already in the input** (`<USER_1>` in the original) → escape it before
  masking so it can't be confused with a real placeholder, and restore it in the output.
- **The same value with different types** (e.g. a username that is also a hostname) → one
  placeholder per value; type chosen by priority in [9].
- **Overlapping detections** → union span, highest-priority type.
- **Cloud answer invents placeholders** → left as-is with a warning.
- **Cloud CLI not logged in / not installed / timeout** → exit 5; the audit entry is marked `error`.
- **Target changed mid-session** → new conversation for that target; mapping is shared.
- **No terminal for the learner prompt** → skip and print a note.

## Open Questions & Risks
### Resolved during the build (2026-10-16)
- **CLI flags:** verified; see [15]. Both CLIs read stdin, resume by ID, and were confirmed (live
  tests) unable to read a local file or run a shell command.
- **Gitleaks conversion:** all 222 rules of v8.30.1 compile with the `regex` module (VERSION1);
  no overrides needed. 221 have regexes; `pkcs12-file` matches file names only and doesn't apply to text.
- **GLiNER:** `nvidia/gliner-pii` at threshold 0.3 catches 24/25 (96%) GLiNER-only values in the
  corpus, with 100% of rule-based values. The urchade model was not needed.
- **`nvidia/gliner-pii` license:** NVIDIA Open Model License. Labels mapped in `gliner_detector.LABELS`.
- **Performance:** the whole corpus (15 files) runs in about 14 s including model load (~7 s) on the
  RTX PRO 2000.

### Still open
- **Claude Code attaches the account email.** Even in isolated mode, Claude Code adds the
  logged-in account's email address to the request context. It is the account's own email (already
  known to Anthropic), but it is not redacted and no option to turn it off was found.
- **CPU-only speed** (Debian without a GPU) has not been measured.
- **Debian** has not been tested yet.
- **Over-redaction:** union spans sometimes hide useful context (for example a whole connection
  string becomes one `<SECRET_n>`); acceptable under the over-redact decision, revisit if answers
  suffer.
