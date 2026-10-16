"""[5] Credentials: gitleaks rules plus extra secret patterns (SPEC: secrets_detector.py).

Only the secret value is redacted, not the key name around it (PASSWORD=<PASSWORD_1>).
"""
from __future__ import annotations

import math
import re
import tomllib
from collections import Counter
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import regex

from .models import DetectorError, Finding, PLACEHOLDER_RE

DETECTOR = "secrets"
RULES_DIR = Path(__file__).resolve().parent / "rules"
GITLEAKS_FILE = RULES_DIR / "gitleaks.toml"
OVERRIDES_FILE = RULES_DIR / "overrides.toml"


# ---------------------------------------------------------------------------
# Gitleaks rules
# ---------------------------------------------------------------------------
@dataclass
class Allowlist:
    target: str = "secret"         # secret | match | line
    condition: str = "OR"
    regexes: list = field(default_factory=list)
    stopwords: list[str] = field(default_factory=list)

    def allows(self, secret: str, match: str, line: str) -> bool:
        target = {"secret": secret, "match": match, "line": line}.get(self.target, secret)
        checks = []
        if self.regexes:
            checks.append(any(r.search(target) for r in self.regexes))
        if self.stopwords:
            low = secret.lower()
            checks.append(any(w in low for w in self.stopwords))
        if not checks:
            return False
        return all(checks) if self.condition.upper() == "AND" else any(checks)


@dataclass
class Rule:
    id: str
    regex: object | None
    secret_group: int
    entropy: float
    keywords: list[str]
    allowlists: list[Allowlist]
    type: str


def _compile(pattern: str, rule_id: str):
    try:
        return regex.compile(pattern, regex.V1)
    except regex.error as e:
        raise DetectorError(f"gitleaks rule '{rule_id}' does not compile in Python ({e}); "
                            f"add a replacement to {OVERRIDES_FILE.name}.") from e


def _allowlist(d: dict, rule_id: str) -> Allowlist:
    return Allowlist(
        target=d.get("regexTarget", "secret"),
        condition=d.get("condition", "OR"),
        regexes=[_compile(p, rule_id) for p in d.get("regexes", [])],
        stopwords=[w.lower() for w in d.get("stopwords", [])],
    )


def type_for_rule(rule_id: str) -> str:
    rid = rule_id.lower()
    if "private-key" in rid or rid.endswith("-pem") or "pkcs12" in rid:
        return "PRIVATE_KEY"
    if "webhook" in rid:
        return "SIGNED_URL"
    if rid.startswith(("npm-", "pypi", "nuget", "rubygems", "docker", "artifactory", "clojars")):
        return "REGISTRY_AUTH"
    if "password" in rid:
        return "PASSWORD"
    if rid == "jwt" or "jwt" in rid:
        return "TOKEN"
    if rid.startswith(("aws-", "azure-", "gcp-")) and ("secret" in rid or "storage" in rid):
        return "CLOUD_SECRET"
    if rid.startswith("generic-"):
        return "SECRET"
    if "token" in rid or "pat" in rid.split("-"):
        return "TOKEN"
    if "secret" in rid:
        return "SECRET"
    return "API_KEY"


@lru_cache(maxsize=1)
def load_rules() -> tuple[list[Rule], Allowlist, list[str]]:
    """Return (rules, global allowlist, ids of path-only rules that don't apply to text)."""
    data = tomllib.loads(GITLEAKS_FILE.read_text(encoding="utf-8"))
    overrides = {}
    if OVERRIDES_FILE.exists():
        odata = tomllib.loads(OVERRIDES_FILE.read_text(encoding="utf-8"))
        overrides = {r["id"]: r for r in odata.get("rules", [])}
    rules, path_only = [], []
    for raw in data.get("rules", []):
        raw = overrides.get(raw["id"], raw)
        if not raw.get("regex"):
            path_only.append(raw["id"])   # e.g. pkcs12-file: matches file names, not text
            continue
        rules.append(Rule(
            id=raw["id"],
            regex=_compile(raw["regex"], raw["id"]),
            secret_group=int(raw.get("secretGroup", 0)),
            entropy=float(raw.get("entropy", 0.0)),
            keywords=[k.lower() for k in raw.get("keywords", [])],
            allowlists=[_allowlist(a, raw["id"]) for a in raw.get("allowlists", [])],
            type=type_for_rule(raw["id"]),
        ))
    g = data.get("allowlist", {})
    global_allow = Allowlist(regexes=[_compile(p, "global") for p in g.get("regexes", [])],
                             stopwords=[w.lower() for w in g.get("stopwords", [])])
    return rules, global_allow, path_only


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start: end if end != -1 else len(text)]


def _gitleaks(text: str, out: list[Finding]) -> None:
    rules, global_allow, _ = load_rules()
    low = text.lower()
    for rule in rules:
        if rule.keywords and not any(k in low for k in rule.keywords):
            continue
        for m in rule.regex.finditer(text):
            if rule.secret_group:
                g = rule.secret_group
            else:
                g = next((i for i in range(1, len(m.groups()) + 1) if m.group(i)), 0)
            secret = m.group(g)
            if not secret or not secret.strip():
                continue
            start, end = m.span(g)
            if rule.entropy:
                if shannon_entropy(secret) <= rule.entropy:
                    continue
                if rule.id.startswith("generic") and not any(ch.isdigit() for ch in secret):
                    continue
            line = _line_at(text, start)
            if global_allow.allows(secret, m.group(0), line):
                continue
            if any(a.allows(secret, m.group(0), line) for a in rule.allowlists):
                continue
            if PLACEHOLDER_RE.fullmatch(secret.strip("\"'")):
                continue
            out.append(_finding(text, start, end, rule.type))


# ---------------------------------------------------------------------------
# Extra rules (things gitleaks lacks or handles only per file type)
# ---------------------------------------------------------------------------
I, M = re.IGNORECASE, re.MULTILINE
_VAL = r"[\"']?([^\s\"',;<>]+)[\"']?"
_EMPTY = {"", "null", "none", "nil", "true", "false", "changeme", "xxx", "***", "****", "*****", "-",
          "<redacted>", "redacted", "undefined", "''", '""'}

EXTRA: list[tuple[re.Pattern, str, int]] = [
    # Private keys and certificates with keys
    (re.compile(r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END (?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?-----"), "PRIVATE_KEY", 0),
    (re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]*?-----END PGP PRIVATE KEY BLOCK-----"), "PRIVATE_KEY", 0),
    (re.compile(r"PuTTY-User-Key-File-\d+:[\s\S]*?Private-MAC:\s*[0-9a-fA-F]+"), "PRIVATE_KEY", 0),
    (re.compile(r"\"private_key\"\s*:\s*\"(-----BEGIN[^\"]+)\""), "PRIVATE_KEY", 1),
    # Password hashes
    (re.compile(r"\$2[abxy]?\$\d{2}\$[./A-Za-z0-9]{53}"), "HASH", 0),
    (re.compile(r"\$(?:1|5|6|md5|sha1|apr1)\$(?:rounds=\d+\$)?[./A-Za-z0-9]{1,16}\$[./A-Za-z0-9]{22,86}"), "HASH", 0),
    (re.compile(r"\$(?:y|gy|7)\$[./A-Za-z0-9$]{20,}"), "HASH", 0),
    (re.compile(r"\$argon2(?:id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=$]+"), "HASH", 0),
    (re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{32}:[0-9a-fA-F]{32}(?![0-9a-fA-F])"), "HASH", 0),          # LM:NT
    (re.compile(r"^[\w.-]+:(\$[^:\s]{8,}):\d*:", M), "HASH", 1),                                            # /etc/shadow
    # Connection strings and credentials in URLs
    (re.compile(r"\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis(?:s)?|amqps?|mssql|sqlserver|oracle|"
                r"jdbc:[a-z]+|clickhouse|cockroachdb|neo4j|couchdb|ldaps?|ftp|sftp)://[^\s:@/\"']*:[^\s@\"']+@[^\s\"'<>]+", I),
     "CONN_STRING", 0),
    (re.compile(r"(?:(?:Server|Data Source|Host|Address)\s*=\s*[^;\"'\n]+;)(?:[^;\"'\n]+;)*?\s*(?:Password|Pwd)\s*=\s*[^;\"'\n]+;?(?:[^;\"'\n]*;?)*", I),
     "CONN_STRING", 0),
    (re.compile(r"\b(?:https?|git|ssh|svn)://([^\s:@/\"']+:[^\s@/\"']+)@", I), "GIT_CRED", 1),
    (re.compile(r"\bhttps?://([A-Za-z0-9_-]{20,})@(?:github\.com|gitlab\.com|bitbucket\.org)", I), "GIT_CRED", 1),
    # Authorization headers, cookies, sessions
    (re.compile(r"\b(?:Proxy-)?Authorization\s*[:=]\s*[\"']?(?:Bearer|Basic|Token|Digest|NTLM|Negotiate|Bot|ApiKey|SharedKey)?\s*([^\s\"',;]{8,})", I), "TOKEN", 1),
    (re.compile(r"\b(?:X-Api-Key|X-Auth-Token|X-Access-Token|Api-Key|X-Functions-Key)\s*[:=]\s*[\"']?([^\s\"',;]{8,})", I), "API_KEY", 1),
    (re.compile(r"^(?:Set-)?Cookie:\s*(.+)$", I | M), "SESSION", 1),
    (re.compile(r"\b(?:sessionid|session[_-]?id|sid|phpsessid|jsessionid|asp\.net_sessionid|connect\.sid|csrftoken|csrf[_-]?token|xsrf[_-]?token|_session|session[_-]?token)[\"']?[ \t]*[=:][ \t]*[\"']?([\w.%+/=-]{8,})", I),
     "SESSION", 1),
    # Key/value secrets in .env, YAML, JSON, INI, CLI flags
    (re.compile(r"(?:^|[\s,{;(\"'])((?:[\w.-]*?)(?:passw(?:or)?d|passwd|pwd|pass(?=[_.\-\s\"':=])))[\"']?[ \t]*(?:=|:|=>)[ \t]*" + _VAL, I | M), "PASSWORD", 2),
    (re.compile(r"(?:^|[\s,{;(\"'])((?:[\w.-]*?)(?:secret|private[_.-]?key|signing[_.-]?key|encryption[_.-]?key|master[_.-]?key|client[_.-]?secret|app[_.-]?key|credential)s?[\w.-]*)[\"']?[ \t]*(?:=|:|=>)[ \t]*" + _VAL, I | M), "SECRET", 2),
    (re.compile(r"(?:^|[\s,{;(\"'])((?:[\w.-]*?)(?:token|auth)[\w.-]*)[\"']?[ \t]*(?:=|:|=>)[ \t]*" + _VAL, I | M), "TOKEN", 2),
    (re.compile(r"(?:^|[\s,{;(\"'])((?:[\w.-]*?)(?:api[_.-]?key|access[_.-]?key|apikey|subscription[_.-]?key)[\w.-]*)[\"']?[ \t]*(?:=|:|=>)[ \t]*" + _VAL, I | M), "API_KEY", 2),
    (re.compile(r"(?:^|\s)--?(?:password|passwd|pass|pwd|pw|secret|token|api-key|apikey)[= ]\s*" + _VAL, I | M), "PASSWORD", 1),
    (re.compile(r"\b(?:PGPASSWORD|MYSQL_PWD|SSHPASS|REDISCLI_AUTH)\s*=\s*" + _VAL), "PASSWORD", 1),
    # Cloud secrets
    (re.compile(r"\baws_?secret_?access_?key[\"']?\s*[:=]\s*[\"']?([A-Za-z0-9/+=]{40})\b", I), "CLOUD_SECRET", 1),
    (re.compile(r"\bAccountKey\s*=\s*([A-Za-z0-9+/=]{40,100})", I), "CLOUD_SECRET", 1),
    (re.compile(r"\bSharedAccessKey\s*=\s*([A-Za-z0-9+/=]{20,100})", I), "CLOUD_SECRET", 1),
    (re.compile(r"\"private_key_id\"\s*:\s*\"([0-9a-f]{40})\""), "CLOUD_SECRET", 1),
    # Signed URLs and webhooks (whole URL)
    (re.compile(r"\bhttps?://[^\s\"'<>]*[?&](?:X-Amz-Signature|X-Goog-Signature|sig|Signature|se=[^&\s]+&sp|token|code)=[^\s\"'<>]+", I), "SIGNED_URL", 0),
    (re.compile(r"\bhttps://(?:hooks\.slack\.com/(?:services|workflows|triggers)/[^\s\"'<>]+|(?:discord(?:app)?\.com)/api/webhooks/[^\s\"'<>]+|[\w-]+\.webhook\.office\.com/[^\s\"'<>]+|outlook\.office\.com/webhook/[^\s\"'<>]+|[\w.-]+\.logic\.azure\.com[^\s\"'<>]*sig=[^\s\"'<>]+)", I),
     "SIGNED_URL", 0),
    # VPN / Wi-Fi
    (re.compile(r"^\s*(?:PrivateKey|PresharedKey)\s*=\s*([A-Za-z0-9+/]{42,43}=)", I | M), "VPN_KEY", 1),
    (re.compile(r"\b(?:wpa_passphrase|wpa-psk|psk|pre-?shared[_ -]?key|wifi[_ -]?password|wireless[_ -]?key)\s*[=:]\s*[\"']?([^\s\"']{6,})", I), "VPN_KEY", 1),
    (re.compile(r"\bcrypto isakmp key\s+(\S+)", I), "VPN_KEY", 1),
    # OTP seeds and recovery codes
    (re.compile(r"\botpauth://[^\s\"'<>]+", I), "OTP_SEED", 0),
    (re.compile(r"\b(?:totp|2fa|mfa|otp)[_ -]?(?:secret|seed|key)\s*[:=]\s*[\"']?([A-Z2-7]{16,}=*)", I), "OTP_SEED", 1),
    (re.compile(r"\brecovery[_ -]?codes?\s*[:=]\s*((?:[A-Za-z0-9-]{6,}[\s,]*){1,16})", I), "OTP_SEED", 1),
    # Registries and package managers
    (re.compile(r"\"auth\"\s*:\s*\"([A-Za-z0-9+/=]{8,})\""), "REGISTRY_AUTH", 1),
    (re.compile(r"_authToken\s*=\s*([^\s\"']+)"), "REGISTRY_AUTH", 1),
    (re.compile(r"\b_auth\s*=\s*([^\s\"']+)"), "REGISTRY_AUTH", 1),
    (re.compile(r"\bpypi-[A-Za-z0-9_-]{50,}"), "REGISTRY_AUTH", 0),
    (re.compile(r"^\s*(?:token|client-key-data|client-certificate-data)\s*:\s*[\"']?([^\s\"']{16,})", I | M), "REGISTRY_AUTH", 1),
    (re.compile(r"<add\s+key=\"(?:ClearText)?Password\"\s+value=\"([^\"]+)\"", I), "REGISTRY_AUTH", 1),
    # Network device secrets
    (re.compile(r"\bsnmp-server community\s+(\S+)", I), "NET_SECRET", 1),
    (re.compile(r"\b(?:community|rocommunity|rwcommunity|snmp[_ -]?community)\s*[=: ]\s*[\"']?([^\s\"']+)", I), "NET_SECRET", 1),
    (re.compile(r"\b(?:radius-server|tacacs-server|radius|tacacs)\s+(?:host\s+\S+\s+)?key\s+(?:\d\s+)?(\S+)", I), "NET_SECRET", 1),
    (re.compile(r"\bneighbor\s+\S+\s+password\s+(?:\d\s+)?(\S+)", I), "NET_SECRET", 1),
    (re.compile(r"\b(?:authentication-key|message-digest-key\s+\d+\s+md5)\s+(?:\d\s+)?(\S+)", I), "NET_SECRET", 1),
    (re.compile(r"\b(?:enable\s+secret|enable\s+password|username\s+\S+\s+(?:privilege\s+\d+\s+)?(?:secret|password))\s+(?:\d+\s+)?(\S+)", I), "NET_SECRET", 1),
    (re.compile(r"\bkey-string\s+(?:\d\s+)?(\S+)", I), "NET_SECRET", 1),
    # JWTs anywhere
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "TOKEN", 0),
]

_SECRET_WORD_RE = re.compile(r"key|token|secret|pass|pwd|auth|credential|signature|\bsig\b|bearer|cookie|session|apikey", I)
_TOKEN_RE = re.compile(r"(?<![\w+/=-])[A-Za-z0-9+/_-]{20,}={0,2}(?![\w+/=-])")
_UUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
HIGH_ENTROPY_MIN = 3.5
_PWD_DIR_RE = re.compile(r"(?:^|[^\w])(?:OLD)?PWD[ \t]*=[ \t]*$")
# Key/value patterns like "auth: failed" would otherwise redact ordinary words.
_MIN_LEN = {"TOKEN": 8, "API_KEY": 8, "SECRET": 6}


def _finding(text: str, start: int, end: int, type_: str) -> Finding:
    return Finding(start, end, text[start:end], type_, DETECTOR, 1.0)


def _extra(text: str, out: list[Finding]) -> None:
    for pattern, type_, group in EXTRA:
        for m in pattern.finditer(text):
            value = m.group(group)
            if value is None:
                continue
            start, end = m.span(group)
            # trim surrounding quotes/whitespace
            while start < end and text[start] in " \t\"'":
                start += 1
            while end > start and text[end - 1] in " \t\"',;":
                end -= 1
            value = text[start:end]
            if value.lower() in _EMPTY or len(value) < _MIN_LEN.get(type_, 3):
                continue
            if type_ == "PASSWORD" and value[:1] in "/~" and _PWD_DIR_RE.search(text[max(0, start - 12):start]):
                continue   # sudo/shell "PWD=/home/x" is the working directory, not a password
            if PLACEHOLDER_RE.fullmatch(value) or value.startswith(("${", "$(", "{{", "%")) and value.endswith(("}", ")", "%")):
                continue
            out.append(_finding(text, start, end, type_))


def _high_entropy(text: str, out: list[Finding]) -> None:
    pos = 0
    for line in text.split("\n"):
        if _SECRET_WORD_RE.search(line):
            for m in _TOKEN_RE.finditer(line):
                tok = m.group(0)
                if _UUID_RE.fullmatch(tok) or PLACEHOLDER_RE.search(tok):
                    continue
                has_alpha = any(ch.isalpha() for ch in tok)
                has_digit = any(ch.isdigit() for ch in tok)
                if has_alpha and has_digit and shannon_entropy(tok) >= HIGH_ENTROPY_MIN:
                    out.append(_finding(text, pos + m.start(), pos + m.end(), "HIGH_ENTROPY"))
        pos += len(line) + 1


def detect(text: str) -> list[Finding]:
    out: list[Finding] = []
    _gitleaks(text, out)
    _extra(text, out)
    _high_entropy(text, out)
    return out
