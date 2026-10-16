"""Shared data structures, the redaction type catalog, and errors used by every script."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Errors and exit codes (SPEC: Exit codes)
# ---------------------------------------------------------------------------
EXIT_OK = 0
EXIT_USAGE = 2
EXIT_INPUT = 3
EXIT_SCAN_ABORT = 4
EXIT_CLOUD = 5
EXIT_STORAGE = 6
EXIT_DETECTOR = 7


class RedactAskError(Exception):
    """An error that maps to one of the SPEC exit codes."""

    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


class UsageError(RedactAskError):
    def __init__(self, message: str):
        super().__init__(EXIT_USAGE, message)


class InputError(RedactAskError):
    def __init__(self, message: str):
        super().__init__(EXIT_INPUT, message)


class ScanAbort(RedactAskError):
    def __init__(self, message: str):
        super().__init__(EXIT_SCAN_ABORT, message)


class CloudError(RedactAskError):
    def __init__(self, message: str):
        super().__init__(EXIT_CLOUD, message)


class StorageError(RedactAskError):
    def __init__(self, message: str):
        super().__init__(EXIT_STORAGE, message)


class DetectorError(RedactAskError):
    def __init__(self, message: str):
        super().__init__(EXIT_DETECTOR, message)


# ---------------------------------------------------------------------------
# Data structures (SPEC: Shared Data Structures)
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Finding:
    start: int
    end: int
    value: str
    type: str
    detector: str
    confidence: float = 1.0
    subnet: str | None = None


@dataclass
class Mapping:
    forward: dict[str, str] = field(default_factory=dict)   # lookup key -> placeholder
    reverse: dict[str, str] = field(default_factory=dict)   # placeholder -> real value
    counters: dict[str, int] = field(default_factory=dict)  # prefix -> last number used

    def to_dict(self) -> dict:
        return {"forward": self.forward, "reverse": self.reverse, "counters": self.counters}

    @classmethod
    def from_dict(cls, d: dict) -> "Mapping":
        return cls(dict(d.get("forward", {})), dict(d.get("reverse", {})), dict(d.get("counters", {})))


@dataclass
class Session:
    id: str
    name: str
    mapping: Mapping
    conversations: dict[str, str]
    created: datetime
    last_used: datetime

    def to_dict(self) -> dict:
        return {
            "id": self.id,
            "name": self.name,
            "mapping": self.mapping.to_dict(),
            "conversations": self.conversations,
            "created": self.created.isoformat(),
            "last_used": self.last_used.isoformat(),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Session":
        return cls(
            id=d["id"],
            name=d["name"],
            mapping=Mapping.from_dict(d.get("mapping", {})),
            conversations=dict(d.get("conversations", {})),
            created=datetime.fromisoformat(d["created"]),
            last_used=datetime.fromisoformat(d["last_used"]),
        )


@dataclass
class RunResult:
    redacted_text: str
    findings: list[Finding]
    retries: int


def now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Redaction catalog (SPEC: Redaction Catalog)
# ---------------------------------------------------------------------------
# Priority groups, highest first. Used by merger.py when findings overlap.
GROUPS = ["secrets", "identity", "network", "infrastructure", "programming", "other"]

ALWAYS = "always"
ON = "on"
OFF = "off"


@dataclass(frozen=True)
class TypeInfo:
    group: str
    default: str            # ALWAYS | ON | OFF
    prefix: str             # placeholder prefix, e.g. IP for IP_PRIVATE
    case_insensitive: bool  # same placeholder regardless of case (names, hosts)
    list_file: str | None = None  # list-backed types (lists_detector + learner)


def _t(group, default, prefix=None, ci=False, list_file=None):
    return (group, default, prefix, ci, list_file)


_CATALOG_SPEC = {
    # --- always: secrets ---
    "API_KEY": _t("secrets", ALWAYS),
    "TOKEN": _t("secrets", ALWAYS),
    "PASSWORD": _t("secrets", ALWAYS),
    "HASH": _t("secrets", ALWAYS),
    "PRIVATE_KEY": _t("secrets", ALWAYS),
    "CONN_STRING": _t("secrets", ALWAYS),
    "CLOUD_SECRET": _t("secrets", ALWAYS),
    "SIGNED_URL": _t("secrets", ALWAYS),
    "SESSION": _t("secrets", ALWAYS),
    "SECRET": _t("secrets", ALWAYS),
    "VPN_KEY": _t("secrets", ALWAYS),
    "OTP_SEED": _t("secrets", ALWAYS),
    "REGISTRY_AUTH": _t("secrets", ALWAYS),
    "GIT_CRED": _t("secrets", ALWAYS),
    "NET_SECRET": _t("secrets", ALWAYS),
    "HIGH_ENTROPY": _t("secrets", ALWAYS),
    # --- always: identity ---
    "USER": _t("identity", ALWAYS, ci=True, list_file="usernames.txt"),
    "EMAIL": _t("identity", ALWAYS, ci=True),
    "PERSON": _t("identity", ALWAYS, ci=True, list_file="people.txt"),
    "SID": _t("identity", ALWAYS),
    "PHONE": _t("identity", ALWAYS),
    "ADDRESS": _t("identity", ALWAYS, ci=True),
    "GOV_ID": _t("identity", ALWAYS),
    "CARD": _t("identity", ALWAYS),
    "BANK": _t("identity", ALWAYS),
    # --- always: network ---
    "IP": _t("network", ALWAYS),                       # public IPs
    "MAC": _t("network", ALWAYS, ci=True),
    "HOST": _t("network", ALWAYS, ci=True, list_file="hosts.txt"),
    "DOMAIN": _t("network", ALWAYS, ci=True, list_file="domains.txt"),
    "CLOUD_ID": _t("infrastructure", ALWAYS, ci=True),
    # --- configurable, on by default ---
    "IP_PRIVATE": _t("network", ON, prefix="IP"),
    "SUBNET": _t("network", ON),
    "URL": _t("network", ON),
    "SSID": _t("network", ON),
    "VPN_ID": _t("network", ON, ci=True),
    "CERT": _t("network", ON),
    "CLUSTER": _t("infrastructure", ON, ci=True),
    "IMAGE": _t("infrastructure", ON),
    "SERIAL": _t("infrastructure", ON),
    "LICENSE": _t("infrastructure", ON),
    "MACHINE_ID": _t("infrastructure", ON, ci=True),
    "DB": _t("programming", ON, ci=True, list_file="databases.txt"),
    "TABLE": _t("programming", ON, ci=True, list_file="tables.txt"),
    "COLUMN": _t("programming", ON, ci=True, list_file="columns.txt"),
    "PROC": _t("programming", ON, ci=True, list_file="procedures.txt"),
    "SQL_VALUE": _t("programming", ON),
    "ENV_VALUE": _t("programming", ON),
    "REPO": _t("programming", ON, ci=True),
    "ORG": _t("programming", ON, ci=True),
    "PACKAGE": _t("programming", ON, ci=True, list_file="packages.txt"),
    "ORG_NAME": _t("programming", ON, ci=True, list_file="orgs.txt"),
    "CUSTOMER_ID": _t("programming", ON),
    "PATH": _t("programming", ON),
    "PROJECT": _t("programming", ON, ci=True, list_file="projects.txt"),
    # --- configurable, off by default ---
    "BUCKET": _t("infrastructure", OFF),
    "IP_LOCAL": _t("network", OFF, prefix="IP"),
    "PORT": _t("network", OFF),
    "VLAN": _t("network", OFF),
    "UUID": _t("other", OFF, ci=True),
    "UID": _t("other", OFF),
    "BRANCH": _t("programming", OFF),
    "TIME": _t("other", OFF),
    "PROCESS": _t("other", OFF),
    "GEO": _t("other", OFF),
    "VERSION": _t("other", OFF),
    # --- hex/base64 blobs whose decoded content contains sensitive values ---
    "ENCODED": _t("secrets", ALWAYS),
    # --- internal: text in the input that already looks like a placeholder ---
    "LITERAL": _t("other", ALWAYS),
}

CATALOG: dict[str, TypeInfo] = {
    name: TypeInfo(group=g, default=d, prefix=p or name, case_insensitive=ci, list_file=lf)
    for name, (g, d, p, ci, lf) in _CATALOG_SPEC.items()
}

# Explicit order inside each group for overlap resolution (earlier wins).
TYPE_PRIORITY: list[str] = [
    # secrets
    "PRIVATE_KEY", "CONN_STRING", "SIGNED_URL", "GIT_CRED", "CLOUD_SECRET", "REGISTRY_AUTH",
    "VPN_KEY", "NET_SECRET", "OTP_SEED", "PASSWORD", "HASH", "TOKEN", "API_KEY", "SESSION",
    "SECRET", "ENCODED", "HIGH_ENTROPY",
    # identity
    "GOV_ID", "CARD", "BANK", "EMAIL", "SID", "USER", "PERSON", "PHONE", "ADDRESS",
    # network
    "URL", "SUBNET", "IP", "IP_PRIVATE", "IP_LOCAL", "MAC", "DOMAIN", "HOST", "VPN_ID",
    "CERT", "SSID", "PORT", "VLAN",
    # infrastructure
    "CLOUD_ID", "IMAGE", "CLUSTER", "MACHINE_ID", "SERIAL", "LICENSE", "BUCKET",
    # programming
    "REPO", "ORG", "PACKAGE", "ORG_NAME", "PROJECT", "DB", "PROC",
    "TABLE", "COLUMN", "SQL_VALUE", "ENV_VALUE", "CUSTOMER_ID", "PATH", "BRANCH",
    # other
    "LITERAL", "UUID", "UID", "TIME", "PROCESS", "GEO", "VERSION",
]


def priority(type_name: str) -> tuple[int, int]:
    """Lower tuple = higher priority: (group rank, rank inside the ordering)."""
    info = CATALOG.get(type_name)
    group_rank = GROUPS.index(info.group) if info else len(GROUPS)
    try:
        type_rank = TYPE_PRIORITY.index(type_name)
    except ValueError:
        type_rank = len(TYPE_PRIORITY)
    return (group_rank, type_rank)


# ---------------------------------------------------------------------------
# Placeholders
# ---------------------------------------------------------------------------
# <TYPE_N> or <IP_N in SUBNET_M>
PLACEHOLDER_RE = re.compile(r"<([A-Z][A-Z_]*?)_(\d+)(?: in SUBNET_(\d+))?>")
# Anything in the original input that already looks like one of our placeholders.
PLACEHOLDER_LIKE_RE = re.compile(r"<[A-Za-z][A-Za-z_]*_\d+(?: in SUBNET_\d+)?>")


def placeholder_spans(text: str) -> list[tuple[int, int]]:
    return [(m.start(), m.end()) for m in PLACEHOLDER_RE.finditer(text)]


def inside_any(start: int, end: int, spans: list[tuple[int, int]]) -> bool:
    """True if [start, end) overlaps any of the spans."""
    for s, e in spans:
        if start < e and end > s:
            return True
    return False


def list_backed_types() -> dict[str, str]:
    """Type name -> list file name for every list-backed type."""
    return {t: i.list_file for t, i in CATALOG.items() if i.list_file}
