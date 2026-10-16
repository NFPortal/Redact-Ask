"""[4] Fixed-format patterns: IPs, MACs, emails, paths, users, cloud IDs, SQL names, ... (SPEC: rules_detector.py).

Does not detect secrets (that is secrets_detector) and does not use the word lists
(that is lists_detector). The only list it reads is subnets.txt, passed in as `subnets`.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Iterable

from .models import Finding, PLACEHOLDER_RE

DETECTOR = "rules"

_GUID = r"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}"
_SEP = r"[\"']?[ \t]*[:=][ \t]*[\"']?"   # key: / key = value, optional quotes; never crosses a line break


class _Collector:
    def __init__(self, text: str):
        self.text = text
        self.findings: list[Finding] = []

    def add(self, start: int, end: int, type_: str, subnet: str | None = None) -> None:
        # Trim whitespace and surrounding quotes/brackets so only the value is redacted.
        while start < end and self.text[start] in " \t\"'`([{<":
            start += 1
        while end > start and self.text[end - 1] in " \t\"'`)]}>,;.":
            end -= 1
        if end - start < 2:
            return
        self.findings.append(Finding(start, end, self.text[start:end], type_, DETECTOR, 1.0, subnet))

    def regex(self, pattern: re.Pattern, type_: str, group: int | str = 0,
              keep=None) -> None:
        for m in pattern.finditer(self.text):
            if m.group(group) is None:
                continue
            value = m.group(group)
            if keep is not None and not keep(value):
                continue
            self.add(m.start(group), m.end(group), type_)


# ---------------------------------------------------------------------------
# IP addresses and subnets
# ---------------------------------------------------------------------------
_IPV4 = r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4_RE = re.compile(rf"(?<![\d.]){_IPV4}(?!\d|\.\d)")
CIDR4_RE = re.compile(rf"(?<![\d.])({_IPV4})/(3[0-2]|[12]?\d)(?!\d)")
NETMASK_PAIR_RE = re.compile(
    rf"IPv4 Address[ .]*:\s*(?P<ip>{_IPV4})(?:\(Preferred\))?[ \t]*\r?\n[ \t]*Subnet Mask[ .]*:\s*(?P<mask>{_IPV4})"
    rf"|\binet (?:addr:)?(?P<ip2>{_IPV4})\s+(?:netmask|Mask:)\s*(?P<mask2>{_IPV4})"
    rf"|\bip address (?P<ip3>{_IPV4}) (?P<mask3>{_IPV4})", re.IGNORECASE)
IPV6_CAND_RE =re.compile(r"(?<![\w:.])(?:[0-9A-Fa-f]{0,4}:){2,7}[0-9A-Fa-f]{0,4}(?:%[\w.]+)?(?:/(?:12[0-8]|1[01]\d|[1-9]?\d))?(?![\w:])")


def _is_netmask(ip: ipaddress.IPv4Address) -> bool:
    n = int(ip)
    inv = ~n & 0xFFFFFFFF
    return str(ip).startswith("255.") and (inv & (inv + 1)) == 0


def classify_ip(ip: ipaddress._BaseAddress) -> str | None:
    """IP (public) | IP_PRIVATE | IP_LOCAL, or None for netmasks."""
    if isinstance(ip, ipaddress.IPv4Address) and _is_netmask(ip):
        return None
    if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified:
        return "IP_LOCAL"
    if isinstance(ip, ipaddress.IPv4Address) and str(ip) == "255.255.255.255":
        return "IP_LOCAL"
    if ip.is_global:
        return "IP"
    return "IP_PRIVATE"   # RFC1918, CGNAT (Tailscale 100.64/10), ULA, documentation ranges


def _subnet_for(ip, known: list, prefix_v4: int) -> str:
    best = None
    for net in known:
        if ip.version == net.version and ip in net and (best is None or net.prefixlen > best.prefixlen):
            best = net
    if best is None:
        best = ipaddress.ip_network(f"{ip}/{prefix_v4 if ip.version == 4 else 64}", strict=False)
    return str(best)


def _ips(c: _Collector, prefix_v4: int, subnets: list) -> None:
    text = c.text
    known = list(subnets)
    cidr_spans = []
    for m in CIDR4_RE.finditer(text):
        try:
            net = ipaddress.ip_network(f"{m.group(1)}/{m.group(2)}", strict=False)
        except ValueError:
            continue
        cidr_spans.append((m.start(), m.end()))
        if net.prefixlen == 0:
            continue
        known.append(net)
        c.add(m.start(), m.end(), "SUBNET")

    # Address + netmask pairs (ipconfig, ifconfig/ip, Cisco) give the real network size, so the
    # address and its gateway land in the same <SUBNET_n> instead of a guessed /24.
    for m in NETMASK_PAIR_RE.finditer(text):
        ip = m.group("ip") or m.group("ip2") or m.group("ip3")
        mask = m.group("mask") or m.group("mask2") or m.group("mask3")
        try:
            known.append(ipaddress.ip_network(f"{ip}/{mask}", strict=False))
        except ValueError:
            continue

    for m in IPV4_RE.finditer(text):
        ip = ipaddress.ip_address(m.group(0))
        kind = classify_ip(ip)
        if kind is None:
            continue
        subnet = _subnet_for(ip, known, prefix_v4) if kind == "IP_PRIVATE" else None
        c.add(m.start(), m.end(), kind, subnet)

    for m in IPV6_CAND_RE.finditer(text):
        raw = m.group(0)
        addr, _, plen = raw.partition("/")
        try:
            ip = ipaddress.ip_address(addr.split("%")[0])
        except ValueError:
            continue
        if plen:
            try:
                net = ipaddress.ip_network(f"{ip}/{plen}", strict=False)
            except ValueError:
                continue
            if net.prefixlen:
                known.append(net)
                c.add(m.start(), m.end(), "SUBNET")
            continue
        kind = classify_ip(ip)
        if kind is None:
            continue
        subnet = _subnet_for(ip, known, prefix_v4) if kind == "IP_PRIVATE" else None
        c.add(m.start(), m.start() + len(addr), kind, subnet)


# ---------------------------------------------------------------------------
# Static patterns
# ---------------------------------------------------------------------------
I = re.IGNORECASE
M = re.MULTILINE

MAC_RE = re.compile(r"(?<![\w:-])[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}(?![\w:-])")
MAC_HEADER_RE = re.compile(r"\bMAC=([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5,15})")   # iptables/UFW logs
MAC_CISCO_RE = re.compile(r"(?<![\w.])[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4}(?![\w.])")
EMAIL_RE = re.compile(r"(?<![\w.%+-])[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}(?![\w-]|:[^\s\"'/]*/)")  # not git@host:org/repo
PHONE_RE = re.compile(r"(?<![\w+/.:-])(?:\+\d{1,3}[ .-]?)?(?:\(\d{3}\)\s?|\d{3}[ .-])\d{3}[ .-]\d{4}(?![\w.:-])")
PHONE_INTL_RE = re.compile(r"(?<![\w+])\+\d{1,3}(?:[ .-]\d{2,4}){2,4}(?![\w.-])")
SID_RE = re.compile(r"\bS-1-(?:5-21|12-1)(?:-\d{1,10}){3,4}\b")
SSN_RE = re.compile(r"(?<![\w-])(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}(?![\w-])")
CARD_RE = re.compile(r"(?<![\w-])(?:\d[ -]?){12,18}\d(?![\w-])")
IBAN_RE = re.compile(r"\b[A-Z]{2}\d{2}(?: ?[A-Z0-9]{4}){2,7}(?: ?[A-Z0-9]{1,4})?\b")
BANK_RE = re.compile(r"\b(?:bank[_ -]?)?(?:account|acct)[_ -]?(?:no|num(?:ber)?|#)\s*[:=#]?\s*(\d{6,17})\b", I)
ROUTING_RE = re.compile(r"\brouting[_ -]?(?:no|num(?:ber)?)?\s*[:=#]?\s*(\d{9})\b", I)
STREET_RE = re.compile(r"\b\d{1,6}\s+(?:[A-Z][a-z]+\s){1,4}(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr|Drive|Ct|Court|Way|Pl|Place|Pkwy|Parkway|Hwy|Highway)\b\.?")

# Users
WIN_HOME_RE = re.compile(r"\b[A-Za-z]:[\\/]+(?:Users|Documents and Settings)[\\/]+([^\\/\s:*?\"<>|]+)", I)
NIX_HOME_RE = re.compile(r"(?<![\w.-])/(?:home|Users)/([^/\s:*?\"<>|]+)")
_NOT_USERS = {"public", "default", "all users", "default user", "defaultuser0", "shared", "%username%",
              "$user", "${user}", "<user>", "username", "user"}
USER_KV_RE = re.compile(
    r"\b(?:user(?:[_ -]?name)?|usr|login(?:[_ -]?name)?|logon[_ -]?name|account[_ -]?name|"
    r"sam[_ -]?account[_ -]?name|user[_ -]?id|uid_name|owner|principal|acct|"
    r"subject user name|target user name|username)" + _SEP + r"([^\s\"',;)\]}]+)", I)
SSHD_USER_RE = re.compile(r"\b(?:for(?: invalid)?(?: user)?|invalid user|by user|user)\s+([A-Za-z0-9._$@-]+)(?=\s+(?:from|by|on|\(|port)\b|\(uid)", I)
CISCO_USER_RE = re.compile(r"^\s*username\s+(\S+)", M)
SUDO_RE = re.compile(r"\bsudo(?:\[\d+\])?:\s+([A-Za-z0-9._$-]+)\s*:")
DOMAIN_USER_RE = re.compile(r"(?<![\\\w$-])([A-Z][A-Z0-9-]{1,14})\\([A-Za-z][\w.$-]{0,63})(?![\\\w])")
_NOT_DOMAINS = {"AUTHORITY", "BUILTIN", "SERVICE", "NT", "WORKGROUP", "HKLM", "HKCU", "HKCR", "HKU", "HKCC",
                "SYSTEM", "SOFTWARE", "WINDOWS", "PROGRAM", "PROGRA", "USERS", "MICROSOFT", "SYSTEM32"}
_EMPTY_VALUES = {"-", "--", "n/a", "na", "none", "null", "nil", "unknown", "(null)", "''", '""', "true", "false"}

# Hosts and domains
UNC_RE = re.compile(r"(?<![\\\w])\\\\([A-Za-z0-9][\w.-]*)\\([^\\/\s\"'*?<>|]+)")
SMB_RE = re.compile(r"\b(?:smb|cifs|nfs)://([A-Za-z0-9][\w.-]*)/([^/\s\"']+)", I)
HOST_KV_RE = re.compile(
    r"\b(?:host(?:[_ -]?name)?|server(?:[_ -]?name)?|computer(?:[_ -]?name)?|workstation(?:[_ -]?name)?|"
    r"machine(?:[_ -]?name)?|node[_ -]?name|fqdn|dc|domain[_ -]?controller|source[_ -]?host|dest(?:ination)?[_ -]?host|"
    r"remote[_ -]?host|client[_ -]?name)" + _SEP + r"([A-Za-z0-9][\w.-]*)", I)
# Common machine-name patterns: DESKTOP-4F2K9QZ, laptop-kchen, ws-fin-0142, srv-db01, vm-build-3
HOST_PATTERN_RE = re.compile(r"(?<![\w.-])(?:desktop|laptop|ws|pc|nb|srv|server|vm|host|node|dc|nas|fs|sql|db|web|app|k8s)-[A-Za-z0-9][\w-]*(?![\w-])", I)
CISCO_HOST_RE = re.compile(r"^\s*hostname\s+(\S+)\s*$", I | M)
_NOT_HOSTS = {"localhost", "localhost.localdomain", "-", "none", "null", "unknown", "true", "false"}
SYSLOG_HOST_RE = re.compile(
    r"^(?:<\d+>\d?\s*)?(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T[\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"([A-Za-z0-9][\w.-]*)\s+[\w./()-]+(?:\[\d+\])?:", M)
DOMAIN_KV_RE = re.compile(r"\b(?:domain|account domain|ad[_ -]?domain|realm|workgroup)" + _SEP + r"([A-Za-z0-9][\w.-]*)", I)

# Cloud identifiers
ARN_RE = re.compile(r"\barn:aws[a-z-]*:[a-z0-9-]+:[a-z0-9-]*:\d{12}:[^\s\"',)]+")
AWS_ACCOUNT_RE = re.compile(r"\b(?:aws[_ -]?)?(?:account(?:[_ -]?id)?|owner(?:[_ -]?id)?)" + _SEP + r"(\d{12})\b", I)
AZ_SUB_RE = re.compile(rf"/subscriptions/({_GUID})", I)
AZ_RG_RE = re.compile(r"/resourceGroups/([^/\s\"']+)", I)
AZ_ID_RE = re.compile(rf"\b(?:tenant|subscription|client|app(?:lication)?|object|directory)[_ -]?id" + _SEP + rf"({_GUID})", I)
AZ_LOGIN_RE = re.compile(rf"login\.microsoftonline\.com/({_GUID})", I)
GCP_PROJECT_RE = re.compile(r"\bprojects/([a-z][a-z0-9-]{4,28}[a-z0-9])\b")
GCP_PROJECT_KV_RE = re.compile(r"\b(?:gcp[_ -]?)?project[_ -]?id" + _SEP + r"([a-z][a-z0-9-]{4,28}[a-z0-9])\b", I)

# URLs, certificates, networks
URL_RE = re.compile(r"\b(?:https?|ftps?|wss?|ldaps?|smb|rdp|vnc|ssh)://[^\s\"'<>()\[\]{}`]+", I)
CERT_PEM_RE = re.compile(r"-----BEGIN (?:TRUSTED )?CERTIFICATE(?: REQUEST)?-----[\s\S]*?-----END (?:TRUSTED )?CERTIFICATE(?: REQUEST)?-----")
CERT_PRINT_RE = re.compile(r"\b(?:thumbprint|fingerprint)[^\n:=]{0,20}[:=]\s*([0-9A-Fa-f]{2}(?::?[0-9A-Fa-f]{2}){15,63})", I)
SSH_FP_RE = re.compile(r"\b(?:SHA256|SHA1|MD5):([A-Za-z0-9+/:=]{20,})")
CN_RE = re.compile(r"\b(?:CN|OU|O)=([^,\n/\"]+)")
SAN_RE = re.compile(r"\bDNS:([\w*.-]+)")
SSID_RE = re.compile(r"\b(?:ssid|network[_ ]name|wifi(?:[_ ]name)?)\s*[=:]\s*\"?([^\"\n,;]+?)\"?(?=\s*$|[,;\n])", I | M)
TAILNET_RE = re.compile(r"\b[\w-]+(?:\.[\w-]+)*\.ts\.net\b", I)
ZEROTIER_RE = re.compile(r"\b(?:zerotier|zt|network[_ -]?id|nwid)\D{0,20}?\b([0-9a-f]{16})\b", I)
CF_TUNNEL_RE = re.compile(rf"\btunnel(?:[_ -]?id)?[\"']?\s*[:=]?\s*[\"']?({_GUID})|({_GUID})\.cfargotunnel\.com", I)
WG_ENDPOINT_RE = re.compile(r"^\s*Endpoint\s*=\s*(\S+)", I | M)

# Infrastructure
CLUSTER_RE = re.compile(r"\b(?:namespace|cluster(?:[_ -]?name)?|kube[_ -]?context|context|pve[_ -]?node|proxmox[_ -]?node|swarm(?:[_ -]?name)?)" + _SEP + r"([\w.-]+)", I)
NS_FLAG_RE = re.compile(r"(?:\s-n\s+|--namespace[= ])([\w-]+)")
_NOT_CLUSTERS = {"default", "kube-system", "kube-public", "kube-node-lease", "true", "false", "null"}
IMAGE_RE = re.compile(r"\b((?:registry\.[\w.-]+|[\w.-]+\.(?:lan|local|internal|corp|home\.arpa)|[\w-]+\.azurecr\.io|\d{12}\.dkr\.ecr\.[\w-]+\.amazonaws\.com|[\w.-]+\.pkg\.dev|ghcr\.io/[\w.-]+)(?::\d+)?/[\w./-]+(?::[\w.-]+)?(?:@sha256:[0-9a-f]{64})?)", I)
SERIAL_RE = re.compile(r"\b(?:serial(?:[_ -]?(?:number|no))?|s/n|asset[_ -]?tag|service[_ -]?tag|serialnumber)\s*[:=#]\s*[\"']?([A-Za-z0-9][A-Za-z0-9-]{3,})", I)
HW_UUID_RE = re.compile(rf"\b(?:system|product|bios|hardware|smbios)[_ -]?uuid\s*[:=]\s*[\"']?({_GUID})", I)
LICENSE_RE = re.compile(r"\b[A-Z0-9]{5}(?:-[A-Z0-9]{5}){4}\b")
LICENSE_KV_RE = re.compile(r"\b(?:licen[cs]e|product)[_ -]?key" + _SEP + r"([\w-]{8,})", I)
MACHINE_ID_RE = re.compile(r"\bmachine[_-]?id[\"']?\s*[:=]?\s*[\"']?([0-9a-f]{32})\b", I)
MACHINE_GUID_RE = re.compile(rf"\bMachineGuid\b\s*(?:REG_SZ)?\s*[:=]?\s*[\"']?\{{?({_GUID})", I)
DEVICE_ID_RE = re.compile(r"\bdevice[_ -]?id" + _SEP + r"([\w{}-]{8,})", I)

# Programming
REPO_RE = re.compile(r"(?:github\.com|gitlab\.com|bitbucket\.org)[:/]([\w.-]+)/([\w.-]+?)(?:\.git)?(?=[/\s\"'#?]|$)", I)
GIT_SSH_RE = re.compile(r"\bgit@[\w.-]+:([\w.-]+)/([\w.-]+?)(?:\.git)?(?=[\s\"']|$)")
AZDO_RE = re.compile(r"dev\.azure\.com/([\w.-]+)/([\w.%-]+)/_git/([\w.%-]+)", I)
CUSTOMER_RE = re.compile(r"\b(?:customer|cust|client|order|invoice|ticket|case|subscriber|member)[_ -]?(?:id|no|num(?:ber)?|#)\s*[:=#]?\s*[\"']?([A-Z0-9][\w-]{3,})", I)
ENV_RE = re.compile(r"^[ \t]*(?:-[ \t]+)?(?:export[ \t]+)?([A-Z][A-Z0-9_]+)=(\S.*?)[ \t]*$", M)  # .env style KEY=value

# SQL
SQL_STMT_RE = re.compile(
    r"\b(?:SELECT\b[\s\S]{1,2000}?\bFROM\b|INSERT\s+INTO\b|UPDATE\s+\S+\s+SET\b|DELETE\s+FROM\b|MERGE\s+INTO\b|"
    r"(?:CREATE|ALTER|DROP)\s+(?:OR\s+(?:REPLACE|ALTER)\s+)?(?:TABLE|VIEW|PROCEDURE|PROC|INDEX|DATABASE|SCHEMA|TRIGGER|FUNCTION)\b|"
    r"TRUNCATE\s+TABLE\b|EXEC(?:UTE)?\s+[\w\[\]$.]+|CALL\s+[\w$.]+\s*\(|USE\s+[\w\[\]$]+\s*;)"
    r"[\s\S]*?(?:;|\n[ \t]*\n|\Z)", I)
_IDENT = r"(?:[\[`\"]?[\w$]+[\]`\"]?\.){0,2}[\[`\"]?[\w$]+[\]`\"]?"
SQL_TABLE_RE = re.compile(rf"\b(?:FROM|JOIN|INTO|UPDATE|TRUNCATE\s+TABLE|MERGE\s+INTO|USING|(?:CREATE|ALTER|DROP)\s+TABLE(?:\s+IF\s+(?:NOT\s+)?EXISTS)?)\s+({_IDENT})", I)
SQL_PROC_RE = re.compile(rf"\b(?:EXEC(?:UTE)?|CALL|(?:CREATE|ALTER|DROP)\s+(?:OR\s+(?:REPLACE|ALTER)\s+)?(?:PROCEDURE|PROC|VIEW|TRIGGER|FUNCTION)(?:\s+IF\s+(?:NOT\s+)?EXISTS)?)\s+({_IDENT})", I)
SQL_DB_RE = re.compile(r"\b(?:USE|(?:CREATE|DROP|ALTER)\s+(?:DATABASE|SCHEMA)(?:\s+IF\s+(?:NOT\s+)?EXISTS)?)\s+([\[`\"]?[\w$]+[\]`\"]?)", I)
DB_KV_RE = re.compile(r"\b(?:database|initial catalog|dbname|db[_ -]?name)\s*=\s*([^;\s\"']+)", I)
SQL_SELECT_LIST_RE = re.compile(r"\bSELECT\s+(?:DISTINCT\s+|TOP\s+\d+\s+)?([\s\S]+?)\s+FROM\b", I)
SQL_COND_COL_RE = re.compile(r"(?:\b(?:WHERE|AND|OR|ON|SET|BY|HAVING)\s+|,\s*)((?:[\w$]+\.)?[\w$]+)\s*(?:=|<>|!=|<=|>=|<|>|\bLIKE\b|\bIN\b|\bIS\b|\bBETWEEN\b|,|\s+(?:ASC|DESC)\b|$)", I)
SQL_INSERT_COLS_RE = re.compile(rf"\bINSERT\s+INTO\s+{_IDENT}\s*\(([^)]*)\)", I)
SQL_STRING_RE = re.compile(r"N?'((?:[^']|'')+)'")
SQL_KEYWORDS = {
    "select", "from", "where", "and", "or", "not", "null", "is", "in", "on", "as", "join", "inner", "left", "right",
    "outer", "full", "cross", "group", "order", "by", "having", "limit", "offset", "top", "distinct", "insert", "into",
    "values", "update", "set", "delete", "create", "alter", "drop", "table", "view", "index", "procedure", "function",
    "trigger", "database", "schema", "exec", "execute", "call", "use", "asc", "desc", "like", "between", "exists",
    "case", "when", "then", "else", "end", "union", "all", "with", "count", "sum", "avg", "min", "max", "coalesce",
    "cast", "convert", "true", "false", "default", "primary", "key", "foreign", "references", "unique", "if",
    "begin", "commit", "rollback", "transaction", "merge", "using", "matched", "nolock", "dbo", "now", "getdate",
    "current_timestamp", "lower", "upper", "isnull", "nullif", "returning", "only", "temporary", "temp",
}

# Off-by-default patterns
PORT_RE = re.compile(rf"(?:{_IPV4}|\]|\b[A-Za-z][\w-]*(?:\.[\w-]+)*):(\d{{2,5}})(?![\d:])")
PORT_KV_RE = re.compile(r"\bport\s*[=: ]\s*(\d{2,5})\b", I)
VLAN_RE = re.compile(r"\bvlan\s*[-_ ]?(?:id)?\s*[:=]?\s*(\d{1,4})\b", I)
UUID_RE = re.compile(rf"\b{_GUID}\b")
UID_RE = re.compile(r"\b(?:uid|gid|euid|egid|auid|ouid|ogid)=(\d+)")
BRANCH_RE = re.compile(r"(?:refs/heads/|\borigin/)([\w./-]+)|\bbranch\s*[:=]?\s*['\"]?([\w./-]+)", I)
TIME_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?|\b(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}")
PID_RE = re.compile(r"\bpid\s*[=: ]\s*(\d+)|\b[\w.-]+\[(\d+)\]:", I)
GEO_RE = re.compile(r"\b(?:lat(?:itude)?|lon(?:g(?:itude)?)?|lng)\s*[:=]\s*(-?\d{1,3}\.\d{3,})|\b(?:timezone|tz|time[_ ]zone)\s*[:=]\s*([\w/+-]+)", I)
VERSION_RE = re.compile(r"(?<![\w.])v?\d+\.\d+\.\d+(?:[-+][\w.]+)?(?![\w.])")


def _luhn(digits: str) -> bool:
    total, alt = 0, False
    for ch in reversed(digits):
        d = int(ch)
        if alt:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
        alt = not alt
    return total % 10 == 0


def _iban_ok(raw: str) -> bool:
    s = raw.replace(" ", "")
    if not 15 <= len(s) <= 34:
        return False
    s = s[4:] + s[:4]
    num = "".join(str(int(ch, 36)) for ch in s)
    return int(num) % 97 == 1


def _host_is_internal(host: str, suffixes: list[str]) -> bool:
    host = host.lower().rstrip(".")
    try:
        ip = ipaddress.ip_address(host.strip("[]"))
        return not ip.is_global
    except ValueError:
        pass
    if host in ("localhost",):
        return False
    if "." not in host:
        return True   # single-label names (http://grafana:3000) are internal
    return any(host.endswith(s) for s in suffixes) or host.endswith(".ts.net")


def _sql(c: _Collector) -> None:
    text = c.text
    for stmt in SQL_STMT_RE.finditer(text):
        base = stmt.start()
        s = stmt.group(0)

        def add_ident(m: re.Match, group: int, type_: str) -> None:
            ident = m.group(group)
            if ident.strip("[]`\"").lower() in SQL_KEYWORDS or ident.strip("[]`\"").isdigit():
                return
            c.add(base + m.start(group), base + m.end(group), type_)

        for m in SQL_TABLE_RE.finditer(s):
            add_ident(m, 1, "TABLE")
        for m in SQL_PROC_RE.finditer(s):
            add_ident(m, 1, "PROC")
        for m in SQL_DB_RE.finditer(s):
            add_ident(m, 1, "DB")
        for m in SQL_STRING_RE.finditer(s):
            c.add(base + m.start(1), base + m.end(1), "SQL_VALUE")
        for m in SQL_INSERT_COLS_RE.finditer(s):
            off = base + m.start(1)
            for cm in re.finditer(r"[\w$]+", m.group(1)):
                if cm.group(0).lower() not in SQL_KEYWORDS:
                    c.add(off + cm.start(), off + cm.end(), "COLUMN")
        for m in SQL_SELECT_LIST_RE.finditer(s):
            off = base + m.start(1)
            items = m.group(1)
            for part in re.finditer(r"[^,]+", items):
                item = part.group(0)
                # bare identifier or table.column, optionally followed by an alias
                im = re.match(r"\s*(?:([\w$]+)\.)?([\w$]+)\s*(?:(?:AS\s+)?([\w$]+))?\s*$", item, I)
                if not im:
                    continue
                for g in (1, 2, 3):
                    if im.group(g) and im.group(g).lower() not in SQL_KEYWORDS and not im.group(g).isdigit():
                        c.add(off + part.start() + im.start(g), off + part.start() + im.end(g),
                              "TABLE" if g == 1 else "COLUMN")
        for m in SQL_COND_COL_RE.finditer(s):
            ident = m.group(1)
            if ident.split(".")[-1].lower() in SQL_KEYWORDS or ident.isdigit():
                continue
            c.add(base + m.start(1), base + m.end(1), "COLUMN")
    c.regex(DB_KV_RE, "DB", 1)


def detect(text: str, config, subnets: Iterable = ()) -> list[Finding]:
    """Return rule-based Findings for `text`. `subnets` are ipaddress networks from lists/subnets.txt."""
    c = _Collector(text)
    suffixes = list(getattr(config, "internal_suffixes", [".local", ".lan", ".internal", ".corp", ".home.arpa"]))
    prefix_v4 = getattr(config, "private_subnet_prefix", 24)

    _ips(c, prefix_v4, list(subnets))

    # MAC addresses
    c.regex(MAC_HEADER_RE, "MAC", 1)
    for pat in (MAC_RE, MAC_CISCO_RE):
        c.regex(pat, "MAC", 0, keep=lambda v: v.replace(":", "").replace("-", "").replace(".", "").lower()
                not in ("000000000000", "ffffffffffff"))

    # Identity
    c.regex(EMAIL_RE, "EMAIL")
    c.regex(PHONE_RE, "PHONE")
    c.regex(PHONE_INTL_RE, "PHONE")
    c.regex(SID_RE, "SID")
    c.regex(SSN_RE, "GOV_ID")
    for m in CARD_RE.finditer(text):
        digits = re.sub(r"\D", "", m.group(0))
        if 13 <= len(digits) <= 19 and digits[0] in "23456" and _luhn(digits):
            c.add(m.start(), m.end(), "CARD")
    c.regex(IBAN_RE, "BANK", 0, keep=_iban_ok)
    c.regex(BANK_RE, "BANK", 1)
    c.regex(ROUTING_RE, "BANK", 1)
    c.regex(STREET_RE, "ADDRESS")

    # Users (home folders count as USER per SPEC)
    not_user = lambda v: v.lower() not in _NOT_USERS and v.lower() not in _EMPTY_VALUES and not PLACEHOLDER_RE.fullmatch(v)
    c.regex(WIN_HOME_RE, "USER", 1, keep=not_user)
    c.regex(NIX_HOME_RE, "USER", 1, keep=not_user)
    c.regex(USER_KV_RE, "USER", 1, keep=not_user)
    c.regex(SSHD_USER_RE, "USER", 1, keep=lambda v: not_user(v) and not IPV4_RE.fullmatch(v))
    c.regex(SUDO_RE, "USER", 1, keep=not_user)
    c.regex(CISCO_USER_RE, "USER", 1, keep=not_user)
    for m in DOMAIN_USER_RE.finditer(text):
        if m.group(1).upper() in _NOT_DOMAINS:
            continue
        c.add(m.start(1), m.end(1), "DOMAIN")
        if m.group(2).lower() not in _NOT_USERS:
            c.add(m.start(2), m.end(2), "USER")

    # Hosts, shares, domains
    for pat in (UNC_RE, SMB_RE):
        for m in pat.finditer(text):
            c.add(m.start(1), m.end(1), "HOST")
            share = m.group(2)
            if not re.fullmatch(r"[A-Za-z]\$|ADMIN\$|IPC\$|print\$", share, I):
                c.add(m.start(2), m.end(2), "PATH")
    host_ok = lambda v: v.lower() not in _NOT_HOSTS and not PLACEHOLDER_RE.fullmatch(v)
    c.regex(HOST_KV_RE, "HOST", 1, keep=host_ok)
    c.regex(SYSLOG_HOST_RE, "HOST", 1, keep=host_ok)
    c.regex(CISCO_HOST_RE, "HOST", 1, keep=host_ok)
    c.regex(HOST_PATTERN_RE, "HOST", 0, keep=host_ok)
    if suffixes:
        alt = "|".join(re.escape(s.lstrip(".")) for s in sorted(suffixes, key=len, reverse=True))
        internal_re = re.compile(rf"(?<![\w.-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{{0,61}}[A-Za-z0-9])?\.)+(?:{alt})(?![\w-])", I)
        c.regex(internal_re, "HOST")
    c.regex(DOMAIN_KV_RE, "DOMAIN", 1, keep=host_ok)

    # Cloud identifiers
    c.regex(ARN_RE, "CLOUD_ID")
    c.regex(AWS_ACCOUNT_RE, "CLOUD_ID", 1)
    c.regex(AZ_SUB_RE, "CLOUD_ID", 1)
    c.regex(AZ_RG_RE, "CLOUD_ID", 1)
    c.regex(AZ_ID_RE, "CLOUD_ID", 1)
    c.regex(AZ_LOGIN_RE, "CLOUD_ID", 1)
    c.regex(GCP_PROJECT_RE, "CLOUD_ID", 1)
    c.regex(GCP_PROJECT_KV_RE, "CLOUD_ID", 1)

    # URLs on internal hosts
    for m in URL_RE.finditer(text):
        hm = re.match(r"[a-z]+://(?:[^@/\s]*@)?(\[[^\]]+\]|[^:/\s?#]+)", m.group(0), I)
        if hm and _host_is_internal(hm.group(1), suffixes):
            c.add(m.start(), m.end(), "URL")

    # Certificates, Wi-Fi, VPN
    c.regex(CERT_PEM_RE, "CERT")
    c.regex(CERT_PRINT_RE, "CERT", 1)
    c.regex(SSH_FP_RE, "CERT", 1)
    c.regex(CN_RE, "CERT", 1, keep=lambda v: len(v.strip()) > 1)
    c.regex(SAN_RE, "CERT", 1)
    c.regex(SSID_RE, "SSID", 1)
    c.regex(TAILNET_RE, "VPN_ID")
    c.regex(ZEROTIER_RE, "VPN_ID", 1)
    for m in CF_TUNNEL_RE.finditer(text):
        g = 1 if m.group(1) else 2
        c.add(m.start(g), m.end(g), "VPN_ID")
    c.regex(WG_ENDPOINT_RE, "VPN_ID", 1)

    # Infrastructure
    c.regex(CLUSTER_RE, "CLUSTER", 1, keep=lambda v: v.lower() not in _NOT_CLUSTERS)
    c.regex(NS_FLAG_RE, "CLUSTER", 1, keep=lambda v: v.lower() not in _NOT_CLUSTERS)
    c.regex(IMAGE_RE, "IMAGE", 1)
    c.regex(SERIAL_RE, "SERIAL", 1)
    c.regex(HW_UUID_RE, "SERIAL", 1)
    c.regex(LICENSE_RE, "LICENSE")
    c.regex(LICENSE_KV_RE, "LICENSE", 1)
    c.regex(MACHINE_ID_RE, "MACHINE_ID", 1)
    c.regex(MACHINE_GUID_RE, "MACHINE_ID", 1)
    c.regex(DEVICE_ID_RE, "MACHINE_ID", 1)

    # Programming
    for m in REPO_RE.finditer(text):
        c.add(m.start(1), m.end(1), "ORG")
        c.add(m.start(2), m.end(2), "REPO")
    for m in GIT_SSH_RE.finditer(text):
        c.add(m.start(1), m.end(1), "ORG")
        c.add(m.start(2), m.end(2), "REPO")
    for m in AZDO_RE.finditer(text):
        c.add(m.start(1), m.end(1), "ORG")
        c.add(m.start(2), m.end(2), "PROJECT")
        c.add(m.start(3), m.end(3), "REPO")
    c.regex(CUSTOMER_RE, "CUSTOMER_ID", 1)
    for m in ENV_RE.finditer(text):
        value = m.group(2)
        if value.strip("\"'") and value.lower() not in _EMPTY_VALUES:
            c.add(m.start(2), m.end(2), "ENV_VALUE")
    _sql(c)

    # Off by default (merger drops these unless turned on in config)
    c.regex(PORT_RE, "PORT", 1)
    c.regex(PORT_KV_RE, "PORT", 1)
    c.regex(VLAN_RE, "VLAN", 1)
    c.regex(UUID_RE, "UUID")
    c.regex(UID_RE, "UID", 1)
    for m in BRANCH_RE.finditer(text):
        g = 1 if m.group(1) else 2
        c.add(m.start(g), m.end(g), "BRANCH")
    c.regex(TIME_RE, "TIME")
    for m in PID_RE.finditer(text):
        g = 1 if m.group(1) else 2
        c.add(m.start(g), m.end(g), "PROCESS")
    for m in GEO_RE.finditer(text):
        g = 1 if m.group(1) else 2
        c.add(m.start(g), m.end(g), "GEO")
    c.regex(VERSION_RE, "VERSION")

    return c.findings
