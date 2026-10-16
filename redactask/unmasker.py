"""[16] Restore real values in the cloud answer (SPEC: unmasker.py). Never writes to disk."""
from __future__ import annotations

import re
from dataclasses import dataclass

from .models import Mapping

# <IP_3 in SUBNET_1>, <USER_1>, `USER_1`, USER_1, <user_1> ...
_ANY_RE = re.compile(
    r"(?<![A-Za-z0-9_])(?P<open>`?<?)(?P<prefix>[A-Za-z][A-Za-z_]*?)_(?P<n>\d+)(?![\d])"
    r"(?:\s+in\s+SUBNET_(?P<sub>\d+))?(?P<close>>?`?)",
    re.IGNORECASE)


@dataclass
class Unmasked:
    text: str
    unknown: list[str]


def unmask(answer: str, mapping: Mapping) -> Unmasked:
    lookup = {ph.upper(): real for ph, real in mapping.reverse.items()}
    unknown: list[str] = []

    def repl(m: re.Match) -> str:
        prefix, n = m.group("prefix").upper(), m.group("n")
        bracketed = m.group("open").endswith("<") and m.group("close").startswith(">")
        key = f"<{prefix}_{n}>"
        real = lookup.get(key)
        if real is None:
            # Only complain about things that clearly were meant as placeholders.
            if bracketed:
                unknown.append(m.group(0).strip("`"))
            return m.group(0)
        if not bracketed and not (prefix.isupper() or m.group("prefix").isupper()):
            return m.group(0)
        # Keep backticks the model put around the value, drop the angle brackets.
        lead = "`" if m.group("open").startswith("`") else ""
        trail = "`" if m.group("close").endswith("`") else ""
        return f"{lead}{real}{trail}"

    text = _ANY_RE.sub(repl, answer)
    return Unmasked(text=text, unknown=sorted(set(unknown)))
