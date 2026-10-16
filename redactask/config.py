"""[2] Load and validate settings from config.toml (SPEC: config.py)."""
from __future__ import annotations

import os
import shutil
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

import platformdirs

from .models import ALWAYS, CATALOG, ON, UsageError

APP = "redact-ask"
PROJECT_DIR = Path(__file__).resolve().parent.parent
EXAMPLE_CONFIG = PROJECT_DIR / "config.example.toml"


@dataclass(frozen=True)
class Dirs:
    config: Path     # config.toml, lists/, fallback key
    lists: Path
    sessions: Path   # encrypted session files
    workdirs: Path   # empty working folders for the cloud CLI, one per session
    audit: Path      # audit.jsonl


def dirs() -> Dirs:
    """User folders. REDACT_ASK_HOME puts everything under one folder (used by tests)."""
    home = os.environ.get("REDACT_ASK_HOME")
    if home:
        base = Path(home)
        config, data, state = base / "config", base / "data", base / "state"
    else:
        config = Path(platformdirs.user_config_dir(APP, appauthor=False, roaming=True))
        data = Path(platformdirs.user_data_dir(APP, appauthor=False))
        state = Path(platformdirs.user_state_dir(APP, appauthor=False))
        if sys.platform == "win32":
            state = data / "audit"
    return Dirs(
        config=config,
        lists=config / "lists",
        sessions=data / "sessions",
        workdirs=data / "workdirs",
        audit=state,
    )


@dataclass
class GlinerConfig:
    model: str = "nvidia/gliner-pii"
    threshold: float = 0.3
    device: str = "auto"
    allow_download: bool = True


@dataclass
class LlmConfig:
    enabled_by_default: bool = False
    url: str = "http://localhost:11434"
    model: str = "qwen3:8b"


@dataclass
class Config:
    default_target: str = "claude"
    max_lines: int = 5000
    max_bytes: int = 1_000_000
    session_expiry_days: int = 14
    max_scan_retries: int = 2
    cloud_timeout_seconds: int = 300
    context: str = "isolated"
    copilot_max_arg_chars: int = 30000
    preview: bool = True
    internal_suffixes: list[str] = field(default_factory=lambda: [
        ".local", ".lan", ".internal", ".corp", ".home.arpa", ".intranet", ".private"])
    type_overrides: dict[str, bool] = field(default_factory=lambda: {"BUCKET": False})
    path_mode: str = "segments"
    private_subnet_prefix: int = 24
    gliner: GlinerConfig = field(default_factory=GlinerConfig)
    llm: LlmConfig = field(default_factory=LlmConfig)
    warnings: list[str] = field(default_factory=list)

    def type_enabled(self, type_name: str) -> bool:
        info = CATALOG.get(type_name)
        if info is None:
            return True  # unknown types are redacted (over-redact)
        if info.default == ALWAYS:
            return True
        if type_name in self.type_overrides:
            return self.type_overrides[type_name]
        return info.default == ON


def parse_target(target: str) -> tuple[str, str | None]:
    """'claude' -> ('claude', None); 'copilot:gpt-5' -> ('copilot', 'gpt-5')."""
    tool, _, model = target.partition(":")
    tool = tool.strip().lower()
    if tool not in ("claude", "copilot"):
        raise UsageError(f"Unknown target '{target}'. Use claude, copilot, claude:<model> or copilot:<model>.")
    return tool, (model.strip() or None)


def _ensure_user_files(d: Dirs) -> Path:
    """Create config.toml (from the example) and empty list files on first run."""
    from .models import list_backed_types  # local import keeps config independent of lists logic

    d.config.mkdir(parents=True, exist_ok=True)
    d.lists.mkdir(parents=True, exist_ok=True)
    cfg_path = d.config / "config.toml"
    if not cfg_path.exists():
        shutil.copyfile(EXAMPLE_CONFIG, cfg_path)
    names = set(list_backed_types().values()) | {"custom.txt", "subnets.txt"}
    for name in names:
        p = d.lists / name
        if not p.exists():
            p.write_text(f"# One value per line. Lines starting with # are ignored.\n", encoding="utf-8")
    custom = d.lists / "custom.txt"
    if custom.read_text(encoding="utf-8").startswith("# One value per line"):
        custom.write_text("# Format: TYPE value   (e.g. CUSTOMER_ID ACME-00042)\n", encoding="utf-8")
    return cfg_path


def load(path: Path | None = None) -> Config:
    d = dirs()
    cfg_path = path or _ensure_user_files(d)
    try:
        raw = tomllib.loads(cfg_path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise UsageError(f"Can't read config {cfg_path}: {e}") from e
    return from_dict(raw)


def from_dict(raw: dict) -> Config:
    c = Config()
    simple = ["default_target", "max_lines", "max_bytes", "session_expiry_days", "max_scan_retries",
              "cloud_timeout_seconds", "context", "copilot_max_arg_chars", "internal_suffixes", "preview"]
    for key in simple:
        if key in raw:
            setattr(c, key, raw[key])

    parse_target(c.default_target)
    if not isinstance(c.preview, bool):
        raise UsageError("config: preview must be true or false.")
    if c.context not in ("isolated", "full"):
        raise UsageError(f"config: context must be 'isolated' or 'full', not '{c.context}'.")
    for key in ("max_lines", "max_bytes", "session_expiry_days", "cloud_timeout_seconds", "copilot_max_arg_chars"):
        if not isinstance(getattr(c, key), int) or getattr(c, key) <= 0:
            raise UsageError(f"config: {key} must be a positive whole number.")
    if not isinstance(c.max_scan_retries, int) or c.max_scan_retries < 0:
        raise UsageError("config: max_scan_retries must be 0 or more.")
    c.internal_suffixes = [s if s.startswith(".") else "." + s for s in c.internal_suffixes]

    overrides = dict(raw.get("types", {}))
    c.type_overrides = {}
    for name, value in overrides.items():
        name = name.upper()
        info = CATALOG.get(name)
        if info is None:
            c.warnings.append(f"config: unknown type '{name}' in [types] ignored.")
        elif info.default == ALWAYS:
            c.warnings.append(f"config: {name} is always redacted; the [types] setting is ignored.")
        elif not isinstance(value, bool):
            raise UsageError(f"config: [types] {name} must be true or false.")
        else:
            c.type_overrides[name] = value

    paths = raw.get("paths", {})
    c.path_mode = paths.get("mode", "segments")
    if c.path_mode != "segments":
        raise UsageError("config: [paths] mode must be 'segments'.")

    ip = raw.get("ip", {})
    c.private_subnet_prefix = int(ip.get("private_subnet_prefix", 24))
    if not 8 <= c.private_subnet_prefix <= 32:
        raise UsageError("config: [ip] private_subnet_prefix must be between 8 and 32.")

    g = raw.get("gliner", {})
    c.gliner = GlinerConfig(
        model=g.get("model", c.gliner.model),
        threshold=float(g.get("threshold", c.gliner.threshold)),
        device=g.get("device", c.gliner.device),
        allow_download=bool(g.get("allow_download", True)),
    )
    if c.gliner.device not in ("auto", "cuda", "cpu"):
        raise UsageError("config: [gliner] device must be auto, cuda or cpu.")

    l = raw.get("llm", {})
    c.llm = LlmConfig(
        enabled_by_default=bool(l.get("enabled_by_default", False)),
        url=l.get("url", c.llm.url),
        model=l.get("model", c.llm.model),
    )
    return c


def is_localhost_url(url: str) -> bool:
    host = (urlparse(url).hostname or "").lower()
    return host in ("localhost", "127.0.0.1", "::1")
