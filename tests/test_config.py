import pytest

from redactask import config
from redactask.models import UsageError


def test_defaults_match_spec(cfg):
    assert cfg.default_target == "claude"
    assert cfg.max_lines == 5000 and cfg.max_bytes == 1_000_000
    assert cfg.session_expiry_days == 14 and cfg.max_scan_retries == 2
    assert cfg.context == "isolated" and cfg.preview is True
    assert cfg.gliner.model == "nvidia/gliner-pii" and cfg.gliner.threshold == 0.3
    assert cfg.private_subnet_prefix == 24


def test_type_defaults(cfg):
    assert cfg.type_enabled("API_KEY")          # always
    assert cfg.type_enabled("IP_PRIVATE")       # on by default
    assert not cfg.type_enabled("BUCKET")       # turned off by user decision
    assert not cfg.type_enabled("PORT")         # off by default


def test_every_type_can_be_turned_off_with_warning_for_always_types():
    c = config.from_dict({"types": {"PASSWORD": False, "PORT": True, "USER": False}})
    assert not c.type_enabled("PASSWORD") and not c.type_enabled("USER")
    assert c.type_enabled("PORT")
    assert sum("turned off" in w for w in c.warnings) == 2
    assert c.type_enabled("LITERAL")                 # internal escaping can't be turned off


def test_allow_everything_and_redact_everything():
    from redactask.models import CATALOG
    names = [n for n in CATALOG if n != "LITERAL"]
    off = config.from_dict({"types": {n: False for n in names}})
    on = config.from_dict({"types": {n: True for n in names}})
    assert not any(off.type_enabled(n) for n in names)
    assert all(on.type_enabled(n) for n in names)


def test_example_config_lists_every_type_with_current_defaults():
    import tomllib
    from redactask.models import CATALOG
    raw = tomllib.loads(config.EXAMPLE_CONFIG.read_text(encoding="utf-8"))["types"]
    assert set(raw) == {n for n in CATALOG if n != "LITERAL"}
    defaults = config.Config()
    for name, value in raw.items():
        assert value == defaults.type_enabled(name), name


def test_invalid_values_rejected():
    with pytest.raises(UsageError):
        config.from_dict({"context": "everything"})
    with pytest.raises(UsageError):
        config.from_dict({"default_target": "chatgpt"})
    with pytest.raises(UsageError):
        config.from_dict({"gliner": {"device": "tpu"}})


def test_parse_target():
    assert config.parse_target("claude") == ("claude", None)
    assert config.parse_target("copilot:gpt-5") == ("copilot", "gpt-5")
    assert config.parse_target("Claude:opus") == ("claude", "opus")


def test_first_run_creates_config_and_lists(isolated_home):
    c = config.load()
    d = config.dirs()
    assert (d.config / "config.toml").exists()
    assert (d.lists / "usernames.txt").exists() and (d.lists / "subnets.txt").exists()
    assert not c.type_enabled("BUCKET")


def test_localhost_check():
    assert config.is_localhost_url("http://localhost:11434")
    assert config.is_localhost_url("http://127.0.0.1:11434")
    assert not config.is_localhost_url("http://ollama.example.com:11434")
