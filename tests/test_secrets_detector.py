import tomllib

from redactask import secrets_detector as sd


def found(text):
    return {(f.type, f.value) for f in sd.detect(text)}


def test_every_gitleaks_rule_loads():
    """SPEC: every gitleaks rule must load, directly or via rules/overrides.toml."""
    data = tomllib.loads(sd.GITLEAKS_FILE.read_text(encoding="utf-8"))
    ids = {r["id"] for r in data["rules"]}
    rules, _, path_only = sd.load_rules()
    loaded = {r.id for r in rules} | set(path_only)
    assert loaded == ids
    assert len(rules) + len(path_only) == len(data["rules"]) >= 200
    assert all(not r.get("regex") for r in data["rules"] if r["id"] in path_only)


def test_value_only_not_key_name():
    text = "STRIPE_SECRET_KEY=sk_live_T467cBsVjdODwyenwQRPMqTn\n"
    vals = {v for _, v in found(text)}
    assert "sk_live_T467cBsVjdODwyenwQRPMqTn" in vals
    assert not any("STRIPE" in v for v in vals)


def test_common_secret_shapes():
    text = "\n".join([
        "AKIAZ4X7Q2M5KD3LT7VB",
        "password: Hunter2!x",
        "Authorization: Bearer sJusu4s6cqAuvSfP5IWLrIrc4u41d7iBF4FPYKvk",
        "postgres://app:Xq7vR2pLm9w@db.lan:5432/billing",
        "PrivateKey = uH+LM5m1oqkReajSrm3qQ3iW7GJfAft730O9VrWc7xE=",
        "snmp-server community Wh1sk3yTango RO",
        "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA\n-----END OPENSSH PRIVATE KEY-----",
        "$2b$12$KIXQJ1u7lH0x2y3z4A5B6.CDEFGHIJKLMNOPQRSTUVWXYZabcdefgh",
    ])
    types = {t for t, _ in found(text)}
    assert {"PASSWORD", "TOKEN", "CONN_STRING", "VPN_KEY", "NET_SECRET", "PRIVATE_KEY", "HASH"} <= types
    assert any(v == "AKIAZ4X7Q2M5KD3LT7VB" for _, v in found(text))


def test_ignores_placeholders_empty_values_and_working_dirs():
    assert not found("password: <PASSWORD_1>\npassword=\npassword: changeme")
    assert not any(t == "PASSWORD" for t, _ in found("sudo: bob : PWD=/home/bob/deploy ; USER=root"))


def test_high_entropy_needs_secret_context():
    tok = "q8Xv2mZ4pL0kT7nR3wY9bC6dF1gH5jK8"
    assert ("HIGH_ENTROPY", tok) in found(f"my key is {tok}")
    assert not found(f"build id {tok}")
