from redactask import masker, merger, unmasker
from redactask.models import Finding, Mapping


def F(text, value, type_, det="rules", subnet=None, nth=0):
    start = -1
    for _ in range(nth + 1):
        start = text.index(value, start + 1)
    return Finding(start, start + len(value), value, type_, det, 1.0, subnet)


# ---- merger ----------------------------------------------------------------
def test_overlap_union_and_priority(cfg):
    text = "key=AbCdEf123456 end"
    a = Finding(4, 10, "AbCdEf", "HOST", "gliner")
    b = Finding(6, 16, text[6:16], "API_KEY", "secrets")
    [m] = merger.merge(text, [a, b], cfg)
    assert (m.start, m.end, m.type) == (4, 16, "API_KEY")


def test_container_type_wins_unless_inner_is_secret(cfg):
    text = "image: registry.corp.local:5000/app:1"
    img = F(text, "registry.corp.local:5000/app:1", "IMAGE")
    host = F(text, "registry.corp.local", "HOST")
    [m] = merger.merge(text, [img, host], cfg)
    assert m.type == "IMAGE"
    text = "APP_KEY=sk_live_abcdefghijklmnop"
    env = F(text, "sk_live_abcdefghijklmnop", "ENV_VALUE")
    key = F(text, "sk_live_abcdefghijklmnop", "API_KEY", "secrets")
    [m] = merger.merge(text, [env, key], cfg)
    assert m.type == "API_KEY"


def test_disabled_types_and_placeholders_dropped(cfg):
    text = "port 8080 user <USER_1>"
    fs = [F(text, "8080", "PORT"), F(text, "USER_1", "USER")]
    assert merger.merge(text, fs, cfg) == []


# ---- masker ----------------------------------------------------------------
def test_consistent_placeholders_and_subnets():
    m = Mapping()
    text = "jdoe from 10.1.2.3; JDOE again from 10.1.2.9"
    fs = [F(text, "jdoe", "USER"), F(text, "10.1.2.3", "IP_PRIVATE", subnet="10.1.2.0/24"),
          F(text, "JDOE", "USER"), F(text, "10.1.2.9", "IP_PRIVATE", subnet="10.1.2.0/24")]
    out = masker.mask(text, fs, m)
    assert out == "<USER_1> from <IP_1 in SUBNET_1>; <USER_1> again from <IP_2 in SUBNET_1>"
    # a second run in the same session reuses the numbers
    out2 = masker.mask("jdoe", [Finding(0, 4, "jdoe", "USER", "rules")], m)
    assert out2 == "<USER_1>"


def test_case_sensitive_secrets_get_different_placeholders():
    m = Mapping()
    a = masker.placeholder_for(m, "PASSWORD", "Secret1")
    b = masker.placeholder_for(m, "PASSWORD", "secret1")
    assert a != b


def test_literal_placeholders_in_input_are_escaped_and_restored():
    m = Mapping()
    escaped = masker.escape_literals("the doc says <USER_1> literally", m)
    assert "<USER_1>" not in escaped and "<LITERAL_1>" in escaped
    assert unmasker.unmask(escaped, m).text == "the doc says <USER_1> literally"


# ---- unmasker --------------------------------------------------------------
def test_unmask_variants_and_unknown():
    m = Mapping()
    masker.placeholder_for(m, "USER", "jdoe")
    ip = masker.placeholder_for(m, "IP_PRIVATE", "10.1.2.3")
    masker.placeholder_for(m, "SUBNET", "10.1.2.0/24")
    ans = f"User <USER_1> (also `USER_1`, <user_1>, USER_1) hit {ip[:-1]} in SUBNET_1> and <IP_1>. <HOST_9> is unknown; file_1 untouched."
    r = unmasker.unmask(ans, m)
    assert r.text == ("User jdoe (also `jdoe`, jdoe, jdoe) hit 10.1.2.3 and 10.1.2.3. "
                      "<HOST_9> is unknown; file_1 untouched.")
    assert r.unknown == ["<HOST_9>"]
