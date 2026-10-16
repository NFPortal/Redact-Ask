from redactask import lists_detector
from redactask.lists_detector import ListData


def test_whole_word_with_separators():
    data = ListData(values={"TABLE": {"orders"}, "USER": {"jdoe"}})
    text = "acme_billing.orders, orders_archive, reorders, JDOE logged in, jdoe2"
    hits = [(f.type, f.value) for f in lists_detector.detect(text, data)]
    assert hits.count(("TABLE", "orders")) == 2      # . and _ are separators
    assert ("USER", "JDOE") in hits                  # case-insensitive
    assert not any(v == "jdoe" for _, v in hits)     # jdoe2 is a different word


def test_load_lists_custom_and_subnets(isolated_home):
    from redactask import config
    config.load()
    d = config.dirs()
    (d.lists / "hosts.txt").write_text("# comment\natlas-prod\n", encoding="utf-8")
    (d.lists / "custom.txt").write_text("CUSTOMER_ID ACME-42\nBOGUS x\n", encoding="utf-8")
    (d.lists / "subnets.txt").write_text("10.20.0.0/16\nnot-a-cidr\n", encoding="utf-8")
    data = lists_detector.load(d.lists)
    assert "atlas-prod" in data.values["HOST"]
    assert "ACME-42" in data.values["CUSTOMER_ID"]
    assert [str(n) for n in data.subnets] == ["10.20.0.0/16"]
    assert len(data.warnings) == 2
    assert data.contains("HOST", "ATLAS-PROD")
