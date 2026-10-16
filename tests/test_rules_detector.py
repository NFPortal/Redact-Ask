import ipaddress

from redactask import rules_detector


def found(text, cfg, subnets=()):
    return {(f.type, f.value) for f in rules_detector.detect(text, cfg, subnets)}


def test_ip_classification_and_subnets(cfg):
    fs = {f.value: f for f in rules_detector.detect(
        "a 8.8.8.8 b 10.1.2.3 c 127.0.0.1 d 255.255.255.0 e 100.64.1.2", cfg)}
    assert fs["8.8.8.8"].type == "IP"
    assert fs["10.1.2.3"].type == "IP_PRIVATE" and fs["10.1.2.3"].subnet == "10.1.2.0/24"
    assert fs["127.0.0.1"].type == "IP_LOCAL"
    assert "255.255.255.0" not in fs                     # netmask, not an address
    assert fs["100.64.1.2"].type == "IP_PRIVATE"        # CGNAT / Tailscale


def test_subnet_from_list_and_text(cfg):
    fs = {f.value: f for f in rules_detector.detect("net 10.30.0.0/16 host 10.30.5.9", cfg)}
    assert fs["10.30.5.9"].subnet == "10.30.0.0/16"
    assert ("SUBNET", "10.30.0.0/16") in {(f.type, f.value) for f in fs.values()}
    fs = {f.value: f for f in rules_detector.detect("host 10.40.5.9", cfg, [ipaddress.ip_network("10.40.0.0/20")])}
    assert fs["10.40.5.9"].subnet == "10.40.0.0/20"


def test_ipv6(cfg):
    r = found("from fe80::1 and 2606:4700:4700::1111 and fd12:3456::7", cfg)
    assert ("IP_LOCAL", "fe80::1") in r
    assert ("IP", "2606:4700:4700::1111") in r
    assert ("IP_PRIVATE", "fd12:3456::7") in r
    assert not any(t.startswith("IP") for t, v in found("at 12:30:45 done", cfg))


def test_users_and_homes(cfg):
    r = found("C:\\Users\\jdoe\\x /home/asmith/y CORP\\bwayne user=kchen Accepted password for mlopez from 1.2.3.4", cfg)
    for u in ("jdoe", "asmith", "bwayne", "kchen", "mlopez"):
        assert ("USER", u) in r
    assert ("DOMAIN", "CORP") in r
    assert ("USER", "Public") not in found("C:\\Users\\Public\\x", cfg)


def test_unc_and_internal_hosts(cfg):
    r = found("\\\\nas01\\finance and \\\\fs1\\C$ and db01.corp.local and printer.example.com", cfg)
    assert ("HOST", "nas01") in r and ("PATH", "finance") in r
    assert ("PATH", "C$") not in r                       # admin shares are kept
    assert ("HOST", "db01.corp.local") in r
    assert not any(v == "printer.example.com" for _, v in r)


def test_email_but_not_git_ssh(cfg):
    r = found("mail bob@contoso.com, repo git@github.com:acme/app.git", cfg)
    assert ("EMAIL", "bob@contoso.com") in r
    assert not any(t == "EMAIL" and "git@" in v for t, v in r)
    assert ("ORG", "acme") in r and ("REPO", "app") in r


def test_key_value_never_crosses_lines(cfg):
    r = found("- cluster:\n    server: https://x.lan\n", cfg)
    assert ("CLUSTER", "server") not in r


def test_sql_names(cfg):
    sql = "SELECT e.emp_ssn, p.net FROM hr.employees e JOIN payroll p ON p.id = e.id WHERE e.mail = 'a@b.co';"
    r = found(sql, cfg)
    assert ("TABLE", "hr.employees") in r and ("TABLE", "payroll") in r
    assert ("COLUMN", "emp_ssn") in r and ("COLUMN", "net") in r
    assert ("SQL_VALUE", "a@b.co") in r
    assert ("PROC", "dbo.usp_X") in found("EXEC dbo.usp_X @a = 1;", cfg)
    assert ("DB", "Payroll") in found("Server=x;Database=Payroll;", cfg)
    # ordinary log English is not treated as SQL
    assert not any(t == "TABLE" for t, _ in found("Accepted publickey for bob from 10.0.0.1", cfg))


def test_identity_numbers(cfg):
    r = found("card 4111 1111 1111 1111 ssn 523-41-8876 iban GB82 WEST 1234 5698 7654 32", cfg)
    assert ("CARD", "4111 1111 1111 1111") in r
    assert ("GOV_ID", "523-41-8876") in r
    assert ("BANK", "GB82 WEST 1234 5698 7654 32") in r
    assert not any(t == "CARD" for t, _ in found("order 1234 5678 9012 3456", cfg))   # fails Luhn


def test_env_values_only_dotenv_style(cfg):
    assert ("ENV_VALUE", "production") in found("APP_ENV=production", cfg)
    assert not any(t == "ENV_VALUE" for t, _ in found('API_BASE = "https://x.com"', cfg))


def test_off_by_default_types_are_still_reported(cfg):
    # merger drops these unless enabled; the detector reports them.
    r = found("vlan 120 uid=0 port=8443", cfg)
    assert ("VLAN", "120") in r and ("UID", "0") not in r and ("PORT", "8443") in r


def test_netmask_sets_real_subnet_for_address_and_gateway(cfg):
    text = ("   IPv4 Address. . . . . . . . . . . : 10.50.20.31\n"
            "   Subnet Mask . . . . . . . . . . . : 255.255.254.0\n"
            "   Default Gateway . . . . . . . . . : 10.50.21.1\n")
    fs = {f.value: f for f in rules_detector.detect(text, cfg)}
    assert fs["10.50.20.31"].subnet == fs["10.50.21.1"].subnet == "10.50.20.0/23"
    assert "255.255.254.0" not in fs
    fs = {f.value: f for f in rules_detector.detect("inet 192.168.8.20  netmask 255.255.252.0  broadcast 192.168.11.255", cfg)}
    assert fs["192.168.8.20"].subnet == "192.168.8.0/22"
    fs = {f.value: f for f in rules_detector.detect(" ip address 10.120.0.1 255.255.0.0", cfg)}
    assert fs["10.120.0.1"].subnet == "10.120.0.0/16"
