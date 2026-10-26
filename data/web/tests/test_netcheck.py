"""DNS & ports page: the checks against an in-memory zone, no network."""
import pytest

from crassostrea.extensions import db
from crassostrea.models import DkimKey, Domain, RelayNetwork
from crassostrea.services import dkim, netcheck
from crassostrea.services.netcheck import ERROR, INFO, OK, WARN

HOST = "mx.gateway.example"
HOST_IP = "203.0.113.10"
LOCAL = {HOST_IP, "127.0.0.1"}


@pytest.fixture
def zone(monkeypatch):
    """(name, type) -> records; a value of None makes the lookup fail."""
    records = {
        (HOST, "A"): [HOST_IP],
        ("10.113.0.203.in-addr.arpa", "PTR"): [HOST],
    }

    def lookup(name, rdtype):
        key = (name.rstrip(".").lower(), rdtype)
        if key in records and records[key] is None:
            raise netcheck.LookupFailed(f"{name} {rdtype}: timeout")
        if key not in records:
            raise netcheck.NoRecords(name)
        return list(records[key])
    monkeypatch.setattr(netcheck, "lookup", lookup)
    monkeypatch.setattr(netcheck, "is_local", lambda address: address in LOCAL)
    monkeypatch.setattr(netcheck, "source_addresses", lambda: [HOST_IP])
    # documentation addresses stand in for public ones
    monkeypatch.setattr(netcheck, "_is_public", lambda address: not address.startswith(("10.", "127.")))
    return records


@pytest.fixture
def connections(monkeypatch):
    """host -> (connected, detail) for every port; unknown hosts refuse."""
    hosts = {HOST_IP: (True, HOST_IP), "mx.internal": (True, "10.0.0.5"),
             "acme-v02.api.letsencrypt.org": (True, "172.65.32.248")}
    monkeypatch.setattr(netcheck, "connect", lambda host, port: hosts.get(host, (False, "Connection refused")))
    return hosts


# ---------------------------------------------------------------------------
# SPF
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("record, result", [
    ("v=spf1 ip4:203.0.113.0/24 -all", "pass"),
    ("v=spf1 ip4:198.51.100.1 -all", "fail"),
    ("v=spf1 ip4:198.51.100.1 ~all", "softfail"),
    ("v=spf1 ip4:198.51.100.1", "neutral"),
    ("v=spf1 a:mx.gateway.example -all", "pass"),
    ("v=spf1 a:other.example/24 -all", "pass"),
    ("v=spf1 a:other.example -all", "fail"),
    ("v=spf1 mx -all", "pass"),
    ("v=spf1 include:_spf.provider.example -all", "pass"),
    ("v=spf1 include:_spf.empty.example -all", "permerror (include:_spf.empty.example has no SPF record)"),
    ("v=spf1 redirect=_spf.provider.example", "pass"),
    ("v=spf1 -ip4:203.0.113.10 +all", "fail"),
    ("v=spf1 ptr -all", "fail"),
    ("v=spf1 exp=explain.example ip4:203.0.113.10 -all", "pass"),
    ("v=spf1 foo:bar -all", "permerror (unknown mechanism foo:bar)"),
])
def test_spf_evaluate(zone, record, result):
    zone[("example.com", "TXT")] = ["some-verification=1", record]
    zone[("example.com", "MX")] = [(10, HOST)]
    zone[("other.example", "A")] = ["203.0.113.99"]
    zone[("_spf.provider.example", "TXT")] = ["v=spf1 ip4:203.0.113.10 ip6:2001:db8::/32 -all"]
    zone[("_spf.empty.example", "TXT")] = ["unrelated"]
    assert netcheck.spf_evaluate(HOST_IP, "example.com") == result


def test_spf_lookup_limit(zone):
    zone[("example.com", "TXT")] = ["v=spf1 " + " ".join(f"a:h{i}.example" for i in range(11)) + " -all"]
    assert netcheck.spf_evaluate(HOST_IP, "example.com") == "permerror (more than 10 DNS lookups)"


def test_spf_macros_are_not_evaluated(zone):
    zone[("example.com", "TXT")] = ["v=spf1 exists:%{i}.spf.example -all"]
    with pytest.raises(netcheck.SpfUnsupported):
        netcheck.spf_evaluate(HOST_IP, "example.com")


def test_check_spf(zone):
    assert netcheck.check_spf("example.com", [HOST_IP])["status"] == WARN  # none
    zone[("example.com", "TXT")] = ["v=spf1 ip4:203.0.113.10 -all"]
    row = netcheck.check_spf("example.com", [HOST_IP])
    assert row["status"] == OK and row["expected"] == "v=spf1 ip4:203.0.113.10 ~all"
    zone[("example.com", "TXT")] = ["v=spf1 ip4:198.51.100.1 -all"]
    assert netcheck.check_spf("example.com", [HOST_IP])["status"] == ERROR
    zone[("example.com", "TXT")] = ["v=spf1 ip4:198.51.100.1 ~all"]
    assert netcheck.check_spf("example.com", [HOST_IP])["status"] == WARN
    zone[("example.com", "TXT")] = ["v=spf1 -all", "v=spf1 +all"]
    assert netcheck.check_spf("example.com", [HOST_IP])["status"] == ERROR
    zone[("example.com", "TXT")] = None
    assert netcheck.check_spf("example.com", [HOST_IP])["status"] == WARN


# ---------------------------------------------------------------------------
# MX, DKIM, DMARC
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mx, status", [
    ([(10, HOST)], OK),
    ([(10, "alias.example")], OK),          # another name for the gateway's address
    ([(10, HOST), (20, "backup.example")], WARN),
    ([(10, "backup.example"), (20, HOST)], ERROR),
    ([(10, "backup.example")], ERROR),
    ([(0, "")], ERROR),                     # null MX
    (None, WARN),                           # lookup failed
    ([], ERROR),                            # no MX
])
def test_check_mx(zone, mx, status):
    zone[("alias.example", "A")] = [HOST_IP]
    zone[("backup.example", "A")] = ["198.51.100.20"]
    if mx != []:
        zone[("example.com", "MX")] = mx
    row = netcheck.check_mx("example.com", HOST, {HOST}, {HOST_IP})
    assert row["status"] == status, row


def test_check_mx_accepts_cluster_members(zone):
    zone[("example.com", "MX")] = [(10, HOST), (10, "mx2.gateway.example")]
    assert netcheck.check_mx("example.com", HOST, {HOST, "mx2.gateway.example"}, {HOST_IP})["status"] == OK


@pytest.fixture(scope="module")
def dkim_record():
    pem, _ = dkim.generate_private_key(2048)
    domain = Domain(name="example.com", destination_host="mx.internal")
    return dkim.dns_record(DkimKey(domain=domain, selector="sf1", private_key=pem, key_size=2048))


def test_check_dkim(zone, dkim_record):
    assert netcheck.check_dkim(dkim_record)["status"] == ERROR  # not published
    # published split into strings and with whitespace in p=
    value = dkim_record["value"]
    zone[("sf1._domainkey.example.com", "TXT")] = [value[:60] + " " + value[60:]]
    assert netcheck.check_dkim(dkim_record)["status"] == OK
    zone[("sf1._domainkey.example.com", "TXT")] = ["v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA"]
    row = netcheck.check_dkim(dkim_record)
    assert row["status"] == ERROR and "not the gateway's signing key" in row["message"]


@pytest.mark.parametrize("records, status", [
    ([], WARN),
    (["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"], OK),
    (["v=DMARC1;p=quarantine"], OK),
    (["v=DMARC1; p=none"], INFO),
    (["v=DMARC1; rua=mailto:x@example.com"], ERROR),
    (["v=DMARC1; p=reject", "v=DMARC1; p=none"], ERROR),
])
def test_check_dmarc(zone, records, status):
    if records:
        zone[("_dmarc.example.com", "TXT")] = records
    assert netcheck.check_dmarc("example.com")["status"] == status


# ---------------------------------------------------------------------------
# Gateway hostname
# ---------------------------------------------------------------------------

def test_check_host(zone):
    assert netcheck.check_host(HOST, [HOST_IP], None, None, [HOST_IP])["status"] == OK
    row = netcheck.check_host(HOST, [HOST_IP, "198.51.100.7"], None, None, [HOST_IP])
    assert row["status"] == WARN and "198.51.100.7 is not an address of this server" in row["message"]
    # the floating address of a cluster may be on another node
    assert netcheck.check_host(HOST, ["198.51.100.7"], None, "198.51.100.7", [HOST_IP])["status"] == OK
    assert netcheck.check_host(HOST, [], None, None, [HOST_IP])["status"] == ERROR
    assert netcheck.check_host(HOST, [], "timeout", None, [HOST_IP])["status"] == ERROR


def test_check_ptr(zone):
    assert netcheck.check_ptr(HOST_IP, HOST, [HOST_IP])["status"] == OK
    row = netcheck.check_ptr(HOST_IP, HOST, [])
    assert row["status"] == WARN and "does not resolve to" in row["message"]
    zone[("10.113.0.203.in-addr.arpa", "PTR")] = ["static-10.provider.example"]
    assert netcheck.check_ptr(HOST_IP, HOST, [HOST_IP])["status"] == WARN
    del zone[("10.113.0.203.in-addr.arpa", "PTR")]
    row = netcheck.check_ptr(HOST_IP, HOST, [HOST_IP])
    assert row["status"] == WARN and "No reverse DNS" in row["message"]


def test_check_caa(zone):
    assert netcheck.check_caa(HOST)["status"] == OK  # none: every CA
    zone[("gateway.example", "CAA")] = [("issue", "letsencrypt.org"), ("iodef", "mailto:x@gateway.example")]
    row = netcheck.check_caa(HOST)
    assert row["status"] == OK and row["record"] == "gateway.example"
    zone[("gateway.example", "CAA")] = [("issue", "digicert.com; cansignhttpexchanges=yes")]
    assert netcheck.check_caa(HOST)["status"] == ERROR
    # the closest name with records wins
    zone[(HOST, "CAA")] = [("issue", "letsencrypt.org")]
    assert netcheck.check_caa(HOST)["status"] == OK


# ---------------------------------------------------------------------------
# Ports and the page
# ---------------------------------------------------------------------------

def test_check_downstream(zone, connections):
    assert netcheck.check_downstream("mx.internal", 25, False, ["example.com"])["status"] == OK
    row = netcheck.check_downstream("down.internal", 2525, False, ["example.com"])
    assert row["status"] == ERROR and "down.internal: Connection refused" in row["message"]
    zone[("corp.example", "MX")] = [(20, "mx.internal"), (10, "down.internal")]
    row = netcheck.check_downstream("corp.example", 25, True, ["example.com"])
    assert row["status"] == OK and "mx.internal" in row["message"]  # the first that connects


def _setup(app, relay=False, **config):
    app.config.update({"HOSTNAME": HOST, **config})
    domain = Domain(name="example.com", destination_host="mx.internal")
    db.session.add(domain)
    db.session.add(Domain(name="inactive.example", destination_host="mx.internal", active=False))
    if relay:
        db.session.add(RelayNetwork(cidr="192.0.2.0/24"))
    db.session.commit()
    return domain


def test_run(app, zone, connections):
    _setup(app, relay=True, CLUSTER_NODES=[(HOST, "10.0.0.1"), ("mx2.gateway.example", "10.0.0.2")],
           CLUSTER_WITNESS=("witness.gateway.example", "10.0.0.3"))
    zone[("example.com", "MX")] = [(10, HOST), (10, "mx2.gateway.example")]
    zone[("example.com", "TXT")] = ["v=spf1 ip4:203.0.113.10 -all"]
    zone[("_dmarc.example.com", "TXT")] = ["v=DMARC1; p=reject"]
    connections["10.0.0.2"] = (True, "10.0.0.2")
    results = netcheck.run(netcheck.settings())

    assert [(c["type"], c["status"]) for c in results["gateway"]] == [("A/AAAA", OK), ("PTR", OK), ("CAA", OK)]
    assert [name for name, _ in results["domains"]] == ["example.com"]
    assert [(c["type"], c["status"]) for c in results["domains"][0][1]] == [
        ("MX", OK), ("TXT (SPF)", OK), ("TXT (DMARC)", OK)]
    assert [(p["port"], p["status"]) for p in results["inbound"]] == [
        ("25/tcp", OK), ("80/tcp", OK), ("443/tcp", OK)]
    assert [(p["port"], p["status"]) for p in results["outbound"]] == [
        ("53/udp+tcp", OK), ("25/tcp", OK), ("443/tcp", OK), ("25/tcp", INFO)]
    # mx2 is reachable, the witness is not; this node is not checked
    assert [(p["target"], p["port"], p["status"]) for p in results["cluster"]] == [
        ("mx2.gateway.example (10.0.0.2)", "4567/tcp", OK),
        ("mx2.gateway.example (10.0.0.2)", "6380/tcp", OK),
        ("mx2.gateway.example (10.0.0.2)", "26379/tcp", OK),
        ("witness.gateway.example (10.0.0.3)", "4567/tcp", ERROR),
        ("witness.gateway.example (10.0.0.3)", "26379/tcp", ERROR)]
    assert netcheck.summary(results) == {OK: 15, WARN: 0, ERROR: 2, INFO: 1}


def test_run_without_relay_networks_or_lets_encrypt(app, zone, connections):
    _setup(app, LETS_ENCRYPT=False)
    zone[("example.com", "MX")] = [(10, HOST)]
    results = netcheck.run(netcheck.settings())
    # SPF and DMARC only matter when the gateway sends the domains' mail
    assert [c["type"] for c in results["domains"][0][1]] == ["MX"]
    assert [c["type"] for c in results["gateway"]] == ["A/AAAA", "PTR"]
    assert [(p["port"], p["status"]) for p in results["outbound"]] == [("53/udp+tcp", OK), ("25/tcp", OK)]
    # port 80 is only required for Let's Encrypt's HTTP validation
    assert results["inbound"][1]["purpose"] == "HTTP: redirect to HTTPS"
    assert results["cluster"] == []


def test_run_when_the_resolver_fails(app, zone, connections):
    _setup(app)
    zone[(HOST, "A")] = None
    zone[(HOST, "AAAA")] = None
    results = netcheck.run(netcheck.settings())
    assert results["gateway"][0]["status"] == ERROR
    assert results["outbound"][0]["status"] == ERROR and "timeout" in results["outbound"][0]["message"]


def test_page(logged_in, app, zone, connections):
    domain = _setup(app, relay=True)
    db.session.add(DkimKey(domain=domain, selector="sf1", private_key=dkim.generate_private_key(2048)[0],
                           key_size=2048))
    db.session.commit()
    zone[("example.com", "MX")] = [(10, "backup.example"), (20, HOST)]
    response = logged_in.get("/network")
    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert "DNS &amp; ports" in html and "sf1._domainkey.example.com" in html
    assert "has a higher priority (lower number) than the gateway" in html
    assert "nc -vz mx.gateway.example 25" in html
    assert 'href="/network" class="active"' in html


def test_page_requires_an_administrator(client):
    assert client.get("/network").status_code == 302
