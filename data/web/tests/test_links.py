"""Link protection: the map for rspamd, clicks on rewritten links, the block
lists, the page and the API."""
import json
import os

import pytest
import redis

from crassostrea.extensions import db
from crassostrea.models import Domain, set_setting
from crassostrea.services import links, netcheck

LINK_ID = "0123456789abcdef01234567"


@pytest.fixture
def dns(monkeypatch):
    """Block list answers: {query name: [addresses]}; anything else does not exist."""
    answers = {}
    queries = []

    def lookup(name, rdtype):
        queries.append(name)
        if name in answers:
            return answers[name]
        raise netcheck.NoRecords(name)
    monkeypatch.setattr(netcheck, "lookup", lookup)
    answers["queries"] = queries
    return answers


def store_link(fake_redis, url, link_id=LINK_ID):
    fake_redis.set(links.LINK_PREFIX + link_id, url)


def test_map(app):
    db.session.add_all([Domain(name="example.com", destination_host="mx.internal", link_protection=True),
                        Domain(name="other.example", destination_host="mx.internal")])
    set_setting("link_protection_exempt_hosts", "intranet.example.com")
    db.session.commit()
    data = json.loads(links.build_json())
    hostname = app.config["HOSTNAME"]
    assert data["base"] == f"https://{hostname}/l/" and data["domains"] == ["example.com"]
    assert data["exempt"] == sorted({"intranet.example.com", hostname}) and data["ttl"] == 90 * 86400


def test_click_redirects(app, client, fake_redis, dns):
    store_link(fake_redis, "https://shop.example/deal?id=1&x=2")
    response = client.get(f"/l/{LINK_ID}")
    assert response.status_code == 302 and response.headers["Location"] == "https://shop.example/deal?id=1&x=2"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    [click] = links.clicks()
    assert (click["id"], click["host"], click["blocked"], click["ip"]) == (LINK_ID, "shop.example", False, "127.0.0.1")
    # the verdict is cached
    count = len(dns["queries"])
    client.get(f"/l/{LINK_ID}")
    assert len(dns["queries"]) == count


@pytest.mark.parametrize("link_id", ["0123456789abcdef0123456x", "short", "0123456789ABCDEF01234567"])
def test_unknown_links(client, fake_redis, link_id):
    response = client.get(f"/l/{link_id}")
    assert response.status_code == 404 and "This link does not work" in response.get_data(as_text=True)
    assert client.get(f"/l/{LINK_ID}").status_code == 404
    assert client.get("/l/../etc").status_code == 404


@pytest.mark.parametrize("zone, answer, blocked", [
    ("dbl.spamhaus.org", "127.0.1.4", True), ("dbl.spamhaus.org", "127.0.1.102", True),
    ("dbl.spamhaus.org", "127.255.255.254", False), ("multi.surbl.org", "127.0.0.16", True),
    ("multi.surbl.org", "127.0.0.1", False), ("multi.uribl.com", "127.0.0.2", True),
    ("multi.uribl.com", "127.0.0.4", False), ("multi.uribl.com", "127.0.0.1", False),
])
def test_block_lists(app, fake_redis, dns, zone, answer, blocked):
    dns[f"evil.example.{zone}"] = [answer]
    with app.test_request_context():
        assert links.check("https://login.evil.example/x")["blocked"] is blocked
    queried = [q for q in dns["queries"] if q.endswith(zone)]
    assert queried == [f"login.evil.example.{zone}", f"evil.example.{zone}"]


def test_dqs_key(app, fake_redis, dns):
    with open(app.config["CONF_FILE"], "w") as handle:
        handle.write("SPAMHAUS_DQS_KEY=abc123\n")
    with app.test_request_context():
        links.check("https://example.org/")
    assert "example.org.abc123.dbl.dq.spamhaus.net" in dns["queries"]


def test_blocked_page(app, client, fake_redis, dns):
    store_link(fake_redis, "https://www.badsite.example/login")
    set_setting("link_protection_block_domains", "badsite.example")
    db.session.commit()
    response = client.get(f"/l/{LINK_ID}")
    page = response.get_data(as_text=True)
    assert response.status_code == 200 and "This link was blocked" in page and "administrators blocked" in page
    assert "open it anyway" not in page and links.clicks(blocked_only=True)[0]["host"] == "www.badsite.example"
    set_setting("link_protection_allow_continue", 1)
    db.session.commit()
    assert 'href="https://www.badsite.example/login"' in client.get(f"/l/{LINK_ID}").get_data(as_text=True)


def test_ip_links_are_not_looked_up(app, fake_redis, dns):
    with app.test_request_context():
        assert links.check("http://192.0.2.10/x") == {"blocked": False, "reason": None, "host": "192.0.2.10"}
        assert links.check("http:///nohost")["blocked"]
    assert dns["queries"] == []


def test_valkey_down(client, monkeypatch):
    def down(link_id):
        raise redis.ConnectionError("refused")
    monkeypatch.setattr(links, "lookup", down)
    assert client.get(f"/l/{LINK_ID}").status_code == 503


def test_admin_page(app, logged_in, fake_redis, dns):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    db.session.commit()
    domain = Domain.query.one()
    logged_in.post(f"/domains/{domain.id}", data={"destination_host": "mx.internal", "destination_port": "25",
                                                 "recipient_check": "any", "link_protection": "y", "active": "y"})
    assert db.session.get(Domain, domain.id).link_protection
    response = logged_in.post("/link-protection/", data={
        "link_protection_exempt_hosts": "intranet.example.com", "link_protection_block_domains": "bad.example",
        "link_protection_days": "30"}, follow_redirects=True)
    assert "Link protection saved" in response.get_data(as_text=True)
    path = os.path.join(app.config["RSPAMD_MAP_DIR"], "link_protection.json")
    data = json.load(open(path))
    assert data["domains"] == ["example.com"] and data["ttl"] == 30 * 86400
    assert "intranet.example.com" in data["exempt"]
    page = logged_in.post("/link-protection/check", data={"check-url": "bad.example/x"}).get_data(as_text=True)
    assert "bad.example: blocked" in page and 'href="/link-protection/" class="active"' in page
    store_link(fake_redis, "https://shop.example/")
    logged_in.get(f"/l/{LINK_ID}")
    assert "shop.example" in logged_in.get("/link-protection/").get_data(as_text=True)


def test_api(api, fake_redis, dns):
    store_link(fake_redis, "https://shop.example/")
    api("PATCH", "/settings", json={"link_protection_block_domains": "shop.example"})
    assert api("POST", "/link-check", json={"url": "https://a.shop.example/"}).get_json()["blocked"] is True
    assert api("POST", "/link-check", json={"url": 5}).status_code == 422
    from flask import current_app
    current_app.test_client().get(f"/l/{LINK_ID}")
    assert api("GET", "/link-clicks?blocked=true").get_json()["items"][0]["host"] == "shop.example"
    body = api("POST", "/domains", json={"name": "example.com", "destination_host": "mx.internal",
                                         "link_protection": True}).get_json()
    assert body["link_protection"] is True
    assert api("PATCH", "/settings", json={"link_protection_days": 0}).status_code == 422
