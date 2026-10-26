"""Outbound limits: the limits, their map for rspamd, the Valkey counting
script rspamd runs and the counts shown on the page."""
import os
import time

import pytest
import redis

from crassostrea.extensions import db
from crassostrea.models import OutboundLimit, set_setting
from crassostrea.services import outbound
from crassostrea.services.errors import ServiceError

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "..", "conf", "rspamd", "lua", "outbound_limit.redis.lua")


@pytest.fixture
def check(fake_redis):
    """outbound_limit.redis.lua as rspamd.local.lua calls it: True if the
    message is within the limit."""
    script = fake_redis.register_script(open(SCRIPT).read())

    def run(sender, recipients, limit, seconds=3600, now=None):
        now = int(now or time.time())
        key = f"sf_rl:{seconds}:{sender}:{now // seconds}"
        allowed, _ = script(keys=[key], args=[recipients, limit, seconds, sender, now])
        return allowed == 1
    return run


@pytest.mark.parametrize("value, expected", [
    ("Alice@Example.COM", "alice@example.com"), ("example.com", "example.com"), ("@example.com", "example.com"),
    ("*@Example.com", "example.com"),
])
def test_normalize_sender(app, value, expected):
    assert outbound.normalize_sender(value) == expected


@pytest.mark.parametrize("value", ["", "not a domain", "a@@b", None])
def test_invalid_sender(app, value):
    with pytest.raises(ServiceError, match="address or a domain"):
        outbound.normalize_sender(value)


def test_map_and_lookup(app):
    assert outbound.build_map() == []
    outbound.add_limit("newsletter@example.com", 5000, "day")
    outbound.add_limit("example.com", 200)
    outbound.add_limit("trusted@example.com", 0)
    db.session.commit()
    with pytest.raises(ServiceError) as exc:
        outbound.add_limit("Example.com", 1)
    assert exc.value.status == 409
    for bad in ({"max_recipients": -1}, {"max_recipients": "x"}, {"max_recipients": True}, {"period": "week"}):
        with pytest.raises(ServiceError):
            outbound.add_limit("other.example", **{"max_recipients": 1, **bad})
    db.session.rollback()
    set_setting("outbound_limit", 100)
    db.session.commit()
    assert outbound.build_map() == ["* 100:3600", "@example.com 200:3600", "newsletter@example.com 5000:86400",
                                    "trusted@example.com 0:3600"]
    assert outbound.limit_for("newsletter@example.com") == (5000, "day", "newsletter@example.com")
    assert outbound.limit_for("bob@example.com") == (200, "hour", "example.com")
    assert outbound.limit_for("trusted@example.com") is None
    assert outbound.limit_for("someone@other.example") == (100, "hour", "default")
    assert outbound.limit_for("bounces:192.0.2.5") == (100, "hour", "default")


def test_counting_script(app, check, fake_redis):
    now = 1_800_000_000
    assert check("alice@example.com", 6, 10, now=now)
    assert check("alice@example.com", 4, 10, now=now)
    # the eleventh recipient is refused, and the refusal is not counted
    assert not check("alice@example.com", 1, 10, now=now)
    assert not check("alice@example.com", 1, 10, now=now + 1)
    key = f"sf_rl:3600:alice@example.com:{now // 3600}"
    assert fake_redis.get(key) == "10" and 0 < fake_redis.ttl(key) <= 3600
    assert fake_redis.hgetall("sf_rl_hit:alice@example.com") == {"count": "2", "at": str(now + 1), "limit": "10",
                                                                  "seconds": "3600"}
    # the next hour is a new window; others are counted on their own
    assert check("alice@example.com", 10, 10, now=now + 3600)
    assert check("bob@example.com", 10, 10, now=now)


def test_counts_hits_and_reset(app, check, fake_redis):
    db.session.add(OutboundLimit(sender="example.com", max_recipients=5, period="hour"))
    db.session.commit()
    check("alice@example.com", 5, 5)
    check("alice@example.com", 1, 5)
    check("bob@example.com", 2, 5)
    check("bob*@example.com", 1, 50, seconds=60)
    usage = outbound.usage()
    assert usage[0] == {"sender": "alice@example.com", "count": 5, "period": "hour", "limit": 5}
    assert {"sender": "bob*@example.com", "count": 1, "period": "minute", "limit": None} in usage
    [hit] = outbound.hits()
    assert (hit["sender"], hit["count"], hit["limit"], hit["period"]) == ("alice@example.com", 1, 5, "hour")
    # a glob character in a sender does not reset others
    assert outbound.reset("bob*@example.com")
    assert {u["sender"] for u in outbound.usage()} == {"alice@example.com", "bob@example.com"}
    assert outbound.reset("Alice@example.com") and outbound.hits() == []
    assert [u["sender"] for u in outbound.usage()] == ["bob@example.com"]
    assert not outbound.reset("nobody@example.com")
    # a hit record that expired is dropped from the index
    check("bob@example.com", 9, 5)
    fake_redis.delete("sf_rl_hit:bob@example.com")
    assert outbound.hits() == [] and fake_redis.zcard("sf_rl_hits") == 0


def test_page(app, logged_in, check):
    response = logged_in.post("/outbound/default", data={"outbound_limit": "300", "outbound_limit_period": "hour"},
                              follow_redirects=True)
    assert "Every sender may now send to 300 recipients per hour" in response.get_data(as_text=True)
    map_file = os.path.join(app.config["RSPAMD_MAP_DIR"], "outbound_limits.map")
    assert "* 300:3600\n" in open(map_file).read()

    logged_in.post("/outbound/limits", data={"sender": "News@Example.com", "max_recipients": "5000",
                                             "period": "day", "comment": "newsletter"})
    response = logged_in.post("/outbound/limits", data={"sender": "news@example.com", "max_recipients": "6000",
                                                        "period": "day"}, follow_redirects=True)
    assert "Limit for news@example.com changed" in response.get_data(as_text=True)
    assert "news@example.com 6000:86400\n" in open(map_file).read()
    response = logged_in.post("/outbound/limits", data={"sender": "not valid", "max_recipients": "1",
                                                        "period": "hour"})
    assert response.status_code == 400 and "address or a domain" in response.get_data(as_text=True)

    check("alice@example.com", 300, 300)
    check("alice@example.com", 1, 300)
    page = logged_in.get("/outbound/").get_data(as_text=True)
    assert "6000 recipients per day" in page and "alice@example.com" in page and "300 of 300 this hour" in page
    assert 'href="/outbound/" class="active"' in page
    response = logged_in.post("/outbound/reset", data={"sender": "alice@example.com"}, follow_redirects=True)
    assert "alice@example.com can send again" in response.get_data(as_text=True)

    limit = OutboundLimit.query.filter_by(sender="news@example.com").one()
    logged_in.post(f"/outbound/limits/{limit.id}/delete")
    assert "news@example.com" not in open(map_file).read()
    response = logged_in.post("/outbound/default", data={"outbound_limit": "0", "outbound_limit_period": "hour"},
                              follow_redirects=True)
    assert "no longer limited" in response.get_data(as_text=True) and "*" not in open(map_file).read()


def test_page_without_valkey(logged_in, monkeypatch):
    def down(*args, **kwargs):
        raise redis.ConnectionError("Connection refused")
    monkeypatch.setattr(outbound, "usage", down)
    page = logged_in.get("/outbound/").get_data(as_text=True)
    assert "Valkey cannot be reached (Connection refused)" in page


def test_api(app, api, check):
    response = api("POST", "/outbound-limits", json={"sender": "@example.com", "max_recipients": 50})
    assert response.status_code == 201 and response.get_json()["sender"] == "example.com"
    limit_id = response.get_json()["id"]
    assert response.get_json()["period"] == "hour"
    assert api("POST", "/outbound-limits", json={"sender": "example.com", "max_recipients": 5}).status_code == 409
    assert api("POST", "/outbound-limits", json={"sender": "x@example.org", "max_recipients": -5}).status_code == 422
    updated = api("PATCH", f"/outbound-limits/{limit_id}", json={"period": "minute"}).get_json()
    assert (updated["max_recipients"], updated["period"]) == (50, "minute")
    assert api("PATCH", f"/outbound-limits/{limit_id}", json={"sender": "other.example"}).status_code == 422
    assert api("GET", "/outbound-limits").get_json()["total"] == 1

    check("alice@example.com", 50, 50, seconds=60)
    check("alice@example.com", 1, 50, seconds=60)
    senders = api("GET", "/outbound-senders").get_json()
    assert senders["counts"][0] == {"sender": "alice@example.com", "count": 50, "period": "minute", "limit": 50}
    assert senders["deferred"][0]["sender"] == "alice@example.com"
    assert api("POST", "/outbound-senders/reset", json={"sender": "alice@example.com"}).get_json()["reset"] is True
    assert api("POST", "/outbound-senders/reset", json={}).status_code == 422

    settings = api("PATCH", "/settings", json={"outbound_limit": 1000, "outbound_limit_period": "day"}).get_json()
    assert (settings["outbound_limit"], settings["outbound_limit_period"]) == (1000, "day")
    assert api("PATCH", "/settings", json={"outbound_limit_period": "week"}).status_code == 422
    assert api("DELETE", f"/outbound-limits/{limit_id}").status_code == 204
    assert api("GET", f"/outbound-limits/{limit_id}").status_code == 404
