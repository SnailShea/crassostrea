"""Rate limits page: inbound limits per sending host (Postfix), per sending IP
and recipient (rspamd: inbound_limit.redis.lua in Valkey), exempt networks."""
import os
import subprocess
from pathlib import Path

import pytest

from crassostrea.extensions import db
from crassostrea.services import filters, ratelimits
from crassostrea.services.errors import ServiceError
from crassostrea.services.maps import sync_all

REPO = Path(__file__).resolve().parents[3]
SCRIPT = REPO / "data" / "conf" / "rspamd" / "lua" / "inbound_limit.redis.lua"
POSTFIX_APPLY = REPO / "system" / "libexec" / "postfix-apply"


@pytest.fixture
def check(fake_redis):
    """inbound_limit.redis.lua as rspamd.local.lua calls it: the limits that
    apply to a message, as (kind, key, limit, seconds)."""
    script = fake_redis.register_script(SCRIPT.read_text())

    def run(*rules, now=1_800_000_000):
        keys, args = [], [str(now)]
        for kind, key, limit, seconds in rules:
            keys.append(f"sf_irl:{kind}:{seconds}:{key}:{now // seconds}")
            args += [str(limit), str(seconds), f"{kind}:{key}"]
        return script(keys=keys, args=args)
    return run


def test_counting_script(check, fake_redis):
    ip = ("ip", "203.0.113.5", 3, 3600)
    assert check(ip, ("rcpt", "a@example.com", 2, 3600)) == [1]
    assert check(ip, ("rcpt", "a@example.com", 2, 3600)) == [1]
    # the recipient is full: refused, and nothing is counted
    assert check(ip, ("rcpt", "a@example.com", 2, 3600)) == [0, 2]
    assert fake_redis.get("sf_irl:ip:3600:203.0.113.5:500000") == "2"
    assert check(ip, ("rcpt", "b@example.com", 2, 3600)) == [1]
    assert check(ip, ("rcpt", "c@example.com", 2, 3600)) == [0, 1]  # the IP is full
    assert fake_redis.ttl("sf_irl:ip:3600:203.0.113.5:500000") > 0
    hit = fake_redis.hgetall("sf_irl_hit:rcpt:a@example.com")
    assert hit["count"] == "1" and hit["limit"] == "2" and hit["seconds"] == "3600"
    # a new period starts empty
    assert check(("rcpt", "a@example.com", 2, 3600), now=1_800_003_600) == [1]


def test_hits_and_reset(app, check, fake_redis):
    for _ in range(3):
        check(("rcpt", "a@example.com", 2, 3600))
    hits = ratelimits.hits()
    assert hits == [{"kind": "rcpt", "key": "a@example.com", "count": 1, "at": 1_800_000_000, "limit": 2,
                     "seconds": 3600}]
    assert ratelimits.reset("rcpt", "a@example.com") == 1
    assert ratelimits.hits() == [] and check(("rcpt", "a@example.com", 2, 3600)) == [1]
    # glob characters in a key are literals
    assert ratelimits.reset("rcpt", "*") == 0 and ratelimits.reset("other", "x") == 0


def test_settings_validation(app):
    values = filters.update_settings(rate_limit_exempt="192.0.2.5\n2001:db8::/48, 198.51.100.0/24 192.0.2.5")
    assert values["rate_limit_exempt"] == "192.0.2.5/32\n198.51.100.0/24\n2001:db8::/48"
    for value, message in (("not-a-net", "not a network"), ("0.0.0.0/0", "turns the rate limits off")):
        with pytest.raises(ServiceError, match=message):
            filters.update_settings(rate_limit_exempt=value)
    with pytest.raises(ServiceError):
        filters.update_settings(smtp_connection_count_limit=5000)
    with pytest.raises(ServiceError):
        filters.update_settings(inbound_ip_period="week")


def test_maps(app, config):
    filters.update_settings(smtp_connection_rate_limit=60, smtp_message_rate_limit=0, inbound_ip_limit=100,
                            inbound_ip_period="hour", inbound_bounce_limit=5, inbound_bounce_period="day",
                            rate_limit_exempt="192.0.2.0/24")
    db.session.commit()
    assert sync_all()
    rspamd = Path(config["RSPAMD_MAP_DIR"])
    assert (rspamd / "inbound_limits.map").read_text().splitlines()[1:] == ["ip 100:3600", "bounce 5:86400"]
    assert (rspamd / "rate_limit_exempt.map").read_text().splitlines()[1:] == ["192.0.2.0/24"]
    postfix = Path(config["POSTFIX_DYNAMIC_DIR"])
    assert (postfix / "rate_limits").read_text() == (
        "smtpd_client_connection_count_limit=50\nsmtpd_client_connection_rate_limit=60\n"
        "smtpd_client_message_rate_limit=0\nsmtpd_client_recipient_rate_limit=0\n")
    assert (postfix / "rate_limit_exempt.cidr").read_text().splitlines()[1:] == ["192.0.2.0/24\tOK"]


def test_page(logged_in, check, fake_redis):
    page = logged_in.get("/rate-limits/").get_data(as_text=True)
    assert "SMTP connections" in page and 'name="smtp_connection_count_limit"' in page and 'value="50"' in page
    assert 'class="active" aria-current="page">Rate limits</a>' in page and "Nothing was deferred" in page
    data = {"smtp_connection_count_limit": "20", "smtp_connection_rate_limit": "30", "smtp_message_rate_limit": "0",
            "smtp_recipient_rate_limit": "0", "inbound_ip_limit": "200", "inbound_ip_period": "hour",
            "inbound_rcpt_limit": "0", "inbound_rcpt_period": "hour", "inbound_bounce_limit": "0",
            "inbound_bounce_period": "hour", "rate_limit_exempt": "bogus"}
    response = logged_in.post("/rate-limits/", data=data)
    assert response.status_code == 400 and "bogus is not a network" in response.get_data(as_text=True)
    response = logged_in.post("/rate-limits/", data={**data, "rate_limit_exempt": "192.0.2.1"})
    assert response.status_code == 302
    assert filters.get_settings()["inbound_ip_limit"] == 200
    for _ in range(2):
        check(("ip", "203.0.113.5", 1, 3600))
    page = logged_in.get("/rate-limits/").get_data(as_text=True)
    assert "203.0.113.5" in page and "1 messages from one sending IP address per hour" in page
    logged_in.post("/rate-limits/reset", data={"kind": "ip", "key": "203.0.113.5"})
    assert ratelimits.hits() == []


def test_api(api, check):
    body = api("PATCH", "/settings", json={"inbound_rcpt_limit": 50, "inbound_rcpt_period": "minute"}).get_json()
    assert body["inbound_rcpt_limit"] == 50 and body["inbound_rcpt_period"] == "minute"
    assert api("PATCH", "/settings", json={"rate_limit_exempt": "x"}).status_code == 422
    for _ in range(2):
        check(("rcpt", "a@example.com", 1, 60))
    assert api("GET", "/rate-limits/hits").get_json()["hits"][0]["key"] == "a@example.com"
    assert api("POST", "/rate-limits/reset", json={"kind": "nope", "key": "x"}).status_code == 422
    assert api("POST", "/rate-limits/reset", json={"kind": "rcpt", "key": "A@example.com"}).get_json()["counters"] == 1


def test_postfix_apply(tmp_path):
    """postfix-apply sets only the known parameters with whole numbers."""
    bin_dir, dynamic = tmp_path / "bin", tmp_path / "postfix"
    bin_dir.mkdir()
    dynamic.mkdir()
    calls = tmp_path / "calls"
    (bin_dir / "postconf").write_text(f'#!/bin/bash\necho "postconf $*" >> {calls}\n[[ $1 == -h ]] && echo 50\nexit 0\n')
    (bin_dir / "systemctl").write_text("#!/bin/bash\nexit 3\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    (dynamic / "rate_limits").write_text(
        "smtpd_client_connection_count_limit=50\nsmtpd_client_connection_rate_limit=30\n"
        "smtpd_client_message_rate_limit=1;reboot\nmyhostname=evil.example\n")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "POSTFIX_DYNAMIC_DIR": str(dynamic)}
    result = subprocess.run(["bash", str(POSTFIX_APPLY)], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    applied = [line for line in calls.read_text().splitlines() if line.startswith("postconf -e")]
    # count_limit is already 50: unchanged
    assert applied == ["postconf -e smtpd_client_connection_rate_limit=30"]
    assert result.stderr.count("Ignoring a line") == 2
