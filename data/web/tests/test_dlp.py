"""Outbound data loss prevention: detectors, rules, their JSON for rspamd,
the rule test and the outbound quarantine of matching mail."""
import io
import json
import os
import shutil
import subprocess

import pytest

from crassostrea.extensions import db
from crassostrea.models import DlpRule, QuarantineItem, set_setting
from crassostrea.services import dlp
from crassostrea.services.errors import ServiceError

LUA = os.path.join(os.path.dirname(__file__), "..", "..", "conf", "rspamd", "lua", "dlp_detectors.lua")

SAMPLE = """Card 4111 1111 1111 1111 and 5500-0000-0000-0004, not 4111 1111 1111 1112.
Amex 378282246310005. Phone 0049 30 1234567. Order 1234567890123. Twice: 4111111111111111.
IBAN DE89 3704 0044 0532 0130 00 BANK and gb82west12345698765432, bad DE89 3704 0044 0532 0130 01.
SSN 123-45-6789, 666-12-3456, 078-05-1120, 123-00-4567, 1123-45-6789. Strictly Confidential!"""
EXPECTED = {
    "credit_card": {"4111111111111111", "5500000000000004", "378282246310005"},
    "iban": {"DE89370400440532013000", "GB82WEST12345698765432"},
    "us_ssn": {"123-45-6789", "078-05-1120"},
}


@pytest.mark.parametrize("detector", sorted(EXPECTED))
def test_detectors(detector):
    assert getattr(dlp, detector)(SAMPLE) == EXPECTED[detector]


def test_keywords_and_regex():
    assert dlp.keywords(SAMPLE, ["confidential", "Secret", "BANK"]) == {"confidential", "bank"}
    assert dlp.regex(SAMPLE, r"(?i)order \d+") == {"Order 1234567890123"}


@pytest.mark.skipif(not shutil.which("rspamadm"), reason="rspamd is not installed")
def test_lua_detectors_find_the_same(tmp_path):
    script = tmp_path / "check.lua"
    script.write_text(f"""
local d = dofile({json.dumps(os.path.abspath(LUA))})
local text = {json.dumps(SAMPLE)}
local function keys(t) local r = {{}} for k in pairs(t) do r[#r + 1] = k end table.sort(r) return r end
local ucl = require "ucl"
print(ucl.to_format({{credit_card = keys(d.credit_card(text)), iban = keys(d.iban(text)),
  us_ssn = keys(d.us_ssn(text)), keywords = keys(d.keywords(text, {{'confidential', 'Secret', 'BANK'}}))}}, 'json'))
""")
    result = subprocess.run(["rspamadm", "lua", str(script)], capture_output=True, text=True, timeout=60,
                            cwd=tmp_path, check=False)
    found = json.loads(result.stdout[result.stdout.index("{"):])
    assert {k: set(found[k]) for k in EXPECTED} == EXPECTED
    assert set(found["keywords"]) == {"confidential", "bank"}


def test_rule_validation(app):
    rule = dlp.add_rule(name="Cards", detector="credit_card", min_matches=2, sender="Example.com")
    db.session.commit()
    assert (rule.action, rule.active, rule.sender, rule.pattern) == ("quarantine", True, "example.com", "")
    for data, field in [
        ({"name": "Cards", "detector": "iban"}, "name"),
        ({"name": 'Say "hi"', "detector": "iban"}, "name"),
        ({"name": "x", "detector": "dna"}, "detector"),
        ({"name": "x", "detector": "keywords", "pattern": " \n "}, "pattern"),
        ({"name": "x", "detector": "regex", "pattern": "([a-z"}, "pattern"),
        ({"name": "x", "detector": "regex", "pattern": "/abc/i"}, "pattern"),
        ({"name": "x", "detector": "regex", "pattern": "a*"}, "pattern"),
        ({"name": "x", "detector": "iban", "min_matches": 0}, "min_matches"),
        ({"name": "x", "detector": "iban", "action": "shred"}, "action"),
        ({"name": "x", "detector": "iban", "sender": "not valid"}, "sender"),
    ]:
        with pytest.raises(ServiceError) as exc:
            dlp.add_rule(**data)
        assert exc.value.field == field, data
        db.session.rollback()
    # switching to keywords needs keywords
    with pytest.raises(ServiceError):
        dlp.update_rule(rule, detector="keywords")
    db.session.rollback()


def test_json_for_rspamd(app):
    dlp.add_rule(name="Cards", detector="credit_card", min_matches=5)
    dlp.add_rule(name="Words", detector="keywords", pattern="Project Bluebird\n\n  merger  \n", action="header")
    dlp.add_rule(name="Off", detector="iban", active=False)
    dlp.add_rule(name="Orders", detector="regex", pattern=r"ORDER-\d{6}", sender="orders@example.com",
                 action="reject")
    db.session.commit()
    data = json.loads(dlp.build_json())["rules"]
    assert [r["name"] for r in data] == ["Cards", "Orders", "Words"]
    assert data[2]["keywords"] == ["Project Bluebird", "merger"] and "pattern" not in data[2]
    assert data[1] == {"name": "Orders", "detector": "regex", "min_matches": 1, "sender": "orders@example.com",
                       "action": "reject", "pattern": r"ORDER-\d{6}"}


def test_rule_test(app):
    dlp.add_rule(name="Cards", detector="credit_card", min_matches=2)
    dlp.add_rule(name="Bob only", detector="us_ssn", sender="bob@example.com")
    db.session.commit()
    bob, cards = dlp.test(SAMPLE)
    assert cards["matched"] and cards["count"] == 3 and bob["matched"]
    bob, cards = dlp.test("card 4111111111111111", sender="alice@example.com")
    assert not cards["matched"] and cards["count"] == 1 and not bob["applies"]
    with pytest.raises(ServiceError):
        dlp.test("")


def test_pages(app, logged_in):
    response = logged_in.post("/dlp/new", data={"name": "Cards", "detector": "credit_card", "min_matches": "3",
                                                "action": "quarantine", "active": "y"}, follow_redirects=True)
    assert "Rule Cards added" in response.get_data(as_text=True)
    path = os.path.join(app.config["RSPAMD_MAP_DIR"], "dlp_rules.json")
    assert json.load(open(path))["rules"][0]["min_matches"] == 3
    response = logged_in.post("/dlp/new", data={"name": "Bad", "detector": "regex", "pattern": "(",
                                                "min_matches": "1", "action": "reject"})
    assert response.status_code == 400 and "Invalid regular expression" in response.get_data(as_text=True)

    rule = DlpRule.query.filter_by(name="Cards").one()
    assert "Payment card numbers" in logged_in.get(f"/dlp/{rule.id}").get_data(as_text=True)
    # turned off: not in the JSON
    logged_in.post(f"/dlp/{rule.id}", data={"name": "Cards", "detector": "credit_card", "min_matches": "3",
                                            "action": "quarantine"})
    assert json.load(open(path))["rules"] == []
    page = logged_in.post("/dlp/test", data={"text": SAMPLE}).get_data(as_text=True)
    assert "3 of 3" in page and "matches" in page and 'href="/dlp/" class="active"' in page
    logged_in.post(f"/dlp/{rule.id}/delete")
    assert DlpRule.query.count() == 0


def test_api(api):
    response = api("POST", "/dlp-rules", json={"name": "Words", "detector": "keywords", "pattern": "merger",
                                               "action": "header"})
    assert response.status_code == 201
    rule_id = response.get_json()["id"]
    assert api("POST", "/dlp-rules", json={"name": "Words", "detector": "iban"}).status_code == 409
    assert api("POST", "/dlp-rules", json={"name": "X", "detector": "iban", "min_matches": "2"}).status_code == 422
    body = api("PATCH", f"/dlp-rules/{rule_id}", json={"pattern": "merger\nacquisition", "min_matches": 2}).get_json()
    assert body["pattern"] == "merger\nacquisition" and body["min_matches"] == 2
    results = api("POST", "/dlp-rules/test", json={"text": "The merger and acquisition"}).get_json()["results"]
    assert results[0]["matched"] and results[0]["values"] == ["acquisition", "merger"]
    assert api("GET", "/dlp-rules").get_json()["total"] == 1
    assert api("DELETE", f"/dlp-rules/{rule_id}").status_code == 204


def _ingest(internal_app, symbols):
    meta = {"qid": "Q1", "subject": "Cards", "from": "alice@example.com", "rcpt": ["x@other.example"],
            "score": 0, "action": "reject", "ip": "192.0.2.10", "symbols": symbols}
    return internal_app.test_client().post(
        "/internal/quarantine", environ_base={"REMOTE_ADDR": "172.22.1.5"},
        data={"metadata": json.dumps(meta), "message": (io.BytesIO(b"Subject: Cards\r\n\r\nx\r\n"), "message")})


def test_dlp_quarantine_even_if_outbound_quarantine_is_off(internal_app):
    set_setting("quarantine_outbound", 0)
    db.session.commit()
    relay = {"name": "RELAY_NETWORK", "score": 0}
    assert _ingest(internal_app, [relay, {"name": "OUTBOUND_DLP", "score": 0}]).get_data(as_text=True) == \
        "skipped: outbound quarantine disabled"
    assert _ingest(internal_app, [relay, {"name": "OUTBOUND_DLP", "score": 0, "options": ["Cards"]},
                                  {"name": "OUTBOUND_DLP_QUARANTINE", "score": 0}]).status_code == 200
    item = QuarantineItem.query.one()
    assert (item.direction, item.domain, item.rcpt) == ("outbound", "example.com", "x@other.example")
