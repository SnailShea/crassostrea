"""Release & allow / block the sender of a quarantined message, "forgot
password", the destination test, the problem badge of the sidebar, plain
explanations of Rspamd symbols and the layout of the settings page."""
import json
import re
import socket

import pytest

from crassostrea.extensions import db
from crassostrea.models import AccountToken, Domain, ListEntry, MailboxUser, QuarantineItem, utcnow
from crassostrea.services import mailer, monitoring, symbols
from crassostrea.services.accounts import create_mailbox_user
from crassostrea.services.digest import send_digest
from test_access_and_accounts import FakeSmtp


@pytest.fixture
def domain(app):
    d = Domain(name="example.com", destination_host="127.0.0.1", destination_port=25)
    db.session.add(d)
    db.session.commit()
    return d


@pytest.fixture
def outbox(monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, msg: sent.append((sender, rcpt, msg)))
    return sent


def _item(rcpt="alice@example.com", sender="news@shop.example", virus=False, direction="inbound"):
    symbol_list = [{"name": "BAYES_SPAM", "score": 5.1}, {"name": "RDNS_NONE", "score": 2.0},
                   {"name": "SOME_UNKNOWN_RULE", "score": 1.0}, {"name": "R_DKIM_NA", "score": 0}]
    if virus:
        symbol_list.append({"name": "CLAM_VIRUS", "score": 0})
    item = QuarantineItem(rcpt=rcpt, domain=rcpt.split("@")[1], subject="Offer", sender=sender,
                          symbols=json.dumps(symbol_list), message=b"Subject: Offer\r\n\r\nbody\r\n",
                          created_at=utcnow(), direction=direction, score=8.1)
    db.session.add(item)
    db.session.commit()
    return item


def _entries(**filters):
    return [(e.list_type, e.value) for e in ListEntry.query.filter_by(**filters).all()]


# ---------------------------------------------------------------------------
# Release & allow / block sender
# ---------------------------------------------------------------------------

def test_admin_scopes_shown(logged_in, domain):
    item = _item()
    page = logged_in.get(f"/quarantine/{item.id}").get_data(as_text=True)
    assert "Release &amp; allow sender" in page and 'value="mailbox"' not in page  # no mailbox user
    assert 'value="domain"' in page and 'value="global"' in page
    create_mailbox_user("alice@example.com", "alice-password")
    db.session.commit()
    assert 'value="mailbox"' in logged_in.get(f"/quarantine/{item.id}").get_data(as_text=True)
    bounce = _item(sender="")
    assert "Release &amp; allow sender" not in logged_in.get(f"/quarantine/{bounce.id}").get_data(as_text=True)


def test_admin_release_and_allow(logged_in, domain, outbox, config):
    user = create_mailbox_user("alice@example.com", "alice-password")
    db.session.commit()
    item = _item(rcpt="alice+shop@example.com")
    response = logged_in.post(f"/quarantine/{item.id}/action", data={"action": "release_allow", "scope": "mailbox"},
                              follow_redirects=True)
    text = response.get_data(as_text=True)
    assert "news@shop.example added to the allow list of alice@example.com" in text
    assert len(outbox) == 1 and db.session.get(QuarantineItem, item.id) is None  # released: removed
    assert [(e.list_type, e.value) for e in user.list_entries] == [("allow", "news@shop.example")]
    # another message of the sender: already listed, still released
    again = _item(rcpt="alice+shop@example.com")
    response = logged_in.post(f"/quarantine/{again.id}/action", data={"action": "release_allow", "scope": "mailbox"},
                              follow_redirects=True)
    assert "already is on the allow list" in response.get_data(as_text=True) and len(outbox) == 2
    other = _item()
    logged_in.post(f"/quarantine/{other.id}/action", data={"action": "release_allow", "scope": "global"})
    assert ("allow", "news@shop.example") in _entries(domain_id=None, mailbox_user_id=None)
    with open(f"{config['RSPAMD_MAP_DIR']}/global_smtp_from_whitelist.map") as handle:
        assert "shop" in handle.read()  # the maps were written


def test_admin_block_and_delete(logged_in, domain, outbox):
    item = _item()
    response = logged_in.post(f"/quarantine/{item.id}/action", data={"action": "block_delete", "scope": "domain"},
                              follow_redirects=True)
    assert "added to the block list of example.com" in response.get_data(as_text=True)
    assert db.session.get(QuarantineItem, item.id) is None and outbox == []
    assert _entries(domain_id=domain.id) == [("block", "news@shop.example")]


def test_virus_needs_confirmation(logged_in, domain, outbox):
    item = _item(virus=True)
    response = logged_in.post(f"/quarantine/{item.id}/action", data={"action": "release_allow", "scope": "domain"},
                              follow_redirects=True)
    assert "Confirm the release" in response.get_data(as_text=True) and outbox == [] and _entries() == []
    logged_in.post(f"/quarantine/{item.id}/action", data={"action": "release_allow", "scope": "domain",
                                                          "confirm_virus": "yes"})
    assert len(outbox) == 1


def test_release_failure_keeps_no_entry(logged_in, domain, monkeypatch):
    def broken(*args):
        raise mailer.ReleaseError("Postfix is down")
    monkeypatch.setattr(mailer, "reinject", broken)
    item = _item()
    response = logged_in.post(f"/quarantine/{item.id}/action", data={"action": "release_allow", "scope": "domain"},
                              follow_redirects=True)
    assert "Postfix is down" in response.get_data(as_text=True) and _entries() == []


def test_domain_admin_cannot_list_globally(app, client, make_admin, domain, outbox):
    admin = make_admin("dom", password="dom-password-1")
    admin.role = "domain"
    admin.domains = [domain]
    db.session.commit()
    client.post("/login", data={"username": "dom", "password": "dom-password-1"})
    item = _item()
    assert 'value="global"' not in client.get(f"/quarantine/{item.id}").get_data(as_text=True)
    client.post(f"/quarantine/{item.id}/action", data={"action": "release_allow", "scope": "global"})
    assert _entries() == [] and outbox == []


def test_portal_allow_and_block(client, domain, outbox):
    create_mailbox_user("alice@example.com", "alice-password")
    db.session.commit()
    client.post("/login", data={"username": "alice@example.com", "password": "alice-password"})
    item = _item()
    page = client.get(f"/my/{item.id}").get_data(as_text=True)
    assert "Release &amp; allow sender" in page and "Why it was held back" in page
    assert "The statistical filter, trained on your mail, considers it spam." in page
    response = client.post(f"/my/{item.id}/action", data={"action": "release_allow"}, follow_redirects=True)
    assert "delivered to your mailbox. news@shop.example added to the allow list" in response.get_data(as_text=True)
    assert len(outbox) == 1
    spam = _item(sender="bad@spam.example")
    client.post(f"/my/{spam.id}/action", data={"action": "block_delete"})
    user = MailboxUser.query.one()
    assert sorted((e.list_type, e.value) for e in user.list_entries) == [("allow", "news@shop.example"),
                                                                           ("block", "bad@spam.example")]
    assert db.session.get(QuarantineItem, spam.id) is None
    virus = _item(virus=True)
    assert "Release &amp; allow sender" not in client.get(f"/my/{virus.id}").get_data(as_text=True)
    client.post(f"/my/{virus.id}/action", data={"action": "release_allow"})
    assert len(outbox) == 1


def test_digest_link_allow_needs_an_account(client, domain, outbox):
    item = _item()
    send_digest("alice@example.com", [item], [item])
    token = re.search(rb"/q/([A-Za-z0-9_-]{20,})", outbox[0][2]).group(1).decode()
    assert "Release &amp; allow sender" not in client.get(f"/q/{token}/{item.id}").get_data(as_text=True)
    create_mailbox_user("alice@example.com", "alice-password")
    db.session.commit()
    assert "Release &amp; allow sender" in client.get(f"/q/{token}/{item.id}").get_data(as_text=True)
    client.post(f"/q/{token}/{item.id}/action", data={"action": "block_delete"})
    assert [(e.list_type, e.value) for e in MailboxUser.query.one().list_entries] == [("block", "news@shop.example")]


def test_api_allow_and_block(api, domain, outbox):
    item = _item()
    body = api("POST", f"/quarantine/{item.id}/release", json={"allow_sender": "domain"}).get_json()
    assert body["id"] == item.id and "news@shop.example added to the allow list of example.com." in body["notes"]
    item = _item()
    assert api("POST", f"/quarantine/{item.id}/release", json={"allow_sender": "mailbox"}).status_code == 422
    assert api("POST", f"/quarantine/{item.id}/release", json={"allow_sender": "everyone"}).status_code == 422
    other = _item(sender="bad@spam.example")
    body = api("POST", f"/quarantine/{other.id}/block-sender", json={"scope": "global"}).get_json()
    assert body["notes"] == ["bad@spam.example added to the global block list."]
    assert db.session.get(QuarantineItem, other.id) is None
    kept = _item(sender="x@spam.example")
    api("POST", f"/quarantine/{kept.id}/block-sender", json={"scope": "global", "delete": False})
    assert db.session.get(QuarantineItem, kept.id) is not None
    outbound = _item(direction="outbound")
    assert api("POST", f"/quarantine/{outbound.id}/block-sender", json={"scope": "global"}).status_code == 422


# ---------------------------------------------------------------------------
# Forgot password
# ---------------------------------------------------------------------------

def test_forgot_password(client, domain, outbox):
    create_mailbox_user("alice@example.com", "alice-password")
    db.session.commit()
    assert "Forgot your password?" in client.get("/login").get_data(as_text=True)
    for address in ("Alice@example.com", "nobody@example.com"):
        response = client.post("/login/forgot", data={"email": address}, follow_redirects=True)
        assert f"If {address} has an account" in response.get_data(as_text=True)
    (sender, rcpt, message), = outbox
    assert rcpt == "alice@example.com" and b"Someone (hopefully you)" in message
    assert AccountToken.query.count() == 1
    user = MailboxUser.query.one()
    assert user.check_password("alice-password")  # still valid until a new one is set


def test_forgot_password_limits(client, domain, outbox):
    user = create_mailbox_user("alice@example.com", "alice-password")
    db.session.commit()
    for _ in range(5):
        client.post("/login/forgot", data={"email": "alice@example.com"})
    assert len(outbox) == 3  # per address and hour
    user.active = False
    db.session.commit()
    for i in range(12):
        client.post("/login/forgot", data={"email": f"user{i}@example.com"})
    assert len(outbox) == 3


# ---------------------------------------------------------------------------
# Destination test
# ---------------------------------------------------------------------------

@pytest.fixture
def smtp():
    servers = []

    def start(known, accept_all=False):
        server = FakeSmtp(known, accept_all)
        servers.append(server)
        return server
    yield start
    for server in servers:
        server.close()


def test_destination_test_page(logged_in, domain, smtp):
    server = smtp(["alice@example.com"])
    domain.destination_port = server.port
    db.session.commit()
    page = logged_in.get(f"/domains/{domain.id}").get_data(as_text=True)
    assert "Test destination" in page
    page = logged_in.post(f"/domains/{domain.id}/test-destination",
                          data={"address": "alice@example.com"}).get_data(as_text=True)
    assert f"127.0.0.1:{server.port}" in page and "reachable" in page
    assert "STARTTLS is not offered" in page
    assert 'alice@example.com: <span class="badge good">accepted</span>' in page
    assert "– the server knows its mailboxes" in page
    response = logged_in.post(f"/domains/{domain.id}/test-destination", data={"address": "bob@other.org"},
                              follow_redirects=True)
    assert "must be an address of example.com" in response.get_data(as_text=True)


def test_destination_test_api(api, domain, smtp):
    server = smtp([], accept_all=True)
    domain.destination_port = server.port
    db.session.commit()
    result, = api("POST", f"/domains/{domain.id}/test-destination", json={"address": "x@example.com"}
                  ).get_json()["results"]
    assert result["ok"] and result["address"] == "accepted" and result["accepts_any"] is True
    assert [s["command"] for s in result["steps"]][:3] == ["connect", "EHLO", "MAIL FROM:<>"]
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    domain.destination_port = closed.getsockname()[1]
    closed.close()
    db.session.commit()
    result, = api("POST", f"/domains/{domain.id}/test-destination").get_json()["results"]
    assert not result["ok"] and result["error"]
    assert api("POST", f"/domains/{domain.id}/test-destination", json={"address": "a@b.c"}).status_code == 422


# ---------------------------------------------------------------------------
# Problems in the sidebar
# ---------------------------------------------------------------------------

def test_problem_badge(logged_in, app):
    assert "problem-dot" not in logged_in.get("/settings/").get_data(as_text=True)
    results = {"queue": {"ok": False, "message": "120 deferred messages"}, "database": {"ok": True, "message": ""}}
    monitoring.run_alerts(results)  # no alert recipients: recorded all the same
    page = logged_in.get("/settings/").get_data(as_text=True)
    assert re.search(r'class="problem-dot"\s+title="1 problem\(s\): [^"]+"', page)
    monitoring.record_problems({"queue": {"ok": True, "message": ""}})
    assert "problem-dot" not in logged_in.get("/settings/").get_data(as_text=True)


def test_no_badge_for_domain_admins(app, client, make_admin, domain):
    admin = make_admin("dom", password="dom-password-1")
    admin.role = "domain"
    admin.domains = [domain]
    db.session.commit()
    monitoring.record_problems({"queue": {"ok": False, "message": "x"}})
    client.post("/login", data={"username": "dom", "password": "dom-password-1"})
    assert "problem-dot" not in client.get("/quarantine/").get_data(as_text=True)


# ---------------------------------------------------------------------------
# Symbol explanations, settings layout
# ---------------------------------------------------------------------------

def test_explanations():
    assert symbols.explain("R_SPF_FAIL").startswith("SPF:")
    assert symbols.explain("RBL_NEW_LIST") == "The sending server is on a block list."
    assert symbols.explain("CLAMD_SOMETHING") and symbols.explain("NOT_A_SYMBOL") == ""


def test_admin_item_reasons(logged_in, domain):
    item = _item()
    page = logged_in.get(f"/quarantine/{item.id}").get_data(as_text=True)
    assert "Why it was held back" in page and "no reverse DNS name" in page
    assert "SOME_UNKNOWN_RULE +1.0" not in page  # only explained rules
    assert 'title="The statistical filter, trained on your mail, considers it spam."' in page


def test_settings_layout(logged_in):
    page = logged_in.get("/settings/").get_data(as_text=True)
    assert '<nav class="section-nav"' in page and 'href="#timezone"' in page
    assert "data-dirty-warn" in page and 'class="save-bar"' in page
    for anchor in ("thresholds", "limits", "quarantine", "scanning", "administrators", "timezone"):
        assert f'id="{anchor}"' in page
