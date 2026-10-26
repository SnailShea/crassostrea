"""Mailbox users and the inbound/outbound quarantine split."""
import io
import json

import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, MailboxUser, QuarantineItem, set_setting
from crassostrea.services import mailer

RAW = b"From: x@bad.example\r\nTo: alice@example.com\r\nSubject: Offer\r\n\r\nhello\r\n"


@pytest.fixture
def domain(app):
    d = Domain(name="example.com", destination_host="mx.internal")
    db.session.add(d)
    db.session.commit()
    return d


def _item(rcpt, direction="inbound", virus=False, subject="Offer"):
    symbols = [{"name": "CLAM_VIRUS", "score": 0}] if virus else [{"name": "BAYES_SPAM", "score": 5}]
    item = QuarantineItem(rcpt=rcpt, domain=rcpt.split("@")[1], direction=direction, subject=subject,
                          sender="x@bad.example", symbols=json.dumps(symbols), message=RAW)
    db.session.add(item)
    db.session.commit()
    return item


@pytest.fixture
def alice(domain):
    user = MailboxUser(email="alice@example.com", domain=domain)
    user.set_password("alice-password")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def alice_client(app, alice):
    client = app.test_client()
    response = client.post("/login", data={"username": "alice@example.com", "password": "alice-password"})
    assert response.status_code == 302
    assert response.headers["Location"] == "/my/"
    return client


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, msg: calls.append(rcpt))
    return calls


def test_admin_creates_mailbox_user(logged_in, domain):
    response = logged_in.post("/mailboxes/", data={"email": "Bob@Example.com", "password": "bob-password1",
                                                   "confirm": "bob-password1"})
    assert response.status_code == 302
    user = MailboxUser.query.one()
    assert user.email == "bob@example.com" and user.domain == domain

    response = logged_in.post("/mailboxes/", data={"email": "carol@unprotected.org", "password": "x" * 10,
                                                   "confirm": "x" * 10})
    assert b"not protected by the gateway" in response.data
    assert MailboxUser.query.count() == 1

    logged_in.post(f"/mailboxes/{user.id}/password", data={"pw-password": "new-password-1"})
    db.session.refresh(user)
    assert user.check_password("new-password-1")


def test_mailbox_user_cannot_reach_admin_area(alice_client):
    for path in ["/", "/domains/", "/quarantine/", "/settings/", "/mailboxes/", "/admins/", "/queue/"]:
        response = alice_client.get(path)
        assert response.status_code == 302, path
        assert response.headers["Location"] == "/my/"
    assert alice_client.post("/quarantine/bulk", data={"action": "delete", "ids": ["1"]}).status_code == 403
    assert alice_client.post("/domains/new", data={"name": "evil.com"}).status_code == 403
    assert alice_client.post("/mailboxes/", data={"email": "a@example.com"}).status_code == 403
    page = alice_client.get("/my/").data
    assert b"Mailbox users" not in page and b"Settings" not in page


def test_admin_is_sent_to_admin_quarantine(logged_in):
    response = logged_in.get("/my/")
    assert response.status_code == 302 and response.headers["Location"] == "/quarantine/"


def test_mailbox_user_sees_only_own_inbound_items(alice_client, domain):
    own = _item("alice@example.com", subject="Mine")
    other = _item("bob@example.com", subject="Bobs")
    outbound = _item("alice@example.com", direction="outbound", subject="Outgoing")
    page = alice_client.get("/my/").data
    assert b"Mine" in page and b"Bobs" not in page and b"Outgoing" not in page
    assert alice_client.get(f"/my/{own.id}").status_code == 200
    assert alice_client.get(f"/my/{other.id}").status_code == 404
    assert alice_client.get(f"/my/{outbound.id}").status_code == 404
    # bulk actions ignore foreign ids
    alice_client.post("/my/bulk", data={"action": "delete", "ids": [str(other.id), str(outbound.id)]})
    assert QuarantineItem.query.count() == 3


def test_mailbox_user_release_and_delete(alice_client, domain, sent):
    item = _item("alice@example.com")
    alice_client.post(f"/my/{item.id}/action", data={"action": "release"})
    assert sent == ["alice@example.com"]
    db.session.refresh(item)
    assert item.released_by == "alice@example.com"
    alice_client.post(f"/my/{item.id}/action", data={"action": "delete"})
    assert QuarantineItem.query.count() == 0


def test_mailbox_user_cannot_release_viruses_or_train(alice_client, domain, sent):
    virus = _item("alice@example.com", virus=True)
    response = alice_client.post(f"/my/{virus.id}/action", data={"action": "release"}, follow_redirects=True)
    assert b"only be released by an administrator" in response.data
    alice_client.post("/my/bulk", data={"action": "release", "ids": [str(virus.id)]})
    assert sent == []
    assert alice_client.post(f"/my/{virus.id}/action", data={"action": "learn_spam"}).status_code == 400
    assert alice_client.post("/training/", data={"kind": "spam", "message_text": "Subject: x\n\ny"}).status_code == 403


def test_disabled_mailbox_user_loses_session(alice_client, alice):
    alice.active = False
    db.session.commit()
    assert alice_client.get("/my/").status_code == 302
    assert "/login" in alice_client.get("/my/").headers["Location"]


def test_mailbox_user_changes_own_password(alice_client, alice):
    response = alice_client.post("/account", data={"current": "alice-password", "password": "better-password",
                                                   "confirm": "better-password"})
    assert response.status_code == 302
    db.session.refresh(alice)
    assert alice.check_password("better-password")


def test_session_ids_are_namespaced(app, alice):
    from crassostrea.auth import load_user
    from crassostrea.models import Admin
    admin = Admin.query.filter_by(username="admin").one()
    assert admin.get_id() == f"admin:{admin.id}" and alice.get_id() == f"user:{alice.id}"
    assert load_user(f"user:{alice.id}") == alice
    assert load_user(f"admin:{admin.id}") == admin
    assert load_user(str(admin.id)) is None  # ids without a prefix are rejected


def test_admin_usernames_cannot_look_like_addresses(logged_in):
    response = logged_in.post("/admins/", data={"username": "alice@example.com", "password": "x" * 12,
                                                "confirm": "x" * 12})
    assert b"Only letters, digits" in response.data


def _ingest(internal_app, rcpts, symbols, sender="clerk@example.com"):
    meta = {"qid": "Q1", "subject": "s", "from": sender, "rcpt": rcpts, "score": 20, "action": "reject",
            "symbols": symbols}
    return internal_app.test_client().post(
        "/internal/quarantine", data={"metadata": json.dumps(meta), "message": (io.BytesIO(RAW), "message")},
        environ_base={"REMOTE_ADDR": "172.22.1.5"})


def test_outbound_mail_is_quarantined_for_admins_only(internal_app, logged_in, domain):
    _ingest(internal_app, ["partner@external.net"], [{"name": "RELAY_NETWORK", "score": 0}])
    item = QuarantineItem.query.one()
    assert item.direction == "outbound"
    assert item.domain == "example.com"  # sender domain
    assert b"outbound" in logged_in.get("/quarantine/?direction=outbound").data
    assert b"partner@external.net" not in logged_in.get("/quarantine/?direction=inbound").data


def test_outbound_quarantine_can_be_disabled(internal_app, domain):
    set_setting("quarantine_outbound", 0)
    db.session.commit()
    _ingest(internal_app, ["partner@external.net"], {"RELAY_NETWORK": {"score": 0}})
    assert QuarantineItem.query.count() == 0


def test_outbound_setting_round_trip(logged_in):
    data = {"greylist_score": "7", "add_header_score": "8", "reject_score": "15",
            "quarantine_retention_days": "14", "quarantine_max_size_mb": "10",
            "digest_interval": "daily", "digest_token_days": "7", "mailbox_invite_days": "7", "ptr_check": "off"}
    logged_in.post("/settings/", data=data)  # checkbox absent -> off
    assert b'id="quarantine_outbound" name="quarantine_outbound" type="checkbox" value="y">' in \
        logged_in.get("/settings/").data
    logged_in.post("/settings/", data=dict(data, quarantine_outbound="y"))
    assert b'checked id="quarantine_outbound"' in logged_in.get("/settings/").data


def test_init_db_adds_listed_columns(app, monkeypatch):
    from crassostrea import cli
    monkeypatch.setattr(cli, "_MIGRATIONS", [("quarantine", "example_column", "INTEGER NULL")])
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert "added quarantine.example_column" in result.output
    assert "example_column" in {c["name"] for c in db.inspect(db.engine).get_columns("quarantine")}
    assert "example_column" not in app.test_cli_runner().invoke(args=["init-db"]).output  # once

