"""Journaling: which mail is queued, the journal report (original kept byte
for byte), sending and keeping copies while the archive is away, the page
and the API."""
import email
import io
import json
from email import policy

import pytest

from crassostrea.extensions import db
from crassostrea.models import MailLogEntry, set_setting
from crassostrea.services import journal, mailer

RAW = (b"From: Alice <alice@sender.example>\r\nTo: bob@example.com\r\nSubject: Caf\xc3\xa9\r\n"
       b"Message-ID: <m1@sender.example>\r\n\r\nHello \xc3\xa9\r\n--=_journal_x\r\n")


@pytest.fixture
def sent(monkeypatch):
    mails = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, message: mails.append((sender, rcpt, message)))
    return mails


def post(internal_app, action="no action", symbols=None, rcpts=("bob@example.com", "secret-bcc@example.com")):
    meta = {"qid": "Q1", "from": "alice@sender.example", "rcpt": list(rcpts), "score": 2.5, "action": action,
            "ip": "203.0.113.5", "symbols": symbols or [{"name": "BAYES_HAM", "score": -1}]}
    return internal_app.test_client().post(
        "/internal/mail-log", environ_base={"REMOTE_ADDR": "172.22.1.5"},
        data={"metadata": json.dumps(meta), "message": (io.BytesIO(RAW), "message")})


def test_what_is_queued(internal_app, app, fake_redis):
    post(internal_app)
    assert fake_redis.llen(journal.QUEUE) == 0  # off
    set_setting("journal_address", "journal@archive.example")
    db.session.commit()
    post(internal_app)
    post(internal_app, action="reject")
    post(internal_app, symbols=[{"name": "RELAY_NETWORK", "score": 0}])
    ids = fake_redis.lrange(journal.QUEUE, 0, -1)
    entries = [db.session.get(MailLogEntry, int(i)) for i in ids]
    assert [(e.direction, e.action) for e in entries] == [("inbound", "no action"), ("outbound", "no action")]
    set_setting("journal_outbound", 0)
    set_setting("journal_rejected", 1)
    db.session.commit()
    post(internal_app, action="reject")
    post(internal_app, symbols=[{"name": "RELAY_NETWORK", "score": 0}])
    assert fake_redis.llen(journal.QUEUE) == 3


def test_envelope_report(app):
    set_setting("journal_address", "journal@archive.example")
    db.session.commit()
    entry = MailLogEntry(direction="inbound", qid="Q1", message_id="<m1@sender.example>",
                         sender="alice@sender.example", rcpts="bob@example.com,secret-bcc@example.com",
                         subject="Café", score=2.5, action="no action", ip="203.0.113.5", message=RAW)
    db.session.add(entry)
    db.session.commit()
    report = journal.build(entry)
    msg = email.message_from_bytes(report, policy=policy.default)
    assert msg["To"] == "journal@archive.example" and msg["Subject"] == "Journal: Café"
    assert msg["X-Crassostrea-Journal"] == "inbound" and msg.get_content_type() == "multipart/mixed"
    text, attached = msg.iter_parts()
    assert "Recipients: bob@example.com, secret-bcc@example.com" in text.get_content()
    assert attached.get_content_type() == "message/rfc822" and attached["Content-Transfer-Encoding"] == "8bit"
    # the original, byte for byte, and a boundary that does not occur in it
    assert RAW.rstrip(b"\r\n") in report
    assert journal.build(entry, "copy") == RAW


def test_forward(app, fake_redis, sent, monkeypatch):
    set_setting("journal_address", "journal@archive.example")
    db.session.commit()
    entry = MailLogEntry(direction="inbound", sender="a@x.example", rcpts="bob@example.com", action="no action",
                         message=RAW)
    db.session.add(entry)
    db.session.commit()
    fake_redis.rpush(journal.QUEUE, entry.id, 999999)
    calls = []
    journal.forward(stop=lambda: calls.append(1) or len(calls) > 3, idle=1)
    assert [(s, r) for s, r, _ in sent] == [(journal.sender(), "journal@archive.example")]
    assert journal.status()["queued"] == 0 and journal.status()["sent"] == 1

    def broken(*args):
        raise mailer.ReleaseError("Connection refused")
    monkeypatch.setattr(mailer, "reinject", broken)
    monkeypatch.setattr(journal.time, "sleep", lambda s: None)
    fake_redis.rpush(journal.QUEUE, entry.id)
    calls.clear()
    journal.forward(stop=lambda: calls.append(1) or len(calls) > 1, idle=1)
    state = journal.status()
    assert state["queued"] == 1 and state["error"] == "Connection refused"


def test_page_and_api(app, logged_in, api, fake_redis, sent):
    page = logged_in.get("/journal/").get_data(as_text=True)
    assert "Journaling" in page and 'href="/journal/" class="active"' in page
    response = logged_in.post("/journal/", data={"journal_address": "Journal@Archive.example", "journal_inbound": "y",
                                                 "journal_format": "envelope"}, follow_redirects=True)
    assert "Journaling saved" in response.get_data(as_text=True)
    body = api("GET", "/settings").get_json()
    assert (body["journal_address"], body["journal_inbound"], body["journal_outbound"]) == (
        "journal@archive.example", True, False)
    response = logged_in.post("/journal/test", follow_redirects=True)
    assert "A test journal report was sent" in response.get_data(as_text=True)
    assert sent[0][1] == "journal@archive.example" and b"message/rfc822" in sent[0][2]
    assert logged_in.post("/journal/", data={"journal_address": "not an address",
                                            "journal_format": "copy"}).status_code == 400
    assert api("GET", "/journal/status").get_json()["queued"] == 0
    assert api("PATCH", "/settings", json={"journal_format": "pdf"}).status_code == 422
