"""Delivery results in the mail log: Postfix's delivery attempts, the notices
it sends the sender and expired messages, from its log (system/libexec/logship)
to /internal/delivery (services/deliveries.py)."""
import importlib.machinery
import importlib.util
import json
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from crassostrea.extensions import db
from crassostrea.models import DeliveryBucket, Domain, MailDelivery, MailLogEntry, set_setting, utcnow
from crassostrea.services import deliveries, maillog

REPO = Path(__file__).resolve().parents[3]
NOW = int(time.time())
RAW = b"From: a@sender.example\r\nTo: bob@example.com\r\nSubject: Report\r\n\r\nHello\r\n"


def _load_logship():
    loader = importlib.machinery.SourceFileLoader("logship", str(REPO / "system" / "libexec" / "logship"))
    spec = importlib.util.spec_from_loader("logship", loader)
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


logship = _load_logship()


def _line(message, identifier="postfix/relay/smtp", when=NOW):
    return {"MESSAGE": message, "SYSLOG_IDENTIFIER": identifier, "__REALTIME_TIMESTAMP": str(when * 1000000)}


@pytest.mark.parametrize("message, identifier, expected", [
    # as logged on the gateway
    ("45505A0702: to=<alma@eoltestdomain.com>, relay=mail.eoltestdomain.com[192.0.2.10]:25, delay=5.6, "
     "delays=0.01/0.02/4.4/1.2, dsn=2.0.0, status=sent (250 2.0.0 Ok: queued as C03C0A0176)", "postfix/relay/smtp",
     {"kind": "delivery", "qid": "45505A0702", "rcpt": "alma@eoltestdomain.com", "status": "sent", "dsn": "2.0.0",
      "relay": "mail.eoltestdomain.com[192.0.2.10]:25", "detail": "250 2.0.0 Ok: queued as C03C0A0176",
      "delay": 5.6}),
    # a reused connection
    ("45505A0702: to=<b@example.org>, relay=mx.example.org[198.51.100.2]:25, conn_use=2, delay=0.4, "
     "delays=0.1/0/0/0.3, dsn=2.0.0, status=sent (250 Ok)", "postfix/smtp",
     {"kind": "delivery", "qid": "45505A0702", "rcpt": "b@example.org", "status": "sent", "dsn": "2.0.0",
      "relay": "mx.example.org[198.51.100.2]:25", "detail": "250 Ok", "delay": 0.4}),
    # a long queue ID, orig_to, a refusal with nested parentheses
    ("4ZtX1m2bQqz9Pk3: to=<bob@example.org>, orig_to=<Bob@Example.org>, relay=mx.example.org[198.51.100.2]:25, "
     "delay=1.1, delays=0/0/0.5/0.6, dsn=5.1.1, status=bounced (host mx.example.org[198.51.100.2] said: 550 5.1.1 "
     "<bob@example.org>: User unknown (in reply to RCPT TO command))", "postfix/smtp",
     {"kind": "delivery", "qid": "4ZtX1m2bQqz9Pk3", "rcpt": "bob@example.org", "status": "bounced", "dsn": "5.1.1",
      "relay": "mx.example.org[198.51.100.2]:25",
      "detail": "host mx.example.org[198.51.100.2] said: 550 5.1.1 <bob@example.org>: User unknown (in reply to "
                "RCPT TO command)", "delay": 1.1}),
    ("4ZtX1m2bQqz9Pk3: to=<c@example.org>, relay=none, delay=30, delays=0/0/30/0, dsn=4.4.1, status=deferred "
     "(connect to mx.example.org[198.51.100.2]:25: Connection timed out)", "postfix/smtp",
     {"kind": "delivery", "qid": "4ZtX1m2bQqz9Pk3", "rcpt": "c@example.org", "status": "deferred", "dsn": "4.4.1",
      "relay": "none", "detail": "connect to mx.example.org[198.51.100.2]:25: Connection timed out",
      "delay": 30.0}),
    ("4ZtX1m2bQqz9Pk3: sender non-delivery notification: 4ZtX1n7cRrz2Lm8", "postfix/bounce",
     {"kind": "bounce_notice", "qid": "4ZtX1m2bQqz9Pk3", "notice_qid": "4ZtX1n7cRrz2Lm8"}),
    ("4ZtX1m2bQqz9Pk3: sender delay notification: 4ZtX1p0dSsz4Nn1", "postfix/bounce",
     {"kind": "delay_notice", "qid": "4ZtX1m2bQqz9Pk3", "notice_qid": "4ZtX1p0dSsz4Nn1"}),
    ("4ZtX1m2bQqz9Pk3: from=<a@sender.example>, status=expired, returned to sender", "postfix/qmgr",
     {"kind": "expired", "qid": "4ZtX1m2bQqz9Pk3"}),
])
def test_logship_recognises(message, identifier, expected):
    assert logship.delivery(_line(message, identifier)) == {"time": NOW, **expected}


@pytest.mark.parametrize("message, identifier", [
    # address verification probes
    ("4ZtX1m2bQqz9Pk3: to=<x@example.com>, relay=mx[10.0.0.5]:25, delay=0.2, delays=0/0/0.1/0.1, dsn=2.1.5, "
     "status=deliverable (250 2.1.5 Ok)", "postfix/smtp"),
    ("45505A0702: removed", "postfix/qmgr"),
    ("45505A0702: to=<x@example.com>, relay=mx, delay=1, dsn=2.0.0, status=sent (250 Ok)", "dovecot"),
])
def test_logship_ignores(message, identifier):
    assert logship.delivery(_line(message, identifier)) is None


def _at(seconds_ago=0):
    return datetime.fromtimestamp(NOW - seconds_ago, timezone.utc).replace(tzinfo=None)


def _entry(qid="4ZtX1m2bQqz9Pk3", rcpts="bob@example.org,c@example.org", created=None, **fields):
    entry = MailLogEntry(qid=qid, sender="a@sender.example", rcpts=rcpts, subject="Report", action="no action",
                         ip="203.0.113.50", symbols="[]", size=len(RAW), message=RAW,
                         created_at=created or _at(60), **fields)
    db.session.add(entry)
    db.session.commit()
    return entry


def _event(**fields):
    event = {"time": NOW, "kind": "delivery", "qid": "4ZtX1m2bQqz9Pk3", "rcpt": "bob@example.org",
             "status": "sent", "dsn": "2.0.0", "relay": "mx.example.org[198.51.100.2]:25", "detail": "250 Ok"}
    event.update(fields)
    return event


def test_record_keeps_the_latest_attempt(app):
    deliveries.record(_event(status="deferred", dsn="4.4.1", detail="timed out", time=NOW - 600))
    deliveries.record(_event(time=NOW))
    deliveries.record(_event(status="deferred", dsn="4.4.1", detail="old news", time=NOW - 300))  # out of order
    db.session.commit()
    row = MailDelivery.query.one()
    assert (row.status, row.detail, row.attempts) == ("sent", "250 Ok", 3)
    assert row.first_at == _at(600) and row.last_at == _at(0)


@pytest.mark.parametrize("changes", [
    {"qid": "x"}, {"kind": "other"}, {"status": "deliverable"}, {"dsn": "250"}, {"rcpt": ""},
    {"rcpt": "a b@example.org"}, {"time": NOW + 3600}, {"time": NOW - 60 * 86400},
    {"kind": "bounce_notice", "notice_qid": ""},
])
def test_record_refuses_invalid_events(app, changes):
    assert deliveries.record(_event(**changes)) is None


def test_summary_and_states(app):
    entry = _entry()
    assert deliveries.summary(entry)["state"] is None and deliveries.states([entry])[entry.id] == (None, False)
    deliveries.record(_event())
    deliveries.record(_event(rcpt="c@example.org", status="deferred", dsn="4.4.1"))
    db.session.commit()
    assert deliveries.summary(entry)["state"] == "deferred"
    deliveries.record(_event(rcpt="c@example.org", status="bounced", dsn="5.1.1", detail="550 User unknown"))
    deliveries.record({"time": NOW, "kind": "bounce_notice", "qid": entry.qid, "notice_qid": "4ZtX1n7cRrz2Lm8"})
    deliveries.record(_event(qid="4ZtX1n7cRrz2Lm8", rcpt="a@sender.example"))  # the notice arrived
    db.session.commit()
    summary = deliveries.summary(entry)
    assert summary["state"] == "bounced" and [d.rcpt for d in summary["deliveries"]] == ["bob@example.org",
                                                                                         "c@example.org"]
    notice, = summary["notices"]
    assert notice["label"].startswith("Non-delivery") and notice["state"] == "delivered"
    assert deliveries.states([entry])[entry.id] == ("bounced", True)
    body = deliveries.as_json(summary)
    assert body["state"] == "bounced" and body["notices"][0]["queue_id"] == "4ZtX1n7cRrz2Lm8"


def test_expired_counts_as_bounced(app):
    entry = _entry(rcpts="bob@example.org")
    deliveries.record(_event(status="deferred", dsn="4.4.1"))
    deliveries.record({"time": NOW, "kind": "expired", "qid": entry.qid})
    db.session.commit()
    summary = deliveries.summary(entry)
    assert summary["state"] == "bounced" and summary["expired"] is not None


def test_a_reused_short_queue_id_does_not_match(app):
    old = _entry(qid="45505A0702", rcpts="bob@example.org", created=_at(20 * 86400))
    deliveries.record(_event(qid="45505A0702"))  # today, for another message with the same short ID
    db.session.commit()
    assert deliveries.summary(old)["state"] is None


def test_filter(app):
    delivered = _entry(qid="AAAAAA1111", rcpts="bob@example.org")
    deferred = _entry(qid="BBBBBB2222", rcpts="bob@example.org")
    bounced = _entry(qid="CCCCCC3333", rcpts="bob@example.org,c@example.org")
    _entry(qid="DDDDDD4444", rcpts="bob@example.org")  # nothing yet
    deliveries.record(_event(qid="AAAAAA1111"))
    deliveries.record(_event(qid="BBBBBB2222", status="deferred", dsn="4.4.1"))
    deliveries.record(_event(qid="CCCCCC3333"))
    deliveries.record(_event(qid="CCCCCC3333", rcpt="c@example.org", status="bounced", dsn="5.1.1"))
    db.session.commit()
    for state, expected in (("delivered", [delivered.id]), ("deferred", [deferred.id]), ("bounced", [bounced.id])):
        assert [e.id for e in maillog.filtered(delivery=state)] == expected
    assert maillog.filtered(delivery="nonsense").count() == 4


def _counted():
    return {(b.domain, b.direction): (b.deliveries, b.delay) for b in DeliveryBucket.query}


def test_sent_recipients_are_counted_once(app):
    db.session.add(Domain(name="example.org", destination_host="mx.internal"))
    _entry(qid="AAAAAA1111", rcpts="bob@example.org,c@example.org")
    _entry(qid="BBBBBB2222", rcpts="x@partner.example", direction="outbound", created=_at(120))
    deliveries.record(_event(qid="AAAAAA1111", status="deferred", dsn="4.4.1", delay=30, time=NOW - 60))
    deliveries.record(_event(qid="AAAAAA1111", delay=90))
    deliveries.record(_event(qid="AAAAAA1111", delay=90))  # the same line again
    deliveries.record(_event(qid="AAAAAA1111", status="deferred", dsn="4.4.1", delay=30, time=NOW - 30))  # late
    deliveries.record(_event(qid="AAAAAA1111", rcpt="c@example.org", delay=10.5))
    deliveries.record(_event(qid="BBBBBB2222", rcpt="x@partner.example", delay=4))
    deliveries.record(_event(qid="CCCCCC3333", delay=1.0))  # not in the mail log
    deliveries.record(_event(qid="DDDDDD4444", rcpt="c@example.org"))  # no delay
    db.session.commit()
    # inbound per recipient domain, outbound per sender domain (stats._domain)
    assert _counted() == {("example.org", "inbound"): (2, 100.5), ("sender.example", "outbound"): (1, 4.0)}


@pytest.mark.parametrize("delay, counted", [(5.6, 5.6), (0, 0.0), ("5", None), (True, None), (-1, None),
                                            (10 ** 9, None)])
def test_only_a_plausible_delay_counts(app, delay, counted):
    _entry()
    deliveries.record(_event(delay=delay))
    db.session.commit()
    assert [b.delay for b in DeliveryBucket.query] == ([] if counted is None else [counted])


def test_internal_api(internal_app):
    client = internal_app.test_client()
    response = client.post("/internal/delivery", json=_event(), environ_base={"REMOTE_ADDR": "127.0.0.1"})
    assert response.get_data(as_text=True) == "stored" and MailDelivery.query.count() == 1
    assert client.post("/internal/delivery", json=_event(qid="x"),
                       environ_base={"REMOTE_ADDR": "127.0.0.1"}).get_data(as_text=True) == "skipped"
    assert client.post("/internal/delivery", json=_event(), environ_base={"REMOTE_ADDR": "8.8.8.8"}).status_code == 403


def test_pages(logged_in):
    entry = _entry()
    deliveries.record(_event())
    deliveries.record(_event(rcpt="c@example.org", status="bounced", dsn="5.1.1", detail="550 5.1.1 User unknown"))
    deliveries.record({"time": NOW, "kind": "bounce_notice", "qid": entry.qid, "notice_qid": "4ZtX1n7cRrz2Lm8"})
    db.session.commit()
    listing = logged_in.get("/mail-log/").get_data(as_text=True)
    assert ">bounced</span>" in listing and ">bounce sent</span>" in listing
    assert "Report" in logged_in.get("/mail-log/?delivery=bounced").get_data(as_text=True)
    assert "Report" not in logged_in.get("/mail-log/?delivery=delivered").get_data(as_text=True)
    page = logged_in.get(f"/mail-log/{entry.id}").get_data(as_text=True)
    assert 'id="delivery"' in page and "550 5.1.1 User unknown" in page
    assert "Non-delivery notice (bounce) sent to" in page and "4ZtX1n7cRrz2Lm8" in page


def test_api(api):
    entry = _entry()
    deliveries.record(_event())
    deliveries.record(_event(rcpt="c@example.org"))
    db.session.commit()
    items = api("GET", "/mail-log?delivery=delivered").get_json()["items"]
    assert [i["delivery"] for i in items] == ["delivered"]
    body = api("GET", f"/mail-log/{entry.id}").get_json()
    assert body["deliveries"]["state"] == "delivered" and len(body["deliveries"]["deliveries"]) == 2
    assert api("GET", "/mail-log?delivery=lost").status_code == 400


def test_cleanup(app):
    set_setting("maillog_retention_days", 7)
    deliveries.record(_event(time=NOW - 10 * 86400))
    deliveries.record(_event(qid="AAAAAA1111"))
    db.session.commit()
    maillog.cleanup()
    db.session.commit()
    assert [r.qid for r in MailDelivery.query] == ["AAAAAA1111"]
    assert utcnow() - timedelta(days=1) < MailDelivery.query.one().last_at
    assert json.dumps(deliveries.as_json(deliveries.summary(_entry(qid="")))) is not None
