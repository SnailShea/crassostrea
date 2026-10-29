"""REST API: quarantine, mail queue, bans, training."""
import json
import time

import pytest

from crassostrea.api import operations
from crassostrea.extensions import db
from crassostrea.models import QuarantineItem
from crassostrea.services import mailer, postfix_control
from crassostrea.services import quarantine as quarantine_service

RAW = (b"From: Spammer <spam@bad.example>\r\nTo: alice@example.com\r\nSubject: Cheap pills\r\n"
       b"\r\nBuy now <b>!</b>\r\n")


def _item(**overrides):
    values = {"rcpt": "alice@example.com", "domain": "example.com", "sender": "spam@bad.example",
              "subject": "Cheap pills", "score": 18.5, "message": RAW, "size": len(RAW),
              "symbols": json.dumps([{"name": "BAYES_SPAM", "score": 5.1}])}
    values.update(overrides)
    item = QuarantineItem(**values)
    db.session.add(item)
    db.session.commit()
    return item


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, msg: calls.append((sender, rcpt, msg)))
    return calls


@pytest.fixture
def learned(monkeypatch):
    calls = []

    def fake_train(message, spam):
        calls.append(spam)
        return ["learned as spam" if spam else "learned as ham"]
    monkeypatch.setattr(quarantine_service, "train", fake_train)
    monkeypatch.setattr(operations, "train", fake_train)
    return calls


# --- quarantine -------------------------------------------------------------

def test_quarantine_list_and_get(api, app):
    item = _item()
    _item(rcpt="bob@other.org", domain="other.org", direction="outbound")
    listed = api("GET", "/quarantine?domain=example.com").get_json()
    assert listed["total"] == 1 and listed["items"][0]["subject"] == "Cheap pills"
    assert listed["items"][0]["virus"] is False and "message" not in listed["items"][0]
    assert api("GET", "/quarantine?direction=outbound").get_json()["total"] == 1
    assert api("GET", "/quarantine?q=pills").get_json()["total"] == 2

    detail = api("GET", f"/quarantine/{item.id}").get_json()
    assert detail["symbols"][0]["name"] == "BAYES_SPAM"
    assert detail["message"]["body"].startswith("Buy now <b>!</b>")
    raw = api("GET", f"/quarantine/{item.id}/raw")
    assert raw.data == RAW and raw.mimetype == "message/rfc822"
    assert api("GET", "/quarantine/9999").status_code == 404


def test_quarantine_release(api, app, sent, learned):
    item = _item()
    item_id = item.id
    response = api("POST", f"/quarantine/{item_id}/release", json={"learn_ham": True})
    assert response.status_code == 200
    body = response.get_json()
    # the message as it was, and gone from the quarantine
    assert body["id"] == item_id and body["subject"] == "Cheap pills" and "learned as ham" in body["notes"]
    assert "released_at" not in body
    assert sent[0][1] == "alice@example.com" and b"X-Quarantine-Released" in sent[0][2] and b"by api:test" in sent[0][2]
    assert learned == [False]
    assert api("GET", f"/quarantine/{item_id}").status_code == 404
    assert api("POST", f"/quarantine/{item_id}/release").status_code == 404
    # without a body
    assert api("POST", f"/quarantine/{_item().id}/release").status_code == 200


def test_quarantine_virus_needs_confirmation(api, app, sent):
    item = _item(symbols=json.dumps([{"name": "CLAM_VIRUS", "score": 20}]))
    refused = api("POST", f"/quarantine/{item.id}/release", json={})
    assert refused.status_code == 409 and refused.get_json()["field"] == "allow_virus"
    assert not sent
    assert api("POST", f"/quarantine/{item.id}/release", json={"allow_virus": "yes"}).status_code == 422
    assert api("POST", f"/quarantine/{item.id}/release", json={"allow_virus": True}).status_code == 200


def test_quarantine_release_failure(api, app, monkeypatch):
    item = _item()

    def refuse(sender, rcpt, msg):
        raise mailer.ReleaseError("Postfix did not accept the message")
    monkeypatch.setattr(mailer, "reinject", refuse)
    response = api("POST", f"/quarantine/{item.id}/release")
    assert response.status_code == 503 and "Postfix" in response.get_json()["error"]
    db.session.expire_all()
    assert db.session.get(QuarantineItem, item.id) is not None  # kept for another try


def test_quarantine_learn_and_delete(api, app, learned):
    item, other = _item(), _item()
    assert api("POST", f"/quarantine/{item.id}/learn-spam").get_json() == {"notes": ["learned as spam"]}
    assert learned == [True]
    assert api("DELETE", f"/quarantine/{other.id}").status_code == 204
    assert QuarantineItem.query.count() == 0


# --- mail queue -------------------------------------------------------------

QUEUE = [{"queue_name": "deferred", "queue_id": "4F3A2B1C", "arrival_time": 100, "sender": "a@example.com",
          "recipients": [{"address": "b@example.net", "delay_reason": "connection timed out"}]},
         {"queue_name": "active", "queue_id": "5A5A5A5A", "arrival_time": 200, "sender": "", "recipients": []}]


def test_queue(api, monkeypatch):
    calls = []
    monkeypatch.setattr(postfix_control, "mail_queue", lambda: [dict(q) for q in QUEUE])
    monkeypatch.setattr(postfix_control, "queue_message", lambda qid: f"*** ENVELOPE RECORDS {qid} ***")
    monkeypatch.setattr(postfix_control, "queue_action", lambda task, ids=None: calls.append((task, ids)))

    listed = api("GET", "/queue").get_json()
    assert listed["total"] == 2 and listed["items"][0]["queue_id"] == "5A5A5A5A" and listed["node"]
    assert "4F3A2B1C" in api("GET", "/queue/4F3A2B1C").get_json()["content"]
    assert api("GET", "/queue/bad-id").status_code == 404

    assert api("POST", "/queue/actions", json={"action": "hold", "ids": ["4F3A2B1C"]}).status_code == 200
    assert api("POST", "/queue/actions", json={"action": "delete_all", "ids": ["4F3A2B1C"]}).status_code == 200
    assert api("POST", "/queue/actions", json={"action": "flush"}).status_code == 200
    assert calls == [("hold", ["4F3A2B1C"]), ("super_delete", []), ("flush", [])]
    assert api("POST", "/queue/actions", json={"action": "delete"}).get_json()["field"] == "ids"
    assert api("POST", "/queue/actions", json={"action": "delete", "ids": ["x; rm -rf /"]}).status_code == 422
    assert api("POST", "/queue/actions", json={"action": "super_delete"}).get_json()["field"] == "action"
    assert len(calls) == 3


def test_queue_unavailable(api, monkeypatch):
    def down():
        raise postfix_control.PostfixControlError("Postfix control service is not reachable")
    monkeypatch.setattr(postfix_control, "mail_queue", down)
    response = api("GET", "/queue")
    assert response.status_code == 503 and "not reachable" in response.get_json()["error"]


# --- bans -------------------------------------------------------------------

def test_bans(api, fake_redis):
    fake_redis.hset("F2B_ACTIVE_BANS", "203.0.113.0/24", int(time.time()) + 600)
    fake_redis.hset("F2B_PERM_BANS", "198.51.100.0/24", int(time.time()))
    bans = api("GET", "/bans").get_json()
    assert bans["total"] == 2 and {b["network"] for b in bans["items"]} == {"203.0.113.0/24", "198.51.100.0/24"}

    response = api("POST", "/bans/unban", json={"network": "203.0.113.0/24"})
    assert response.status_code == 202 and fake_redis.hget("F2B_QUEUE_UNBAN", "203.0.113.0/24") == "1"
    assert api("GET", "/bans").get_json()["items"][1]["unban_queued"] is True
    assert api("POST", "/bans/unban", json={"network": "198.51.100.0/24"}).status_code == 404  # permanent
    assert api("POST", "/bans/unban", json={"network": "192.0.2.0/24"}).status_code == 404
    assert api("POST", "/bans/unban", json={"network": "not-an-ip"}).status_code == 422


# --- training ---------------------------------------------------------------

def test_training(api, learned):
    response = api("POST", "/training/spam", data=RAW, headers={"Content-Type": "message/rfc822"})
    assert response.get_json() == {"notes": ["learned as spam"]}
    assert api("POST", "/training/ham", data=RAW).get_json() == {"notes": ["learned as ham"]}
    assert learned == [True, False]
    assert api("POST", "/training/spam", data=b"").status_code == 400
    assert api("POST", "/training/spam", data=b"just some text\nwithout headers").status_code == 422
    assert api("POST", "/training/eggs", data=RAW).status_code == 404
