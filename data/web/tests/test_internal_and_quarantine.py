import io
import json
from datetime import timedelta
from email.utils import formatdate

import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, QuarantineItem, get_setting, utcnow
from crassostrea.services import mailer
from crassostrea.services import quarantine as quarantine_service

RAW = (b"From: Spammer <spam@bad.example>\r\nTo: alice@example.com\r\nSubject: Cheap pills\r\n"
       b"Message-ID: <1@bad.example>\r\n\r\nBuy now <b>!</b>\r\n")


@pytest.fixture
def domains(app):
    db.session.add_all([
        Domain(name="example.com", destination_host="mx.internal"),
        Domain(name="noquarantine.org", destination_host="mx.internal", quarantine_enabled=False),
    ])
    db.session.commit()


def _ingest(internal_app, rcpts, raw=RAW, symbols=None, remote="172.22.1.5"):
    meta = {"qid": "ABC123", "subject": "Cheap pills", "from": "spam@bad.example", "rcpt": rcpts,
            "score": 21.5, "action": "reject", "ip": "203.0.113.50",
            "symbols": symbols or [{"name": "BAYES_SPAM", "score": 5.1, "options": ["99%"]}]}
    return internal_app.test_client().post(
        "/internal/quarantine",
        data={"metadata": json.dumps(meta), "message": (io.BytesIO(raw), "message")},
        environ_base={"REMOTE_ADDR": remote})


def test_ingest_only_for_quarantine_enabled_domains(internal_app, domains):
    response = _ingest(internal_app, ["Alice@Example.com", "bob@noquarantine.org", "x@unknown.net"])
    assert response.status_code == 200
    items = QuarantineItem.query.all()
    assert [i.rcpt for i in items] == ["alice@example.com"]
    item = items[0]
    assert item.domain == "example.com" and item.score == 21.5 and item.message == RAW
    assert item.symbol_list[0]["name"] == "BAYES_SPAM"


def test_ingest_respects_size_limit(internal_app, domains):
    big = RAW + b"x" * (get_setting("quarantine_max_size_mb") * 1024 * 1024)
    assert _ingest(internal_app, ["alice@example.com"], raw=big).status_code == 200
    assert QuarantineItem.query.count() == 0


def test_internal_api_rejects_public_clients(internal_app, domains):
    assert _ingest(internal_app, ["alice@example.com"], remote="8.8.8.8").status_code == 403
    response = internal_app.test_client().get("/internal/rspamd/settings", environ_base={"REMOTE_ADDR": "8.8.8.8"})
    assert response.status_code == 403


def test_internal_api_rejects_other_hosts(internal_app, domains):
    # private addresses are not trusted unless listed in INTERNAL_CLIENTS
    assert _ingest(internal_app, ["alice@example.com"], remote="172.22.1.77").status_code == 403
    assert QuarantineItem.query.count() == 0


def test_internal_clients_are_resolved_again_on_a_miss(internal_app, domains, monkeypatch):
    from crassostrea import internal
    answers = {"rspamd": "172.22.1.30"}
    lookups = []

    def getaddrinfo(host, *args, **kwargs):
        lookups.append(host)
        return [(None, None, None, "", (answers[host], 0))]

    monkeypatch.setattr(internal.socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(internal, "_RESOLVE_INTERVAL", 0)
    internal_app.config["INTERNAL_CLIENTS"] = ["rspamd"]
    assert _ingest(internal_app, ["alice@example.com"], remote="172.22.1.30").status_code == 200
    answers["rspamd"] = "172.22.1.31"  # restarted with a new address
    assert _ingest(internal_app, ["alice@example.com"], remote="172.22.1.31").status_code == 200
    assert _ingest(internal_app, ["alice@example.com"], remote="172.22.1.30").status_code == 403
    assert lookups == ["rspamd"] * 3


def test_internal_api_not_exposed_on_ui(client):
    assert client.get("/internal/rspamd/settings").status_code == 404


def test_settings_map_conditional_get(internal_app, app):
    c = internal_app.test_client()
    first = c.get("/internal/rspamd/settings", environ_base={"REMOTE_ADDR": "172.22.1.9"})
    assert first.status_code == 200
    assert b"settings {" in first.data
    modified = first.headers.get("Last-Modified")
    assert modified
    again = c.get("/internal/rspamd/settings", headers={"If-Modified-Since": modified},
                  environ_base={"REMOTE_ADDR": "172.22.1.9"})
    assert again.status_code == 304
    old = c.get("/internal/rspamd/settings", headers={"If-Modified-Since": formatdate(0, usegmt=True)},
                environ_base={"REMOTE_ADDR": "172.22.1.9"})
    assert old.status_code == 200


@pytest.fixture
def item(internal_app, domains):
    _ingest(internal_app, ["alice@example.com"])
    return QuarantineItem.query.one()


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
        return ["learned"]
    monkeypatch.setattr(quarantine_service, "train", fake_train)
    return calls


def test_list_and_show(logged_in, item):
    assert b"Cheap pills" in logged_in.get("/quarantine/").data
    page = logged_in.get(f"/quarantine/{item.id}").data
    assert b"BAYES_SPAM" in page
    # HTML is never rendered
    assert b"Buy now &lt;b&gt;!&lt;/b&gt;" in page
    raw = logged_in.get(f"/quarantine/{item.id}/raw")
    assert raw.data == RAW and raw.mimetype == "message/rfc822"


def test_release(logged_in, item, sent, learned):
    item_id = item.id
    response = logged_in.post(f"/quarantine/{item_id}/action", data={"action": "release_ham"})
    assert response.status_code == 302 and response.headers["Location"].endswith("/quarantine/")
    (sender, rcpt, message), = sent
    assert (sender, rcpt) == ("spam@bad.example", "alice@example.com")
    # release header prepended, original message unchanged after it
    first_line, rest = message.split(b"\r\n", 1)
    assert first_line.startswith(b"X-Quarantine-Released: ") and b"by admin" in first_line
    assert rest == RAW
    assert learned == [False]
    # delivered: no longer in the quarantine
    db.session.expire_all()
    assert db.session.get(QuarantineItem, item_id) is None
    assert b"removed from the quarantine" in logged_in.get("/quarantine/").data


def test_virus_release_needs_confirmation(logged_in, internal_app, domains, sent):
    _ingest(internal_app, ["alice@example.com"], symbols=[{"name": "CLAM_VIRUS", "score": 0}])
    virus = QuarantineItem.query.one()
    assert virus.is_virus
    logged_in.post(f"/quarantine/{virus.id}/action", data={"action": "release"})
    assert sent == []
    logged_in.post(f"/quarantine/{virus.id}/action", data={"action": "release", "confirm_virus": "yes"})
    assert len(sent) == 1
    # bulk release skips viruses entirely
    logged_in.post("/quarantine/bulk", data={"action": "release", "ids": [str(virus.id)]})
    assert len(sent) == 1


def test_release_failure_is_reported(logged_in, item, monkeypatch):
    def broken(*args):
        raise mailer.ReleaseError("Postfix did not accept the message")
    monkeypatch.setattr(mailer, "reinject", broken)
    response = logged_in.post(f"/quarantine/{item.id}/action", data={"action": "release"}, follow_redirects=True)
    assert b"Postfix did not accept" in response.data
    db.session.expire_all()
    assert db.session.get(QuarantineItem, item.id) is not None  # kept for another try


def test_learn_spam_deletes(logged_in, item, learned):
    logged_in.post(f"/quarantine/{item.id}/action", data={"action": "learn_spam"})
    assert learned == [True]
    assert QuarantineItem.query.count() == 0


def test_bulk_delete_and_safe_next(logged_in, item):
    response = logged_in.post("/quarantine/bulk", data={
        "action": "delete", "ids": [str(item.id)], "next": "https://evil.example/"})
    assert response.headers["Location"] == "/quarantine/"
    assert QuarantineItem.query.count() == 0


def test_cleanup_command(app, item):
    item.created_at = utcnow() - timedelta(days=get_setting("quarantine_retention_days") + 1)
    db.session.commit()
    result = app.test_cli_runner().invoke(args=["cleanup"])
    assert "Deleted 1" in result.output
    assert QuarantineItem.query.count() == 0


def test_init_db_removes_messages_released_before(app, item):
    """Released messages stayed in the quarantine up to 0.5.1, marked by
    released_at; init-db deletes them and the columns once."""
    kept = QuarantineItem(rcpt="bob@example.com", domain="example.com", message=RAW, symbols="[]")
    db.session.add(kept)
    db.session.commit()
    with db.engine.begin() as conn:
        conn.execute(db.text("ALTER TABLE quarantine ADD COLUMN released_at DATETIME"))
        conn.execute(db.text("ALTER TABLE quarantine ADD COLUMN released_by VARCHAR(64)"))
        conn.execute(db.text("UPDATE quarantine SET released_at = CURRENT_TIMESTAMP, released_by = 'admin' "
                             "WHERE id = :id"), {"id": item.id})
    output = app.test_cli_runner().invoke(args=["init-db"]).output
    assert "removed 1 released message(s)" in output
    assert [i.rcpt for i in QuarantineItem.query] == ["bob@example.com"]
    assert "released_at" not in {c["name"] for c in db.inspect(db.engine).get_columns("quarantine")}
    assert "released" not in app.test_cli_runner().invoke(args=["init-db"]).output  # once
