"""Mail log: ingestion from rspamd, the admin pages, re-queueing, retention and the API."""
import io
import json
from datetime import timedelta

import pytest

from crassostrea.extensions import db
from crassostrea.models import DkimKey, Domain, MailLogEntry, QuarantineItem, utcnow
from crassostrea.services import dkim, filters, mailer, maillog
from crassostrea.services.errors import ServiceError

RAW = (b"From: Alice <alice@sender.example>\r\nTo: bob@example.com\r\nSubject: Quarterly report\r\n"
       b"Message-ID: <42@sender.example>\r\n\r\nHello Bob,\r\nthe report is attached.\r\n")


def _meta(**changes):
    meta = {"qid": "4F3A2B1C", "subject": "Quarterly report", "from": "alice@sender.example",
            "rcpt": ["Bob@Example.com", "carol@example.com"], "score": 3.2, "action": "no action",
            "ip": "203.0.113.50", "scan_time": 87, "size": len(RAW),
            "header_from": ["Alice <alice@sender.example>"], "header_subject": ["Quarterly report"],
            "symbols": [{"name": "BAYES_HAM", "score": -3.0, "options": ["99.0%"]},
                        {"name": "MIME_GOOD", "score": -0.1, "options": ["text/plain"]},
                        {"name": "RCPT_PROTECTED_DOMAIN", "score": 0.0},
                        {"name": "DATE_IN_PAST", "score": 6.3}]}
    meta.update(changes)
    return meta


def _post(internal_app, meta, raw=RAW, path="/internal/mail-log", remote="172.22.1.5"):
    return internal_app.test_client().post(
        path, data={"metadata": json.dumps(meta), "message": (io.BytesIO(raw), "message")},
        environ_base={"REMOTE_ADDR": remote})


def _entry(**fields):
    values = {"qid": "4F3A2B1C", "sender": "alice@sender.example", "rcpts": "bob@example.com,carol@example.com",
              "subject": "Quarterly report", "score": 3.2, "action": "no action", "ip": "203.0.113.50",
              "symbols": json.dumps(_meta()["symbols"]), "size": len(RAW), "message": RAW}
    values.update(fields)
    entry = MailLogEntry(**values)
    db.session.add(entry)
    db.session.commit()
    return entry


@pytest.fixture
def sent(monkeypatch):
    calls = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, message: calls.append((sender, rcpt, message)))
    return calls


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

def test_ingest_stores_every_message(internal_app, app):
    assert _post(internal_app, _meta()).status_code == 200
    entry = MailLogEntry.query.one()
    assert entry.direction == "inbound" and entry.qid == "4F3A2B1C" and entry.message_id == "<42@sender.example>"
    assert entry.rcpt_list == ["bob@example.com", "carol@example.com"]
    assert entry.header_from == "Alice <alice@sender.example>" and entry.subject == "Quarterly report"
    assert (entry.score, entry.action, entry.scan_ms, entry.size) == (3.2, "no action", 87, len(RAW))
    assert entry.message == RAW
    assert [s["name"] for s in entry.symbol_list][:2] == ["DATE_IN_PAST", "RCPT_PROTECTED_DOMAIN"]


def test_ingest_outbound_and_missing_values(internal_app, app):
    meta = _meta(qid="unknown", subject="unknown", header_subject="unknown", header_from="unknown",
                 rcpt="unknown", symbols=[{"name": "RELAY_NETWORK", "score": 0}], scan_time="x")
    assert _post(internal_app, meta).status_code == 200
    entry = MailLogEntry.query.one()
    assert entry.direction == "outbound"
    assert (entry.qid, entry.subject, entry.header_from, entry.rcpts, entry.scan_ms) == ("", "", "", "", 0)


def test_ingest_keeps_large_messages_in_full(internal_app, app):
    # larger than the web UI's upload limit, which the internal API raises
    big = RAW + b"x" * (70 * 1024 * 1024)
    assert internal_app.config["MAX_CONTENT_LENGTH"] > len(big) > app.config["MAX_CONTENT_LENGTH"]
    assert _post(internal_app, _meta(), raw=big).status_code == 200
    entry = MailLogEntry.query.one()
    assert entry.size == len(big) and entry.message == big


def test_ingest_rejects_bad_requests_and_other_hosts(internal_app, app):
    assert _post(internal_app, _meta(), remote="8.8.8.8").status_code == 403
    response = internal_app.test_client().post("/internal/mail-log", data={"metadata": "{"},
                                               environ_base={"REMOTE_ADDR": "172.22.1.5"})
    assert response.status_code == 400
    assert MailLogEntry.query.count() == 0


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

def test_list_filters(logged_in, app):
    _entry(subject="Report for example.com")
    _entry(subject="Invoice", sender="billing@example.com", rcpts="x@partner.example", direction="outbound",
           action="reject", qid="9ABCDEF0")
    _entry(subject="Cheap watches", rcpts="dave@other.example", action="add header", ip="198.51.100.9")

    def subjects(query):
        page = logged_in.get(f"/mail-log/?{query}").get_data(as_text=True)
        return [s for s in ("Report for example.com", "Invoice", "Cheap watches") if s in page]
    assert subjects("") == ["Report for example.com", "Invoice", "Cheap watches"]
    assert subjects("domain=example.com") == ["Report for example.com", "Invoice"]  # recipient or sender
    assert subjects("domain=other.example") == ["Cheap watches"]
    assert subjects("direction=outbound") == ["Invoice"]
    assert subjects("action=add+header") == ["Cheap watches"]
    assert subjects("q=9ABCDEF0") == ["Invoice"]
    assert subjects("q=198.51.100.9") == ["Cheap watches"]
    assert subjects("q=%25") == []  # LIKE wildcards are literal


def test_show_page(logged_in, app):
    entry = _entry()
    db.session.add(QuarantineItem(qid="4F3A2B1C", rcpt="bob@example.com", domain="example.com", message=RAW))
    db.session.commit()
    page = logged_in.get(f"/mail-log/{entry.id}").get_data(as_text=True)
    assert "Score breakdown" in page and "DATE_IN_PAST" in page and "+6.30" in page and "-3.00" in page
    assert "99.0%" in page  # symbol options
    assert "the report is attached." in page  # message text
    assert "Message-ID" in page and "&lt;42@sender.example&gt;" in page  # headers
    assert "/logs?q=4F3A2B1C" in page and "/quarantine/" in page
    assert 'name="rcpts" value="carol@example.com" checked' in page
    assert logged_in.get("/mail-log/9999").status_code == 404


def test_download(logged_in, app):
    entry = _entry()
    response = logged_in.get(f"/mail-log/{entry.id}/raw")
    assert response.data == RAW and response.mimetype == "message/rfc822"


def test_dashboard_lists_recent_mail(logged_in, app, monkeypatch):
    from crassostrea.services import rspamd, system
    monkeypatch.setattr(rspamd.RspamdClient, "stat", lambda self: {})
    monkeypatch.setattr(system, "units", lambda: [])
    entry = _entry(subject="Shown on the dashboard")
    page = logged_in.get("/").get_data(as_text=True)
    assert "Shown on the dashboard" in page and f"/mail-log/{entry.id}" in page


# ---------------------------------------------------------------------------
# Re-queueing
# ---------------------------------------------------------------------------

def test_requeue_to_selected_recipients(logged_in, app, sent):
    entry = _entry(message=b"X-Mail-Log-Requeued: forged\r\n" + RAW)
    response = logged_in.post(f"/mail-log/{entry.id}/requeue", data={"rcpts": ["carol@example.com"]},
                              follow_redirects=True)
    assert "queued for carol@example.com" in response.get_data(as_text=True)
    assert [(s, r) for s, r, _ in sent] == [("alice@sender.example", "carol@example.com")]
    message = sent[0][2]
    assert message.startswith(b"X-Mail-Log-Requeued: ") and b"by admin on " in message.split(b"\r\n")[0]
    assert message.count(b"X-Mail-Log-Requeued") == 1 and message.endswith(RAW)
    entry = db.session.get(MailLogEntry, entry.id)
    assert entry.requeued_by == "admin" and entry.requeued_at is not None


def test_requeue_refuses_other_recipients_and_empty_selection(app):
    entry = _entry()
    with pytest.raises(ServiceError, match="not a recipient"):
        maillog.requeue(entry, ["mallory@evil.example"], "admin")
    with pytest.raises(ServiceError, match="at least one"):
        maillog.requeue(entry, [], "admin")


def test_requeue_virus_needs_confirmation(app, sent):
    entry = _entry(symbols=json.dumps([{"name": "CLAM_VIRUS", "score": 20}]))
    with pytest.raises(ServiceError, match="virus"):
        maillog.requeue(entry, ["bob@example.com"], "admin")
    assert maillog.requeue(entry, ["bob@example.com"], "admin", allow_virus=True) == ["queued for bob@example.com"]


def test_requeue_reports_refused_recipients(app, monkeypatch):
    def reinject(sender, rcpt, message):
        if rcpt == "carol@example.com":
            raise mailer.ReleaseError("Postfix refused the recipient")
    monkeypatch.setattr(mailer, "reinject", reinject)
    entry = _entry()
    notes = maillog.requeue(entry, entry.rcpt_list, "admin")
    assert notes == ["queued for bob@example.com", "carol@example.com: Postfix refused the recipient"]
    monkeypatch.setattr(mailer, "reinject", lambda *a: (_ for _ in ()).throw(mailer.ReleaseError("down")))
    with pytest.raises(mailer.ReleaseError, match="down"):
        maillog.requeue(_entry(), ["bob@example.com"], "admin")


def test_requeue_signs_outbound_mail(app, sent):
    domain = Domain(name="sender.example", destination_host="mx.internal")
    db.session.add(domain)
    db.session.add(DkimKey(domain=domain, selector="sf1", private_key=dkim.generate_private_key(2048)[0],
                           key_size=2048))
    db.session.commit()
    entry = _entry(direction="outbound", rcpts="partner@external.example")
    notes = maillog.requeue(entry, ["partner@external.example"], "admin")
    assert "DKIM-signed for sender.example" in notes
    first = sent[0][2].split(b"\r\n")[0]
    assert b"by admin" not in first  # outbound: the administrator is not named
    assert b"DKIM-Signature:" in sent[0][2]


# ---------------------------------------------------------------------------
# Retention and settings
# ---------------------------------------------------------------------------

def test_cleanup_expires_old_entries(app):
    old = _entry(subject="old")
    old.created_at = utcnow() - timedelta(days=8)
    _entry(subject="recent")
    db.session.commit()
    result = app.test_cli_runner().invoke(args=["cleanup"])
    assert result.exit_code == 0, result.output
    assert "1 mail log entry older than 7 day(s)" in result.output
    assert [e.subject for e in MailLogEntry.query.all()] == ["recent"]


def test_settings(app):
    settings = filters.update_settings(maillog_retention_days=31, max_message_size_mb=25, max_attachment_size_mb=10)
    assert (settings["maillog_retention_days"], settings["max_message_size_mb"],
            settings["max_attachment_size_mb"]) == (31, 25, 10)
    for changes in ({"maillog_retention_days": 0}, {"maillog_retention_days": 32}, {"max_message_size_mb": 0},
                    {"max_message_size_mb": 101}, {"max_attachment_size_mb": -1},
                    # the attachment limit cannot exceed the message limit, also when one of them changes
                    {"max_attachment_size_mb": 26}, {"max_message_size_mb": 5},
                    {"max_message_size_mb": 30, "max_attachment_size_mb": 40}):
        with pytest.raises(ServiceError):
            filters.update_settings(**changes)
    assert filters.update_settings(max_attachment_size_mb=0, max_message_size_mb=5)["max_message_size_mb"] == 5


def test_settings_page_writes_the_limits(logged_in, app, config):
    page = logged_in.get("/settings/").get_data(as_text=True)
    assert 'name="maillog_retention_days"' in page and 'name="max_message_size_mb"' in page
    assert 'name="max_attachment_size_mb"' in page
    form = {"greylist_score": "5", "add_header_score": "6", "reject_score": "12", "quarantine_retention_days": "14",
            "quarantine_max_size_mb": "10", "maillog_retention_days": "31", "max_message_size_mb": "20",
            "max_attachment_size_mb": "8", "audit_retention_days": "365", "digest_interval": "daily",
            "digest_token_days": "7", "mailbox_invite_days": "7", "ptr_check": "off",
            "session_lifetime_minutes": "480", "login_max_failures": "10", "login_max_account_failures": "30",
            "login_failure_window_minutes": "15", "postfix_log_lines": "9999", "http_redirect": "y"}
    assert logged_in.post("/settings/", data=form).status_code == 302
    # for Postfix (system/libexec/postfix-apply) and Rspamd (rspamd.local.lua)
    with open(f"{config['POSTFIX_DYNAMIC_DIR']}/message_size_limit") as handle:
        assert handle.read() == "20971520\n"
    with open(f"{config['RSPAMD_MAP_DIR']}/size_limits.map") as handle:
        assert handle.read().splitlines()[-1] == "max_attachment_size 8388608"
    form["max_attachment_size_mb"] = "21"
    response = logged_in.post("/settings/", data=form)
    assert response.status_code == 400 and "cannot exceed the message size limit" in response.get_data(as_text=True)


# ---------------------------------------------------------------------------
# REST API
# ---------------------------------------------------------------------------

def test_api_list_and_detail(api, app):
    entry = _entry()
    _entry(subject="Other", rcpts="x@other.example", action="reject")
    listing = api("GET", "/mail-log?domain=example.com").get_json()
    assert listing["total"] == 1 and listing["items"][0]["rcpts"] == ["bob@example.com", "carol@example.com"]
    assert api("GET", "/mail-log?action=reject").get_json()["items"][0]["subject"] == "Other"
    assert api("GET", "/mail-log?direction=sideways").status_code == 400
    assert api("GET", "/mail-log?action=maybe").status_code == 400
    detail = api("GET", f"/mail-log/{entry.id}").get_json()
    assert detail["symbols"][0]["name"] == "DATE_IN_PAST" and "the report is attached." in detail["message"]["body"]
    assert detail["quarantine_ids"] == []
    assert api("GET", f"/mail-log/{entry.id}/raw").data == RAW
    assert api("GET", "/mail-log/9999").status_code == 404


def test_api_requeue(api, app, sent):
    entry = _entry()
    response = api("POST", f"/mail-log/{entry.id}/requeue")  # all recipients
    assert response.status_code == 200
    assert response.get_json()["requeued_by"] == "api:test"
    assert [r for _, r, _ in sent] == ["bob@example.com", "carol@example.com"]
    assert api("POST", f"/mail-log/{entry.id}/requeue", json={"rcpts": "bob@example.com"}).status_code == 422
    assert api("POST", f"/mail-log/{entry.id}/requeue", json={"rcpts": ["eve@x.example"]}).status_code == 422
    virus = _entry(symbols=json.dumps([{"name": "CLAM_VIRUS", "score": 20}]))
    assert api("POST", f"/mail-log/{virus.id}/requeue").status_code == 409
    assert api("POST", f"/mail-log/{virus.id}/requeue", json={"allow_virus": True}).status_code == 200


def test_api_settings(api, app):
    response = api("PATCH", "/settings", json={"max_message_size_mb": 30, "max_attachment_size_mb": 31})
    assert response.status_code == 422 and response.get_json()["field"] == "max_attachment_size_mb"
    body = api("PATCH", "/settings", json={"max_message_size_mb": 30, "maillog_retention_days": 31}).get_json()
    assert (body["max_message_size_mb"], body["maillog_retention_days"]) == (30, 31)
