"""Recipients Postfix refused because they do not exist: system/libexec/logship
finds them in the Postfix log and reports them to the internal API, which
adds them to the mail log (no message, no scan)."""
import http.server
import importlib.machinery
import importlib.util
import json
import sys
import threading
import time
from pathlib import Path

import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, MailLogEntry, StatBucket

REPO = Path(__file__).resolve().parents[3]


def _load_logship():
    """system/libexec/logship as a module, without writing its bytecode there."""
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
NOW = int(time.time())


def _journal(message, identifier="postfix/smtpd", when=NOW):
    return {"MESSAGE": message, "SYSLOG_IDENTIFIER": identifier, "__REALTIME_TIMESTAMP": str(when * 1000000)}


@pytest.mark.parametrize("message, expected", [
    # the recipient list or a directory
    ("NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 550 5.1.1 <nobody@example.com>: Recipient address "
     "rejected: User unknown in relay recipient table; from=<spam@bad.example> to=<nobody@example.com> "
     "proto=ESMTP helo=<x>",
     {"ip": "203.0.113.5", "sender": "spam@bad.example", "rcpt": "nobody@example.com",
      "reason": "User unknown in relay recipient table"}),
    # newer Postfix separates with commas; client port logging; empty sender; IPv6
    ("NOQUEUE: reject: RCPT from mail.bad.example[2001:db8::5]:40123: 550 5.1.1 <Info@Example.com>: Recipient "
     "address rejected: User unknown in relay recipient table; from=<>, to=<Info@Example.com>, proto=ESMTP, "
     "helo=<mail.bad.example>",
     {"ip": "2001:db8::5", "sender": "", "rcpt": "Info@Example.com",
      "reason": "User unknown in relay recipient table"}),
    # verification with the destination server
    ("NOQUEUE: reject: RCPT from unknown[198.51.100.7]: 550 5.1.1 <gone@example.com>: Recipient address "
     "rejected: undeliverable address: host mx.internal[10.0.0.5] said: 550 5.1.1 <gone@example.com>: User "
     "unknown (in reply to RCPT TO command); from=<a@b.example> to=<gone@example.com> proto=ESMTP helo=<b>",
     {"ip": "198.51.100.7", "sender": "a@b.example", "rcpt": "gone@example.com",
      "reason": "undeliverable address: host mx.internal[10.0.0.5] said: 550 5.1.1 <gone@example.com>: User "
                "unknown (in reply to RCPT TO command)"}),
])
def test_logship_recognises_refusals(message, expected):
    assert logship.refused(_journal(message)) == {"time": NOW, **expected}


@pytest.mark.parametrize("message, identifier", [
    # temporary: the destination server could not be asked
    ("NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 450 4.1.1 <x@example.com>: Recipient address rejected: "
     "undeliverable address: connect timed out; from=<a@b> to=<x@example.com> proto=ESMTP helo=<x>", "postfix/smtpd"),
    # not an unknown recipient
    ("NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 554 5.7.1 <x@other.example>: Relay access denied; "
     "from=<a@b> to=<x@other.example> proto=ESMTP helo=<x>", "postfix/smtpd"),
    ("NOQUEUE: reject: RCPT from [203.0.113.5]:60454: 550 5.7.1 Service unavailable; client [203.0.113.5] "
     "blocked using zen.spamhaus.org; from=<a@b>, to=<x@example.com>, proto=ESMTP, helo=<h>", "postfix/postscreen"),
    # another program
    ("NOQUEUE: reject: RCPT from unknown[203.0.113.5]: 550 5.1.1 <x@example.com>: Recipient address rejected: "
     "User unknown in relay recipient table; from=<a@b> to=<x@example.com>", "postfix/cleanup"),
])
def test_logship_ignores_other_lines(message, identifier):
    assert logship.refused(_journal(message, identifier)) is None


def test_logship_posts_and_survives_failures():
    received = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            received.append((self.headers["Content-Type"],
                             json.loads(self.rfile.read(int(self.headers["Content-Length"])))))
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"stored 1")

        def log_message(self, *args):
            pass

    server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    event = {"time": NOW, "ip": "203.0.113.5", "sender": "", "rcpt": "x@example.com", "reason": "User unknown"}
    try:
        assert logship.report_refused(event, f"http://127.0.0.1:{server.server_port}/internal/refused-recipient")
    finally:
        server.shutdown()
        server.server_close()
    assert received == [("application/json", event)]
    # the internal API is down: logged, not raised
    assert not logship.report_refused(event, f"http://127.0.0.1:{server.server_port}/internal/refused-recipient")


@pytest.fixture
def domain(app):
    db.session.add(Domain(name="example.com", destination_host="mx.internal", recipient_check="list"))
    db.session.commit()


def _report(internal_app, **changes):
    event = {"time": NOW, "ip": "203.0.113.5", "sender": "spam@bad.example", "rcpt": "Nobody@Example.com",
             "reason": "User unknown in relay recipient table", **changes}
    return internal_app.test_client().post("/internal/refused-recipient", json=event,
                                           environ_base={"REMOTE_ADDR": "127.0.0.1"})


def test_internal_api_stores_refusals(internal_app, domain, monkeypatch):
    from crassostrea.services import siem
    events = []
    monkeypatch.setattr(siem, "enqueue", lambda kind, event: events.append(event))
    response = _report(internal_app)
    assert response.status_code == 200 and response.get_data(as_text=True).startswith("stored")
    entry = MailLogEntry.query.one()
    assert (entry.rcpts, entry.sender, entry.ip, entry.action) == ("nobody@example.com", "spam@bad.example",
                                                                   "203.0.113.5", "reject")
    assert entry.refused and entry.message == b"" and entry.size == 0
    assert StatBucket.query.count() == 0  # not counted in the statistics
    assert events[0]["refused"] == "User unknown in relay recipient table"


@pytest.mark.parametrize("changes", [
    {"rcpt": "x@not-a-gateway-domain.example"},   # not one of the gateway's domains
    {"reason": "Relay access denied"},             # not an unknown recipient
    {"time": NOW + 3600},                          # from the future
    {"time": NOW - 60 * 86400},                    # older than the mail log keeps
    {"ip": "not an address"},
    {"rcpt": "a b@example.com"},
])
def test_internal_api_skips_invalid_events(internal_app, domain, changes):
    assert _report(internal_app, **changes).get_data(as_text=True) == "skipped"
    assert MailLogEntry.query.count() == 0


def test_internal_api_only_for_internal_clients(internal_app, domain):
    response = internal_app.test_client().post("/internal/refused-recipient", json={},
                                               environ_base={"REMOTE_ADDR": "8.8.8.8"})
    assert response.status_code == 403
    assert internal_app.test_client().post("/internal/refused-recipient", data="x",
                                           environ_base={"REMOTE_ADDR": "127.0.0.1"}).status_code == 400


def test_mail_log_pages(internal_app, logged_in, domain):
    _report(internal_app)
    entry = MailLogEntry.query.one()
    listing = logged_in.get("/mail-log/").get_data(as_text=True)
    assert "Refused: User unknown in relay recipient table" in listing
    refused = logged_in.get("/mail-log/?action=refused").get_data(as_text=True)
    assert "nobody@example.com" in refused and 'value="refused" selected' in refused
    page = logged_in.get(f"/mail-log/{entry.id}").get_data(as_text=True)
    assert "Refused recipient" in page and "Queue again" not in page and "Score breakdown" not in page
    assert logged_in.get(f"/mail-log/{entry.id}/raw").status_code == 404
    assert logged_in.get(f"/mail-log/{entry.id}/html").status_code == 404
    response = logged_in.post(f"/mail-log/{entry.id}/requeue", data={"rcpts": "nobody@example.com"},
                              follow_redirects=True)
    assert "no message to queue" in response.get_data(as_text=True)


def test_api(internal_app, api, domain):
    _report(internal_app)
    entry = MailLogEntry.query.one()
    items = api("GET", "/mail-log?action=refused").get_json()["items"]
    assert [i["refused"] for i in items] == ["User unknown in relay recipient table"]
    assert api("GET", "/mail-log?action=reject").get_json()["items"][0]["id"] == entry.id
    assert api("GET", f"/mail-log/{entry.id}/raw").status_code == 404
    assert api("POST", f"/mail-log/{entry.id}/requeue", json={"rcpts": ["nobody@example.com"]}).status_code == 409


def test_dashboard_recent_mail_leaves_refusals_out(internal_app, logged_in, domain, monkeypatch):
    from crassostrea.services import rspamd, system
    monkeypatch.setattr(rspamd.RspamdClient, "stat", lambda self: {})
    monkeypatch.setattr(system, "units", lambda: [])
    _report(internal_app)
    page = logged_in.get("/").get_data(as_text=True)
    assert "nobody@example.com" not in page
