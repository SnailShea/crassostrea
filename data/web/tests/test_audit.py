"""Audit log: changes and logins of the web UI, the API and the command line."""
import json
from datetime import timedelta

import pytest

from crassostrea.extensions import db
from crassostrea.models import AuditEntry, DigestToken, Domain, QuarantineItem, set_setting, utcnow
from crassostrea.services import audit, mailer


def entries(action=None):
    query = AuditEntry.query.order_by(AuditEntry.id)
    if action:
        query = query.filter_by(action=action)
    return query.all()


def test_ui_change_is_recorded(logged_in):
    logged_in.post("/settings/networks", data={"net-cidr": "192.0.2.0/24", "net-comment": "office"})
    entry = entries("settings.add_network")[-1]
    assert (entry.actor, entry.ip, entry.method, entry.outcome) == ("admin", "127.0.0.1", "POST", "ok")
    assert json.loads(entry.details) == {"net-cidr": "192.0.2.0/24", "net-comment": "office"}
    assert entry.target == "/settings/networks" and "192.0.2.0/24" in entry.message
    assert audit.describe(entry) == "Settings: add network"
    # reads are not recorded
    count = AuditEntry.query.count()
    logged_in.get("/settings/")
    assert AuditEntry.query.count() == count


def test_logins_and_secrets(client, app):
    client.post("/login", data={"username": "admin", "password": "wrong-password"})
    client.post("/login", data={"username": "admin", "password": "initial-password"})
    failed, ok = entries("auth.login")
    assert (failed.actor, failed.outcome, ok.actor, ok.outcome) == ("admin", "failed", "admin", "ok")
    assert "Invalid username or password" in failed.message
    assert json.loads(failed.details) == {"username": "admin", "password": "(hidden)"}
    client.post("/admins/", data={"username": "second", "password": "a-long-password", "confirm": "a-long-password"})
    created = entries("users.index")[-1]
    assert json.loads(created.details) == {"username": "second", "password": "(hidden)", "confirm": "(hidden)"}
    assert audit.describe(created) == "Create administrator" and "a-long-password" not in created.details


def test_failure_reported_by_the_page(logged_in):
    logged_in.post("/bans/unban", data={"network": "not-a-network"})
    entry = entries("logs.unban")[-1]
    assert entry.outcome == "failed" and entry.message == "Invalid network."


def test_form_action_in_the_description(logged_in, monkeypatch):
    monkeypatch.setattr(mailer, "reinject", lambda *a: None)
    item = QuarantineItem(rcpt="a@example.com", domain="example.com", message=b"Subject: x\r\n\r\nx", symbols="[]")
    db.session.add(item)
    db.session.commit()
    logged_in.post(f"/quarantine/{item.id}/action", data={"action": "release"})
    entry = entries("quarantine.action")[-1]
    assert audit.describe(entry) == "Quarantine: action (release)"
    assert entry.target == f"/quarantine/<int:item_id>/action item_id={item.id}"


def test_api_changes(api, app):
    api("POST", "/relay-networks", json={"cidr": "198.51.100.0/24"})
    entry = entries("api.create_relay_network")[-1]
    assert entry.actor == "api:test" and entry.outcome == "ok" and json.loads(entry.details) == {
        "cidr": "198.51.100.0/24"}
    api("PATCH", "/settings", json={"reject_score": "high"})
    failed = entries("api.update_settings")[-1]
    assert failed.outcome == "failed" and failed.message == "Thresholds must be numbers from -100 to 10000"
    # without a valid key nothing is recorded (the throttling logs it)
    count = AuditEntry.query.count()
    app.test_client().post("/api/v1/relay-networks", json={"cidr": "203.0.113.0/24"},
                           headers={"X-API-Key": "wrong"})
    assert AuditEntry.query.count() == count


def test_digest_links_do_not_reveal_the_token(app, client, monkeypatch):
    monkeypatch.setattr(mailer, "reinject", lambda *a: None)
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    item = QuarantineItem(rcpt="alice@example.com", domain="example.com", message=b"Subject: x\r\n\r\nx",
                          symbols="[]")
    row, token = DigestToken.create("alice@example.com", utcnow() + timedelta(days=1))
    db.session.add_all([item, row])
    db.session.commit()
    client.post(f"/q/{token}/{item.id}/action", data={"action": "release"})
    entry = entries("token.action")[-1]
    assert entry.actor == "link:alice@example.com" and token not in entry.target and token not in entry.details
    assert entry.target == f"/q/<token>/<int:item_id>/action item_id={item.id}"


def test_a_broken_audit_log_does_not_break_requests(logged_in, monkeypatch):
    def broken(**entry):
        raise RuntimeError("database gone")
    monkeypatch.setattr(audit, "_write", broken)
    response = logged_in.post("/settings/networks", data={"net-cidr": "192.0.2.0/24"})
    assert response.status_code == 302


def test_command_line(app, make_admin):
    make_admin("helper")
    runner = app.test_cli_runner()
    assert runner.invoke(args=["reset-password", "helper", "--password", "a-new-password"]).exit_code == 0
    assert runner.invoke(args=["reset-2fa", "helper"]).exit_code == 0
    actions = [(e.actor, e.action, e.target) for e in entries() if e.actor == "cli"]
    assert actions == [("cli", "cli.reset-password", "helper"), ("cli", "cli.reset-2fa", "helper")]
    assert "a-new-password" not in json.dumps([e.message for e in entries()])


def test_retention(app):
    db.session.add_all([AuditEntry(actor="old", action="x", at=utcnow() - timedelta(days=400)),
                        AuditEntry(actor="new", action="x")])
    set_setting("audit_retention_days", 365)
    db.session.commit()
    result = app.test_cli_runner().invoke(args=["cleanup"])
    assert result.exit_code == 0 and "1 audit log entry older than 365 day(s)" in result.output
    assert [e.actor for e in AuditEntry.query.all()] == ["new"]


def test_page_and_filters(logged_in):
    logged_in.post("/settings/networks", data={"net-cidr": "192.0.2.0/24"})
    logged_in.post("/bans/unban", data={"network": "nonsense"})
    page = logged_in.get("/audit/").get_data(as_text=True)
    assert "Settings: add network" in page and "Banned IPs: unban" in page and 'href="/audit/" class="active"' in page
    failed = logged_in.get("/audit/?outcome=failed").get_data(as_text=True)
    assert "Banned IPs: unban" in failed and "Settings: add network" not in failed
    found = logged_in.get("/audit/?q=192.0.2.0").get_data(as_text=True)
    assert "Settings: add network" in found and "Banned IPs: unban" not in found
    assert 'value="admin"' in page  # actor filter


def test_api_list(api, logged_in):
    logged_in.post("/settings/networks", data={"net-cidr": "192.0.2.0/24"})
    body = api("GET", "/audit-log?actor=admin").get_json()
    assert body["total"] >= 1 and body["items"][0]["description"] == "Settings: add network"
    assert body["items"][0]["details"] == {"net-cidr": "192.0.2.0/24"}
    assert api("GET", "/audit-log?outcome=maybe").status_code == 400


@pytest.mark.parametrize("days, ok", [(29, False), (30, True), (3650, True), (3651, False)])
def test_retention_setting(api, days, ok):
    response = api("PATCH", "/settings", json={"audit_retention_days": days})
    assert (response.status_code == 200) is ok
