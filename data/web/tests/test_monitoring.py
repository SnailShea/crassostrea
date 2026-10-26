"""Monitoring: /metrics with its token, alert checks and mail, SIEM events
and their forwarding, the page and the API."""
import io
import json
import socket
import threading
import time

import pytest

from crassostrea.extensions import db
from crassostrea.models import Directory, set_setting, utcnow
from crassostrea.services import mailer, monitoring, postfix_control, siem, system


@pytest.fixture
def gateway(monkeypatch):
    """The parts monitoring asks: a queue, units, rspamd."""
    state = {"queue": [{"queue_name": "deferred", "arrival_time": time.time() - 3 * 3600},
                       {"queue_name": "active", "arrival_time": time.time()}],
             "units": [{"unit": "postfix.service", "state": "active"}, {"unit": "rspamd.service", "state": "active"}]}
    monkeypatch.setattr(postfix_control, "mail_queue", lambda: state["queue"])
    monkeypatch.setattr(system, "units", lambda: state["units"])

    class Client:
        def stat(self):
            return {}
    monkeypatch.setattr(monitoring, "client", lambda: Client())
    return state


@pytest.fixture
def sent(monkeypatch):
    mails = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, message: mails.append((sender, rcpt, message)))
    return mails


def test_metrics_token(app, client, gateway, fake_redis):
    assert client.get("/metrics").status_code == 401
    token = monitoring.create_token()
    db.session.commit()
    assert client.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 401
    response = client.get("/metrics", headers={"Authorization": f"Bearer {token}"})
    text = response.get_data(as_text=True)
    assert response.status_code == 200 and response.mimetype == "text/plain"
    assert 'sf_up{component="database"} 1' in text and 'sf_queue_messages{queue="deferred"} 1' in text
    assert 'sf_service_active{unit="postfix.service"} 1' in text and "# TYPE sf_queue_messages gauge" in text
    assert "sf_queue_deferred_oldest_seconds 10" in text
    monitoring.revoke_token()
    db.session.commit()
    assert client.get("/metrics", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_render_escapes_labels():
    text = monitoring.render([("sf_x", "Help", "gauge", [({"name": 'a"b\\c'}, 1.0), ({}, 2.5)])])
    assert 'sf_x{name="a\\"b\\\\c"} 1' in text and "sf_x 2.5" in text


def test_checks(app, gateway, fake_redis):
    set_setting("alert_deferred_hours", 2)
    db.session.add(Directory(name="AD", kind="ldap", sync_error="LDAP: invalid credentials", synced_at=utcnow()))
    db.session.commit()
    results = monitoring.check()
    assert results["queue"]["ok"] and not results["queue_age"]["ok"]
    assert not results["certificate"]["ok"] and not results["backup"]["ok"]  # none in the tests
    assert results["directories"] == {"ok": False, "message": "Not synchronised: AD"}
    gateway["units"][1]["state"] = "failed"
    assert monitoring.check()["services"] == {"ok": False, "message": "Not running: rspamd.service"}


def test_alert_mail(app, fake_redis, sent):
    failing = {"queue": {"ok": False, "message": "500 deferred"}, "backup": {"ok": True, "message": "fine"}}
    assert monitoring.run_alerts(failing) == ([], [])  # no recipients: nothing recorded
    set_setting("alert_recipients", "ops@example.com\nboss@example.com")
    db.session.commit()
    assert monitoring.run_alerts(failing, now=1000) == ([("queue", "500 deferred")], [])
    assert len(sent) == 2 and b"PROBLEM  Deferred mail: 500 deferred" in sent[0][2]
    assert sent[0][0].startswith("alerts@")
    # not again until a day passed
    assert monitoring.run_alerts(failing, now=2000) == ([], []) and len(sent) == 2
    assert monitoring.run_alerts(failing, now=1000 + 86400)[0] == [("queue", "500 deferred")]
    assert monitoring.alert_state() == {"queue": 1000}
    solved = {"queue": {"ok": True, "message": "3 deferred"}}
    assert monitoring.run_alerts(solved, now=100000) == ([], [("queue", "3 deferred")])
    assert b"SOLVED" in sent[-1][2] and monitoring.alert_state() == {}


def test_alert_mail_failure_retries(app, fake_redis, monkeypatch):
    set_setting("alert_recipients", "ops@example.com")
    db.session.commit()

    def broken(*args):
        raise mailer.ReleaseError("Postfix down")
    monkeypatch.setattr(mailer, "reinject", broken)
    with pytest.raises(mailer.ReleaseError):
        monitoring.run_alerts({"queue": {"ok": False, "message": "x"}})
    assert monitoring.alert_state() == {}


def test_check_alerts_command(app, gateway, fake_redis, sent):
    set_setting("alert_recipients", "ops@example.com")
    db.session.commit()
    result = app.test_cli_runner().invoke(args=["check-alerts"])
    assert result.exit_code == 0 and "PROBLEM certificate" in result.output and sent


def test_siem_events(internal_app, app, fake_redis, logged_in):
    meta = {"qid": "Q1", "from": "a@x.example", "rcpt": ["bob@example.com"], "score": 1, "action": "no action",
            "symbols": [{"name": "BAYES_HAM", "score": -1}]}

    def post():
        internal_app.test_client().post("/internal/mail-log", environ_base={"REMOTE_ADDR": "172.22.1.5"}, data={
            "metadata": json.dumps(meta), "message": (io.BytesIO(b"Subject: Hi\r\n\r\nx\r\n"), "message")})
    post()
    assert fake_redis.llen(siem.QUEUE) == 0  # no SIEM
    set_setting("siem_host", "siem.example.com")
    db.session.commit()
    post()
    logged_in.post("/settings/networks", data={"net-cidr": "192.0.2.0/24"})
    events = [json.loads(e) for e in fake_redis.lrange(siem.QUEUE, 0, -1)]
    kinds = [e["type"] for e in events]
    assert kinds[0] == "mail" and "audit" in kinds
    assert events[0]["recipients"] == ["bob@example.com"] and events[0]["symbols"] == ["BAYES_HAM"]
    audit = next(e for e in events if e["type"] == "audit" and e["action"] == "settings.add_network")
    assert audit["actor"] == "admin" and audit["description"] == "Settings: add network"
    set_setting("siem_mail_log", 0)
    db.session.commit()
    before = fake_redis.llen(siem.QUEUE)
    post()
    assert fake_redis.llen(siem.QUEUE) == before


def test_line_formats(app):
    event = {"type": "mail", "time": "2026-10-21T10:00:00Z", "node": "mx.example.com", "subject": "Hi"}
    assert siem.line(event, "json") == json.dumps(event, separators=(",", ":"))
    assert siem.line(event, "rfc5424").startswith("<134>1 2026-10-21T10:00:00Z mx.example.com crassostrea - mail - {")


def test_forward(app, fake_redis):
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    received = []

    def accept():
        conn, _ = server.accept()
        with conn:
            data = b""
            while data.count(b"\n") < 3:
                chunk = conn.recv(4096)
                if not chunk:
                    break
                data += chunk
            received.append(data)
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    set_setting("siem_host", "127.0.0.1")
    set_setting("siem_port", server.getsockname()[1])
    db.session.commit()
    for n in range(3):
        siem.enqueue("audit", {"type": "audit", "n": n})
    calls = []
    siem.forward(stop=lambda: calls.append(1) or len(calls) > 2, idle=1)
    thread.join(5)
    server.close()
    assert [json.loads(line)["n"] for line in received[0].splitlines()] == [0, 1, 2]
    assert fake_redis.llen(siem.QUEUE) == 0


def test_forward_keeps_events_while_away(app, fake_redis, monkeypatch):
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    set_setting("siem_host", "127.0.0.1")
    set_setting("siem_port", port)
    db.session.commit()
    siem.enqueue("audit", {"type": "audit", "n": 1})
    monkeypatch.setattr(siem.time, "sleep", lambda s: None)
    calls = []
    siem.forward(stop=lambda: calls.append(1) or len(calls) > 1, idle=1)
    assert fake_redis.lrange(siem.QUEUE, 0, -1) == ['{"type":"audit","n":1}']


def test_page(app, logged_in, gateway, fake_redis, sent):
    page = logged_in.get("/monitoring/").get_data(as_text=True)
    assert "Checks" in page and "Create a token" not in page and 'href="/monitoring/settings"' in page
    page = logged_in.get("/monitoring/settings").get_data(as_text=True)
    assert "Create a token" in page and 'class="active" aria-current="page">Alerts &amp; export</a>' in page
    page = logged_in.post("/monitoring/token", follow_redirects=True).get_data(as_text=True)
    assert "sfm_" in page and monitoring.has_token()
    assert "sfm_" not in logged_in.get("/monitoring/settings").get_data(as_text=True).split("credentials:")[0][-200:]
    response = logged_in.post("/monitoring/siem", data={
        "siem-siem_host": "siem.example.com", "siem-siem_port": "6514", "siem-siem_protocol": "tls",
        "siem-siem_format": "rfc5424", "siem-siem_verify_tls": "y", "siem-siem_audit": "y"}, follow_redirects=True)
    assert "SIEM settings saved" in response.get_data(as_text=True)
    response = logged_in.post("/monitoring/alerts", data={
        "alert-alert_recipients": "ops@example.com", "alert-alert_deferred_count": "50",
        "alert-alert_deferred_hours": "4", "alert-alert_cert_days": "10", "alert-alert_backup_hours": "48"},
        follow_redirects=True)
    assert "Alert settings saved" in response.get_data(as_text=True)
    response = logged_in.post("/monitoring/alerts/test", follow_redirects=True)
    assert "A test alert was sent to ops@example.com" in response.get_data(as_text=True) and sent
    response = logged_in.post("/monitoring/alerts", data={"alert-alert_recipients": "not an address",
                                                          "alert-alert_deferred_count": "50",
                                                          "alert-alert_deferred_hours": "4",
                                                          "alert-alert_cert_days": "10",
                                                          "alert-alert_backup_hours": "48"})
    assert response.status_code == 400


def test_api(api, gateway, fake_redis):
    checks = api("GET", "/monitoring/checks").get_json()["checks"]
    assert checks["queue"]["label"] == "Deferred mail" and checks["queue"]["ok"] is True
    body = api("PATCH", "/settings", json={"siem_protocol": "udp", "alert_cert_days": 7}).get_json()
    assert (body["siem_protocol"], body["alert_cert_days"]) == ("udp", 7)
    assert api("PATCH", "/settings", json={"siem_protocol": "smoke"}).status_code == 422




def test_version_card(logged_in, config):
    with open(config["VERSION_FILE"], "w") as fh:
        fh.write("v0.3.1\n1800000000\n")
    page = logged_in.get("/monitoring/").get_data(as_text=True)
    assert '<dd class="mono">v0.3.1' in page
    assert 'href="https://github.com/SnailShea/crassostrea/releases/tag/v0.3.1"' in page
    assert "the newest release" in page  # UPDATE_CHANNEL unset
    # past a release, on the branch: no release notes
    with open(config["VERSION_FILE"], "w") as fh:
        fh.write("v0.3.1-4-g1a2b3c4d5e\n1800000000\n")
    with open(config["CONF_FILE"], "w") as fh:
        fh.write("UPDATE_CHANNEL=main\n")
    page = logged_in.get("/monitoring/").get_data(as_text=True)
    assert "v0.3.1-4-g1a2b3c4d5e" in page and "releases/tag" not in page
    assert "the newest commit of the branch" in page
