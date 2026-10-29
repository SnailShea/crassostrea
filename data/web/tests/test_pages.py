"""Render every page with realistic backend data and with backends down."""
import json
import time

import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, MailboxUser, MailLogEntry, QuarantineItem
from crassostrea.services import postfix_control, rspamd, system
from crassostrea.services.rspamd import RspamdError

PAGES = ["/", "/domains/", "/domains/new", "/lists/allow", "/lists/block", "/monitoring/settings", "/cluster/manage",
         "/quarantine/", "/mail-log/", "/logs", "/bans",
         "/queue/", "/settings/", "/training/", "/admins/", "/account", "/mailboxes/",
         "/api-keys/", "/api/docs/"]

STAT = {"scanned": 100, "learned": 5, "actions": {"reject": 10, "add header": 5, "no action": 80, "greylist": 5}}
QUEUE = [{"queue_name": "deferred", "queue_id": "4F3A2B1C", "arrival_time": int(time.time()),
          "message_size": 1234, "sender": "a@example.com",
          "recipients": [{"address": "b@example.net", "delay_reason": "connection timed out"}]}]
UNITS = [{"unit": "postfix.service", "description": "Postfix Mail Transport Agent", "state": "active",
          "sub_state": "running", "since": "Fri 2026-10-16 10:00:00 UTC"},
         {"unit": "clamd@crassostrea.service", "description": "clamd scanner (crassostrea) daemon",
          "state": "failed", "sub_state": "failed", "since": ""}]


@pytest.fixture
def backends_up(monkeypatch, fake_redis):
    monkeypatch.setattr(rspamd.RspamdClient, "stat", lambda self: STAT)
    monkeypatch.setattr(system, "units", lambda: UNITS)
    monkeypatch.setattr(postfix_control, "mail_queue", lambda: [dict(q) for q in QUEUE])
    fake_redis.lpush("POSTFIX_MAILLOG", json.dumps({"time": str(int(time.time())), "program": "postfix/smtpd",
                                                    "message": "connect from unknown[203.0.113.5]"}))
    fake_redis.hset("F2B_ACTIVE_BANS", "203.0.113.0/24", int(time.time()) + 600)
    fake_redis.hset("F2B_PERM_BANS", "198.51.100.0/24", int(time.time()))


@pytest.fixture
def backends_down(monkeypatch):
    def fail(*args, **kwargs):
        raise RspamdError("Rspamd is not reachable")

    def system_fail(*args, **kwargs):
        raise system.SystemStatusError("Cannot read the service status")

    def queue_fail(*args, **kwargs):
        raise postfix_control.PostfixControlError("Postfix control service is not reachable")
    monkeypatch.setattr(rspamd.RspamdClient, "stat", fail)
    monkeypatch.setattr(system, "units", system_fail)
    monkeypatch.setattr(postfix_control, "mail_queue", queue_fail)


@pytest.fixture
def data(app):
    domain = Domain(name="example.com", destination_host="mx.internal", reject_score=20)
    db.session.add(domain)
    db.session.add(QuarantineItem(rcpt="alice@example.com", domain="example.com", subject="Win", message=b"x"))
    db.session.add(MailLogEntry(sender="spam@bad.example", rcpts="alice@example.com", subject="<script>x</script>",
                                score=18.2, action="reject", ip="203.0.113.5", message=b"Subject: x\r\n\r\nHi\r\n",
                                symbols='[{"name": "BAYES_SPAM", "score": 5}]'))
    user = MailboxUser(email="alice@example.com", domain=domain)
    user.set_password("alice-password")
    db.session.add(user)
    db.session.commit()
    return domain


@pytest.mark.parametrize("path", PAGES)
def test_pages_render_with_data(logged_in, backends_up, data, path):
    response = logged_in.get(path)
    assert response.status_code == 200, response.data[:500]
    assert b"<script>x</script>" not in response.data


def test_domain_page_renders(logged_in, data):
    response = logged_in.get(f"/domains/{data.id}")
    assert response.status_code == 200
    assert b"example.com" in response.data


def test_dashboard_and_queue_content(logged_in, backends_up, data):
    page = logged_in.get("/").data
    assert b"Busiest domains" in page and b"Messages learned" in page and b"Recent mail" not in page
    # the gateway first, then the quarantine and domains, then the statistics
    order = [page.index(h) for h in (b"<h2>Processing time</h2>", b"<h2>Mail queue</h2>", b"<h2>System load</h2>",
                                     b"<h2>Quarantine</h2>", b"<h2>Busiest domains</h2>", b'<div class="stats">',
                                     b"<h2>Over time</h2>", b'<select name="view"')]
    assert order == sorted(order)
    assert b"postfix.service" not in page  # the services are on the Monitoring page
    page = logged_in.get("/monitoring/").data
    assert b"postfix.service" in page and b"Fri 2026-10-16 10:00:00 UTC" in page
    assert b'status-dot bad"></span>failed' in page  # clamd@crassostrea
    queue = logged_in.get("/queue/").data
    assert b"4F3A2B1C" in queue and b"connection timed out" in queue
    bans = logged_in.get("/bans").data
    assert b"203.0.113.0/24" in bans and b"permanent" in bans


@pytest.mark.parametrize("path", ["/", "/queue/"])
def test_pages_render_with_backends_down(logged_in, backends_down, path):
    response = logged_in.get(path)
    assert response.status_code == 200
    assert b"not reachable" in response.data


def test_queue_actions_validate_ids(logged_in, monkeypatch):
    calls = []
    monkeypatch.setattr(postfix_control, "queue_action", lambda task, ids=None: calls.append((task, ids)))
    logged_in.post("/queue/action", data={"action": "delete", "ids": ["4F3A2B1C", "x; rm -rf /"]})
    assert calls == [("delete", ["4F3A2B1C"])]
    assert logged_in.post("/queue/action", data={"action": "shutdown"}).status_code == 400


def test_training_upload(logged_in, monkeypatch):
    from crassostrea.views import training
    learned = []
    monkeypatch.setattr(training, "train", lambda msg, spam: learned.append((msg, spam)) or ["learned as spam"])
    response = logged_in.post("/training/", data={"kind": "spam", "message_text": "Subject: hi\n\nbody"},
                              follow_redirects=True)
    assert b"learned as spam" in response.data
    assert learned == [(b"Subject: hi\n\nbody", True)]
    response = logged_in.post("/training/", data={"kind": "ham", "message_text": "no headers here"})
    assert b"does not look like a raw e-mail" in response.data


def test_sidebar_groups_pages_as_tabs(logged_in, backends_up, data):  # noqa: F811
    page = logged_in.get("/settings/").get_data(as_text=True)
    sidebar = page.split('<nav class="sidebar">')[1].split("</nav>")[0]
    links = sidebar.count("<a ")
    assert links <= 16, links
    for label in ("Protection", "Outbound", "Network", "Users", "Access", "Monitoring"):
        assert f">{label}</a>" in sidebar
    assert ">Impersonation</a>" not in sidebar and ">Banned IPs</a>" not in sidebar
    tabs = page.split('class="tabs page-tabs"')[1].split("</nav>")[0]
    for tab in ("General", "Branding", "Relay networks", "Alerts &amp; export", "Cluster", "Backups"):
        assert f">{tab}</a>" in tabs, tab
    # DMARC and TLS reports: an entry of the Mail section of its own
    mail = sidebar.split(">Mail<")[1].split('class="section"')[0]
    assert ">DMARC &amp; TLS reports</a>" in mail
    # a page of a group: its group is active in the sidebar, its tab above the page
    page = logged_in.get("/lists/allow").get_data(as_text=True)
    assert 'class="active">Lists &amp; training</a>' in page
    assert 'class="active" aria-current="page">Allow list</a>' in page
    # POST endpoints that render their page on errors keep the group
    page = logged_in.post("/settings/hostname", data={"host-hostname": "bad_name"}).get_data(as_text=True)
    assert 'class="active">Network</a>' in page and "Hostname and IP addressing" in page
    tabs = logged_in.get("/admins/").get_data(as_text=True).split('class="tabs page-tabs"')[1].split("</nav>")[0]
    assert ">Administrators</a>" in tabs and ">Mailbox users</a>" in tabs
    # pages of their own have no tabs
    assert "page-tabs" not in logged_in.get("/quarantine/").get_data(as_text=True)


def test_moved_settings_pages(logged_in):
    assert b"Relay networks" in logged_in.get("/settings/networks").data
    assert b"Save branding" in logged_in.get("/settings/branding").data
    general = logged_in.get("/settings/").get_data(as_text=True)
    assert "Save branding" not in general and 'id="networks"' not in general and 'name="host-hostname"' not in general
    assert 'form="send-digests"' in general and 'id="send-digests"' in general
    response = logged_in.post("/settings/networks", data={"net-cidr": "192.0.2.0/24"})
    assert response.headers["Location"].endswith("/settings/networks")


def test_domain_admin_sidebar(app, client, data):  # noqa: F811
    from crassostrea.services import accounts
    accounts.create_admin("dana", "dana-password", role="domain", domains=["example.com"])
    db.session.commit()
    client.post("/login", data={"username": "dana", "password": "dana-password"})
    page = client.get("/quarantine/").get_data(as_text=True)
    sidebar = page.split('<nav class="sidebar">')[1].split("</nav>")[0]
    for label in ("Dashboard", "Quarantine", "Mail log", "Domains", "Users"):
        assert f">{label}</a>" in sidebar
    for label in ("Statistics", "Protection", "Settings", "Access", "Monitoring", "Rspamd UI"):
        assert label not in sidebar
    # the Users group leads them to the mailbox users, without the administrators' tab
    assert 'href="/mailboxes/"' in sidebar
    # a group with a single visible page shows no tabs
    for path in ("/mail-log/", "/domains/", "/mailboxes/"):
        assert "page-tabs" not in client.get(path).get_data(as_text=True), path


def test_allow_and_block_lists_are_separate(logged_in):
    logged_in.post("/lists/", data={"list_type": "allow", "kind": "sender", "value": "friend@partner.org"},
                   follow_redirects=True)
    response = logged_in.post("/lists/", data={"list_type": "block", "kind": "sender", "value": "spam.example"})
    assert response.headers["Location"].endswith("/lists/block")
    logged_in.get("/lists/block")  # shows the message
    allow = logged_in.get("/lists/allow").get_data(as_text=True)
    block = logged_in.get("/lists/block").get_data(as_text=True)
    assert "friend@partner.org" in allow and "spam.example" not in allow and "<h1>Allow list</h1>" in allow
    assert "spam.example" in block and "friend@partner.org" not in block and "<h1>Block list</h1>" in block
    assert 'name="list_type" value="block"' in block
    assert logged_in.get("/lists/").headers["Location"].endswith("/lists/allow")
