"""Domain administrators: what they see and may do, and how they are managed."""


import pytest

from crassostrea.extensions import db
from crassostrea.models import (Admin, Domain, MailboxUser, MailLogEntry, QuarantineItem, StatBucket, utcnow)
from crassostrea.services import accounts, mailer
from crassostrea.services.errors import ServiceError

RAW = b"From: a@x.example\r\nSubject: Hi\r\n\r\nHello\r\n"


@pytest.fixture
def world(app):
    """Two domains with mail; dana administers one of them."""
    mine = Domain(name="mine.example", destination_host="mx.internal")
    other = Domain(name="other.example", destination_host="mx.internal")
    db.session.add_all([mine, other])
    db.session.flush()
    dana = accounts.create_admin("dana", "dana-password", role="domain", domains=["mine.example"])
    items = {
        "q_mine": QuarantineItem(rcpt="bob@mine.example", domain="mine.example", message=RAW, symbols="[]"),
        "q_other": QuarantineItem(rcpt="eve@other.example", domain="other.example", message=RAW, symbols="[]"),
        "l_mine": MailLogEntry(direction="inbound", sender="a@x.example", rcpts="bob@mine.example,eve@other.example",
                               action="no action", message=RAW, subject="to both"),
        "l_out": MailLogEntry(direction="outbound", sender="bob@mine.example", rcpts="x@partner.example",
                              action="no action", message=RAW, subject="from mine"),
        "l_other": MailLogEntry(direction="inbound", sender="a@x.example", rcpts="eve@other.example",
                                action="no action", message=RAW, subject="other only"),
    }
    users = [MailboxUser(email="bob@mine.example", domain=mine), MailboxUser(email="eve@other.example", domain=other)]
    for user in users:
        user.set_password("user-password")
    db.session.add_all([*items.values(), *users])
    hour = utcnow().replace(minute=0, second=0, microsecond=0)
    db.session.add_all([StatBucket(hour=hour, domain=d, direction="inbound", category="clean", messages=n, bytes=0,
                                   viruses=0) for d, n in (("mine.example", 3), ("other.example", 7))])
    db.session.commit()
    return {"dana": dana, "mine": mine, "other": other, **items, "users": users}


@pytest.fixture
def dana(client, world):
    response = client.post("/login", data={"username": "dana", "password": "dana-password"})
    assert response.status_code == 302
    return client


def test_navigation_and_system_pages(dana):
    assert dana.get("/").status_code == 200  # the dashboard, of their domains
    page = dana.get("/quarantine/").get_data(as_text=True)
    assert 'href="/mail-log/"' in page and 'href="/domains/"' in page and 'href="/settings/"' not in page
    for path in ("/settings/", "/admins/", "/api-keys/", "/backups/", "/audit/", "/monitoring/", "/lists/"):
        response = dana.get(path)
        assert response.status_code == 302 and response.headers["Location"].endswith("/quarantine/"), path
    assert dana.post("/settings/networks", data={"net-cidr": "192.0.2.0/24"}).status_code == 403


def test_quarantine(dana, world, monkeypatch):
    page = dana.get("/quarantine/").get_data(as_text=True)
    assert "bob@mine.example" in page and "eve@other.example" not in page
    assert dana.get(f"/quarantine/{world['q_other'].id}").status_code == 404
    assert dana.get(f"/quarantine/{world['q_mine'].id}").status_code == 200
    monkeypatch.setattr(mailer, "reinject", lambda *a: None)
    dana.post("/quarantine/bulk", data={"ids": [world["q_mine"].id, world["q_other"].id], "action": "delete"})
    assert [i.domain for i in QuarantineItem.query.all()] == ["other.example"]


def test_mail_log(dana, world, monkeypatch):
    page = dana.get("/mail-log/").get_data(as_text=True)
    assert "to both" in page and "from mine" in page and "other only" not in page
    assert dana.get(f"/mail-log/{world['l_other'].id}").status_code == 404
    sent = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, message: sent.append(rcpt))
    # re-delivered only to its own recipients
    dana.post(f"/mail-log/{world['l_mine'].id}/requeue", data={"rcpts": ["bob@mine.example", "eve@other.example"]})
    assert sent == ["bob@mine.example"]
    # outbound mail of its domain may go to its outside recipients
    dana.post(f"/mail-log/{world['l_out'].id}/requeue", data={"rcpts": ["x@partner.example"]})
    assert sent[-1] == "x@partner.example"
    response = dana.post(f"/mail-log/{world['l_mine'].id}/requeue", data={"rcpts": ["eve@other.example"]},
                         follow_redirects=True)
    assert "None of the chosen recipients is in your domains" in response.get_data(as_text=True)


def test_domains(dana, world):
    page = dana.get("/domains/").get_data(as_text=True)
    assert "mine.example" in page and "other.example" not in page and "Add domain" not in page
    assert dana.get(f"/domains/{world['other'].id}").status_code == 404
    assert dana.get("/domains/new").status_code == 403
    assert dana.post(f"/domains/{world['mine'].id}/delete").status_code == 403
    response = dana.post(f"/domains/{world['mine'].id}", data={"destination_host": "mx2.internal",
                                                              "destination_port": "25", "recipient_check": "any",
                                                              "active": "y"})
    assert response.status_code == 302 and db.session.get(Domain, world["mine"].id).destination_host == "mx2.internal"
    assert dana.post(f"/domains/{world['other'].id}/recipients", data={"rcpt-addresses": "x"}).status_code == 404


def test_mailbox_users(dana, world):
    page = dana.get("/mailboxes/").get_data(as_text=True)
    assert "bob@mine.example" in page and "eve@other.example" not in page
    other_user = world["users"][1]
    assert dana.get(f"/mailboxes/{other_user.id}").status_code == 404
    response = dana.post("/mailboxes/", data={"email": "new@other.example", "password": "a-long-password",
                                              "confirm": "a-long-password"})
    assert "only add users of your own domains" in response.get_data(as_text=True)
    assert MailboxUser.query.filter_by(email="new@other.example").first() is None
    dana.post("/mailboxes/", data={"email": "new@mine.example", "password": "a-long-password",
                                   "confirm": "a-long-password"})
    assert MailboxUser.query.filter_by(email="new@mine.example").first() is not None


def test_statistics_and_reports(dana, world):
    page = dana.get("/?range=24h").get_data(as_text=True)
    assert '<div class="value">3</div>' in page
    # neither in the domain filter nor in the busiest domains
    assert 'value="other.example"' not in page and ">other.example</a>" not in page
    assert "Health" not in page and "Messages learned" not in page  # full administrators only
    assert "Mail queue" not in page and "System load" not in page and "Processing time" in page
    page = dana.get("/?range=24h&domain=other.example").get_data(as_text=True)
    assert '<div class="value">3</div>' in page
    page = dana.get("/reports/").get_data(as_text=True)
    assert "mine.example" in page and "other.example" not in page and "report_retention_days" not in page
    assert dana.post("/reports/settings", data={"report_retention_days": "30"}).status_code == 403


def test_managing_access(logged_in, world):
    page = logged_in.get("/admins/").get_data(as_text=True)
    assert "Domains: mine.example" in page
    response = logged_in.post("/admins/", data={"username": "otto", "password": "otto-password-1",
                                                "confirm": "otto-password-1", "role": "domain"})
    assert "Choose the domains" in response.get_data(as_text=True)
    logged_in.post("/admins/", data={"username": "otto", "password": "otto-password-1",
                                     "confirm": "otto-password-1", "role": "domain",
                                     "domains": ["mine.example", "other.example"]})
    otto = Admin.query.filter_by(username="otto").one()
    assert [d.name for d in otto.domains] == ["mine.example", "other.example"] and not otto.is_full_admin
    logged_in.post(f"/admins/{otto.id}", data={"role": "admin"})
    assert db.session.get(Admin, otto.id).is_full_admin
    me = Admin.query.filter_by(username="admin").one()
    response = logged_in.post(f"/admins/{me.id}", data={"role": "domain", "domains": ["mine.example"]})
    assert response.status_code == 400 and "your own role" in response.get_data(as_text=True)


def test_last_full_admin_stays(app, world):
    admin = Admin.query.filter_by(username="admin").one()
    # dana does not count as an administrator who could take over
    with pytest.raises(ServiceError, match="At least one active administrator"):
        accounts.update_admin(admin, role="domain", domains=["mine.example"])
    db.session.rollback()
    with pytest.raises(ServiceError, match="At least one active administrator"):
        accounts.delete_admin(Admin.query.filter_by(username="admin").one())
    db.session.rollback()
    # a domain administrator can always be removed
    accounts.delete_admin(Admin.query.filter_by(username="dana").one())
    db.session.commit()


def test_api(api, world):
    body = api("POST", "/admins", json={"username": "dora", "password": "dora-password-1", "role": "domain",
                                        "domains": ["other.example"]}).get_json()
    assert (body["role"], body["domains"]) == ("domain", ["other.example"])
    assert api("POST", "/admins", json={"username": "x1", "password": "x1-password-12", "role": "domain",
                                        "domains": ["nope.example"]}).status_code == 422
    assert api("POST", "/admins", json={"username": "x2", "password": "x2-password-12",
                                        "role": "root"}).status_code == 422
    body = api("PATCH", f"/admins/{body['id']}", json={"domains": ["mine.example", "other.example"]}).get_json()
    assert body["domains"] == ["mine.example", "other.example"]


