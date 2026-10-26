"""Live regions: page fragments for the periodic refresh and in-place forms."""
import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, MailboxUser
from crassostrea.services import accounts, postfix_control

from test_pages import backends_up, data  # noqa: F401 - fixtures

LIVE = {"X-Live-Fragment": "1"}
PAGES = ["/", "/queue/", "/logs", "/mail-log/", "/bans", "/lists/allow", "/lists/block", "/admins/", "/mailboxes/", "/quarantine/"]


@pytest.mark.parametrize("path", PAGES)
def test_full_page_and_fragment(logged_in, backends_up, data, path):  # noqa: F811
    page = logged_in.get(path)
    assert page.status_code == 200 and b"<html" in page.data and b"data-live" in page.data
    assert "X-Live-Fragment" in page.headers.get("Vary", "")

    fragment = logged_in.get(path, headers=LIVE)
    assert fragment.status_code == 200 and fragment.headers["X-Live-Fragment"] == "1"
    assert fragment.headers["Cache-Control"] == "no-store"
    assert b"<html" not in fragment.data and b"sidebar" not in fragment.data
    assert b"<script" not in fragment.data


def test_fragment_needs_login(client):
    response = client.get("/queue/", headers=LIVE)
    assert response.status_code == 302 and "/login" in response.headers["Location"]
    assert "X-Live-Fragment" not in response.headers


def test_async_action_returns_fragment_with_message(logged_in, backends_up, monkeypatch):  # noqa: F811
    calls = []
    monkeypatch.setattr(postfix_control, "queue_action", lambda task, ids=None: calls.append((task, ids)))
    # the browser follows the redirect back to the page and keeps the header
    response = logged_in.post("/queue/action", data={"action": "hold", "ids": ["4F3A2B1C"]}, headers=LIVE,
                              follow_redirects=True)
    assert calls == [("hold", ["4F3A2B1C"])]
    assert response.headers["X-Live-Fragment"] == "1"
    assert b"Messages put on hold." in response.data and b"<html" not in response.data
    # the message was shown in the fragment, not again on the next page
    assert b"Messages put on hold." not in logged_in.get("/queue/").data


def test_mailbox_actions_return_to_the_filtered_list(logged_in):
    for name in ("example.com", "example.org"):
        db.session.add(Domain(name=name, destination_host="mx.internal"))
    db.session.commit()
    accounts.create_mailbox_user("alice@example.com", "a-long-password")
    accounts.create_mailbox_user("bob@example.org", "a-long-password")
    db.session.commit()
    alice = MailboxUser.query.filter_by(email="alice@example.com").one()
    page = "/mailboxes/?domain=example.com"
    response = logged_in.post(f"/mailboxes/{alice.id}/toggle", data={"next": page}, headers=LIVE,
                              follow_redirects=True)
    assert b"alice@example.com disabled." in response.data
    assert b"alice@example.com" in response.data and b"bob@example.org" not in response.data
    assert logged_in.post(f"/mailboxes/{alice.id}/toggle", data={"next": "https://evil.example/"}
                          ).headers["Location"] == "/mailboxes/"


def test_admin_sets_mailbox_password_with_the_same_rules(logged_in):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    db.session.commit()
    user = accounts.create_mailbox_user("alice@example.com", "a-long-password")
    db.session.commit()
    response = logged_in.post(f"/mailboxes/{user.id}/password", data={"pw-password": "another-long-password"},
                              follow_redirects=True)
    assert b"Password of alice@example.com changed." in response.data
    db.session.refresh(user)
    assert user.check_password("another-long-password")


def test_personal_entries_are_not_shown_as_global(logged_in):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    db.session.commit()
    user = accounts.create_mailbox_user("alice@example.com", "a-long-password")
    accounts.add_user_list_entry(user, "allow", "friend@partner.org")
    db.session.commit()
    assert b"friend@partner.org" not in logged_in.get("/lists/allow").data
