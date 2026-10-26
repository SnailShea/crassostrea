"""Per-mailbox-user thresholds and allow/block lists."""
import json
import re

import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, ListEntry, MailboxUser, QuarantineItem
from crassostrea.services import maps
from crassostrea.services.maps import _owner_selector, render_rspamd_settings


@pytest.fixture
def domain(app):
    d = Domain(name="example.com", destination_host="mx.internal")
    db.session.add(d)
    db.session.commit()
    return d


@pytest.fixture
def alice(domain):
    user = MailboxUser(email="alice@example.com", domain=domain)
    user.set_password("alice-password")
    db.session.add(user)
    db.session.commit()
    return user


@pytest.fixture
def alice_client(app, alice):
    client = app.test_client()
    client.post("/login", data={"username": "alice@example.com", "password": "alice-password"})
    return client


def _rule(ucl, name):
    match = re.search(rf"  {name} {{\n(.*?)\n  }}\n", ucl, re.S)
    return match.group(1) if match else None


def test_priority_order():
    assert (maps.PRIO_WATCHDOG > maps.PRIO_DOMAIN_BLOCK > maps.PRIO_USER_BLOCK > maps.PRIO_USER_ALLOW
            > maps.PRIO_DOMAIN_ALLOW > maps.PRIO_USER_SCORES > maps.PRIO_DOMAIN_SCORES > maps.PRIO_GLOBAL_SCORES)


def test_owner_selector():
    assert _owner_selector("alice@example.com") == 'sf_rcpts_owned_by("alice@example.com")'
    assert _owner_selector("o'neil+x@example.com") == 'sf_rcpts_owned_by("o\'neil+x@example.com")'


@pytest.mark.parametrize("email", ['a"b@example.com', "a\\b@example.com", "a b@example.com", "a)b@example.com"])
def test_owner_selector_rejects_unquotable_addresses(email):
    assert _owner_selector(email) is None


def test_user_rules_never_use_any_recipient_matching(app, alice):
    # rcpt matches if any recipient matches: alice's rules would apply to
    # everyone else on the same message
    alice.reject_score = 20
    alice.list_entries.append(ListEntry(list_type="allow", kind="sender", value="*@partner.org"))
    db.session.commit()
    ucl = render_rspamd_settings()
    for name in (f"user_scores_{alice.id}", f"user_allow_{alice.id}_from", f"user_allow_{alice.id}_mime"):
        rule = _rule(ucl, name)
        assert 'selector = "sf_rcpts_owned_by(\\"alice@example.com\\")";' in rule
        assert "rcpt =" not in rule


def test_user_sets_own_thresholds(alice_client, alice):
    response = alice_client.post("/my/settings", data={"settings-reject_score": "20", "settings-add_header_score": "",
                                                       "settings-greylist_score": "", "settings-digest_interval": "weekly"},
                                 follow_redirects=True)
    assert b"Settings saved" in response.data
    db.session.refresh(alice)
    assert alice.reject_score == 20 and alice.digest_interval == "weekly"
    rule = _rule(render_rspamd_settings(), f"user_scores_{alice.id}")
    assert rule is not None
    assert f"priority = {maps.PRIO_USER_SCORES};" in rule
    assert "reject = 20;" in rule and '"add header" = 8;' in rule  # rest from the defaults


@pytest.mark.parametrize("data,message", [
    ({"settings-reject_score": "500"}, b"between 1 and 50"),
    ({"settings-reject_score": "5"}, b"Thresholds must satisfy"),
    ({"settings-digest_interval": "monthly"}, b"Not a valid choice"),
])
def test_user_threshold_validation(alice_client, alice, data, message):
    response = alice_client.post("/my/settings", data=data, follow_redirects=True)
    assert message in response.data
    db.session.refresh(alice)
    assert alice.reject_score is None and alice.digest_interval is None


def test_admin_may_set_values_outside_user_range(logged_in, alice):
    logged_in.post(f"/mailboxes/{alice.id}/settings", data={"settings-reject_score": "500"})
    db.session.refresh(alice)
    assert alice.reject_score == 500
    page = logged_in.get(f"/mailboxes/{alice.id}").data
    assert b"alice@example.com" in page and b"between 1 and 50" not in page


def test_user_list_entries(alice_client, alice):
    alice_client.post("/my/settings/entries", data={"entry-list_type": "allow", "entry-value": "@partner.org"})
    alice_client.post("/my/settings/entries", data={"entry-list_type": "block", "entry-value": "spam@x.org"})
    response = alice_client.post("/my/settings/entries", data={"entry-list_type": "allow", "entry-value": "partner.org"},
                                 follow_redirects=True)
    assert b"already exists" in response.data
    assert ListEntry.query.filter_by(mailbox_user_id=alice.id).count() == 2

    ucl = render_rspamd_settings()
    allow = _rule(ucl, f"user_allow_{alice.id}_from")
    block = _rule(ucl, f"user_block_{alice.id}_mime")
    assert f"priority = {maps.PRIO_USER_ALLOW};" in allow and "DOMAIN_ALLOWLIST = -999;" in allow
    assert 'selector = "sf_rcpts_owned_by(\\"alice@example.com\\")";' in allow
    assert f"priority = {maps.PRIO_USER_BLOCK};" in block and "DOMAIN_BLOCKLIST = 999;" in block
    assert ucl.count("{") == ucl.count("}")

    entry = ListEntry.query.filter_by(list_type="block").one()
    alice_client.post(f"/my/settings/entries/{entry.id}/delete")
    assert ListEntry.query.count() == 1


def test_user_cannot_touch_other_users_entries(alice_client, domain):
    bob = MailboxUser(email="bob@example.com", domain=domain)
    bob.set_password("bob-password1")
    bob.list_entries.append(ListEntry(list_type="allow", kind="sender", value="*@bob.org"))
    db.session.add(bob)
    db.session.commit()
    entry_id = bob.list_entries[0].id
    alice_client.post(f"/my/settings/entries/{entry_id}/delete")
    assert db.session.get(ListEntry, entry_id) is not None


def test_disabled_users_have_no_rules(logged_in, alice):
    alice.reject_score = 20
    db.session.commit()
    assert f"user_scores_{alice.id}" in render_rspamd_settings()
    logged_in.post(f"/mailboxes/{alice.id}/toggle")
    assert f"user_scores_{alice.id}" not in render_rspamd_settings()


def test_user_changes_bump_settings_map_version(alice_client, alice, internal_app):
    from crassostrea.models import get_setting
    before = get_setting("config_updated_at")
    alice_client.post("/my/settings/entries", data={"entry-list_type": "allow", "entry-value": "a@b.org"})
    assert get_setting("config_updated_at") > before


def test_portal_shows_sub_address_items(alice_client, domain):
    for rcpt, subject in [("alice+news@example.com", "Tagged"), ("abc+1@example.com", "Other"),
                          ("alice@example.com", "Plain")]:
        db.session.add(QuarantineItem(rcpt=rcpt, domain="example.com", subject=subject,
                                      symbols=json.dumps([]), message=b"x"))
    db.session.commit()
    page = alice_client.get("/my/").data
    assert b"Tagged" in page and b"Plain" in page and b"Other" not in page


def test_like_wildcards_in_address_are_escaped(app, domain):
    user = MailboxUser(email="a_c@example.com", domain=domain)
    user.set_password("x" * 12)
    db.session.add(user)
    db.session.add(QuarantineItem(rcpt="abc+1@example.com", domain="example.com", symbols="[]", message=b"x"))
    db.session.commit()
    from crassostrea.services.quarantine import owned_by
    assert QuarantineItem.query.filter(owned_by("a_c@example.com")).count() == 0


def test_settings_pages_render(alice_client, logged_in, alice):
    assert b"Allow &amp; block list" in alice_client.get("/my/settings").data
    assert logged_in.get(f"/mailboxes/{alice.id}").status_code == 200
    assert alice_client.get(f"/mailboxes/{alice.id}").status_code == 302
