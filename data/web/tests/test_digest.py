"""Quarantine digests and token access."""
import email
import email.policy
import json
import re
from datetime import timedelta

import pytest

from crassostrea.extensions import db
from crassostrea.models import (DigestState, DigestToken, Domain, MailboxUser, QuarantineItem, set_setting,
                               utcnow)
from crassostrea.services import digest, mailer


@pytest.fixture
def domain(app):
    d = Domain(name="example.com", destination_host="mx.internal")
    db.session.add(d)
    db.session.commit()
    return d


@pytest.fixture
def outbox(monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, msg: sent.append((sender, rcpt, msg)))
    return sent


def _item(rcpt="alice@example.com", subject="Cheap pills", virus=False, age=timedelta(0), direction="inbound"):
    symbols = [{"name": "CLAM_VIRUS", "score": 0}] if virus else []
    item = QuarantineItem(rcpt=rcpt, domain=rcpt.split("@")[1], subject=subject, sender="spam@bad.example",
                          symbols=json.dumps(symbols), message=b"Subject: x\r\n\r\nbody\r\n",
                          created_at=utcnow() - age, direction=direction)
    db.session.add(item)
    db.session.commit()
    return item


def _token(message_bytes):
    return re.search(rb"/q/([A-Za-z0-9_-]{20,})", message_bytes).group(1).decode()


# --- interval resolution ------------------------------------------------------

def test_effective_interval(domain):
    user = MailboxUser(email="alice@example.com")  # not persisted, only the override matters
    assert digest.effective_interval(domain, user) == "daily"       # global default
    domain.digest_interval = "weekly"
    assert digest.effective_interval(domain, user) == "weekly"      # domain override
    user.digest_interval = "hourly"
    assert digest.effective_interval(domain, user) == "hourly"      # user override
    user.digest_interval = None
    domain.digest_interval = None
    set_setting("digest_interval", "never")
    assert digest.effective_interval(domain, user) == "never"


# --- sending ------------------------------------------------------------------

def test_digest_sent_once_per_interval(app, domain, outbox):
    _item()
    _item(rcpt="alice+news@example.com", subject="Tagged")
    _item(rcpt="alice@example.com", direction="outbound", subject="Outbound")
    sent, failed = digest.send_due_digests()
    assert sent == ["alice@example.com"] and not failed
    sender, rcpt, raw = outbox[0]
    assert sender == "quarantine@localhost" and rcpt == "alice@example.com"
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    assert msg["Auto-Submitted"] == "auto-generated"
    text = msg.get_body(("plain",)).get_content()
    assert "Cheap pills" in text and "Tagged" in text and "Outbound" not in text
    assert f"https://localhost/q/{_token(raw)}" in text
    assert db.session.get(DigestState, "alice@example.com") is not None
    assert DigestToken.query.count() == 1

    # nothing new / interval not elapsed
    assert digest.send_due_digests() == ([], {})
    _item(subject="Later")
    assert digest.send_due_digests() == ([], {})
    # after the interval only the new item is listed
    later = utcnow() + timedelta(days=1, minutes=1)
    sent, _ = digest.send_due_digests(now=later)
    assert sent == ["alice@example.com"]
    text = email.message_from_bytes(outbox[1][2], policy=email.policy.default).get_body(("plain",)).get_content()
    assert "Later" in text and "Cheap pills" not in text


def test_html_part_is_escaped(app, domain, outbox):
    _item(subject="<script>alert(1)</script>")
    digest.send_due_digests()
    html = email.message_from_bytes(outbox[0][2], policy=email.policy.default).get_body(("html",)).get_content()
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html


@pytest.mark.parametrize("setup", ["global_never", "domain_never", "user_never", "user_disabled",
                                   "domain_disabled"])
def test_no_digest(app, domain, outbox, setup):
    _item()
    user = MailboxUser(email="alice@example.com", domain=domain)
    user.set_password("x" * 12)
    db.session.add(user)
    if setup == "global_never":
        set_setting("digest_interval", "never")
    elif setup == "domain_never":
        domain.digest_interval = "never"
    elif setup == "user_never":
        user.digest_interval = "never"
    elif setup == "user_disabled":
        user.active = False
    elif setup == "domain_disabled":
        domain.active = False
    db.session.commit()
    assert digest.send_due_digests() == ([], {})


def test_user_override_enables_digest(app, domain, outbox):
    set_setting("digest_interval", "never")
    user = MailboxUser(email="alice@example.com", domain=domain, digest_interval="hourly")
    user.set_password("x" * 12)
    db.session.add(user)
    db.session.commit()
    _item()
    assert digest.send_due_digests()[0] == ["alice@example.com"]


def test_send_failure_keeps_state(app, domain, monkeypatch):
    def broken(*args):
        raise mailer.ReleaseError("connection refused")
    monkeypatch.setattr(mailer, "reinject", broken)
    _item()
    sent, failed = digest.send_due_digests()
    assert sent == [] and "alice@example.com" in failed
    assert DigestState.query.count() == 0 and DigestToken.query.count() == 0


def test_cli_and_admin_button(app, logged_in, domain, outbox):
    _item()
    result = app.test_cli_runner().invoke(args=["send-digests"])
    assert "Sent 1 digest(s)" in result.output
    _item(rcpt="bob@example.com")
    response = logged_in.post("/settings/digests/send", follow_redirects=True)
    assert b"1 digest(s) sent" in response.data


# --- token access -------------------------------------------------------------

@pytest.fixture
def token(app, domain, outbox):
    _item()
    digest.send_due_digests()
    return _token(outbox[0][2])


def test_token_page_lists_only_own_items(app, token, outbox):
    _item(rcpt="bob@example.com", subject="Bobs mail")
    client = app.test_client()
    response = client.get(f"/q/{token}/")
    assert response.status_code == 200
    assert b"Cheap pills" in response.data and b"Bobs mail" not in response.data
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert response.headers["Cache-Control"] == "no-store"
    assert b"Log out" not in response.data  # no navigation for anonymous visitors


def test_get_never_changes_state(app, token, outbox):
    item = QuarantineItem.query.filter_by(subject="Cheap pills").one()
    client = app.test_client()
    assert client.get(f"/q/{token}/{item.id}").status_code == 200
    assert client.get(f"/q/{token}/{item.id}/action").status_code == 405
    db.session.expire_all()
    assert db.session.get(QuarantineItem, item.id) is not None and len(outbox) == 1


def test_token_release_and_delete(app, token, outbox):
    item = QuarantineItem.query.filter_by(subject="Cheap pills").one()
    item_id = item.id
    client = app.test_client()
    response = client.post(f"/q/{token}/{item_id}/action", data={"action": "release"}, follow_redirects=True)
    assert b"delivered to your mailbox" in response.data and b"Cheap pills" not in response.data  # the list
    assert outbox[-1][1] == "alice@example.com"
    assert b"by digest link (alice@example.com)" in outbox[-1][2].split(b"\r\n", 1)[0]
    db.session.expire_all()
    assert db.session.get(QuarantineItem, item_id) is None  # released: removed
    other = _item()
    client.post(f"/q/{token}/{other.id}/action", data={"action": "delete"})
    assert db.session.get(QuarantineItem, other.id) is None


def test_token_cannot_reach_other_items_or_viruses(app, token, outbox):
    foreign = _item(rcpt="bob@example.com")
    virus = _item(virus=True)
    client = app.test_client()
    assert client.get(f"/q/{token}/{foreign.id}").status_code == 404
    assert client.post(f"/q/{token}/{foreign.id}/action", data={"action": "delete"}).status_code == 404
    client.post(f"/q/{token}/bulk", data={"action": "release", "ids": [str(virus.id), str(foreign.id)]})
    assert len(outbox) == 1  # nothing released
    assert db.session.get(QuarantineItem, foreign.id) is not None


@pytest.mark.parametrize("case", ["unknown", "expired", "user_disabled"])
def test_invalid_tokens(app, token, domain, case):
    path = f"/q/{token}/"
    if case == "unknown":
        path = "/q/" + "x" * 43 + "/"
    elif case == "expired":
        DigestToken.query.one().expires_at = utcnow() - timedelta(seconds=1)
        db.session.commit()
    else:
        user = MailboxUser(email="alice@example.com", domain=domain, active=False)
        user.set_password("x" * 12)
        db.session.add(user)
        db.session.commit()
    response = app.test_client().get(path)
    assert response.status_code == 404 and b"no longer valid" in response.data


def test_deleting_the_mailbox_user_revokes_tokens(app, logged_in, token, domain):
    user = MailboxUser(email="alice@example.com", domain=domain)
    user.set_password("x" * 12)
    db.session.add(user)
    db.session.commit()
    assert app.test_client().get(f"/q/{token}/").status_code == 200
    logged_in.post(f"/mailboxes/{user.id}/delete")
    assert DigestToken.query.count() == 0
    assert app.test_client().get(f"/q/{token}/").status_code == 404


def test_access_log_redacts_tokens():
    import importlib.util
    from pathlib import Path
    from types import SimpleNamespace

    from gunicorn.config import Config
    spec = importlib.util.spec_from_file_location("gunicorn_conf", Path(__file__).parent.parent / "gunicorn.conf.py")
    conf = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(conf)
    logger = conf.logger_class(Config())
    environ = {"REQUEST_METHOD": "POST", "RAW_URI": "/q/AbC-12_x/17/action?x=1", "PATH_INFO": "/q/AbC-12_x/17/action",
               "SERVER_PROTOCOL": "HTTP/1.1", "HTTP_REFERER": "https://filter.example/q/AbC-12_x/"}
    atoms = logger.atoms(SimpleNamespace(status="302 FOUND", sent=0, headers=[]), [], environ, timedelta(0))
    assert atoms["r"] == "POST /q/[token]/17/action?x=1 HTTP/1.1"
    assert atoms["U"] == "/q/[token]/17/action" and atoms["f"] == "https://filter.example/q/[token]/"
    assert not any("AbC" in str(value) for value in atoms.values())
    assert conf._TOKEN_PATH.sub("/q/[token]", "/quarantine/5") == "/quarantine/5"


def test_cleanup_removes_expired_tokens(app, token):
    DigestToken.query.one().expires_at = utcnow() - timedelta(days=1)
    db.session.commit()
    result = app.test_cli_runner().invoke(args=["cleanup"])
    assert "1 expired digest token(s)" in result.output
    assert DigestToken.query.count() == 0


def test_token_is_stored_hashed(app, token):
    assert DigestToken.query.filter_by(token_hash=token).count() == 0
