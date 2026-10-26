"""Release header, DKIM key management and signing of released outbound mail."""
import json

import dkim as dkimpy
import pytest

from crassostrea.extensions import db
from crassostrea.models import DkimKey, Domain, MailboxUser, QuarantineItem
from crassostrea.services import dkim, mailer
from crassostrea.services.headers import RELEASE_HEADER, prepend_header, remove_header
from crassostrea.services.quarantine import prepare_release

ORIGINAL = (b"From: Partner <news@partner.org>\r\nTo: alice@example.com\r\nSubject: Report\r\n"
            b"Date: Thu, 16 Oct 2026 10:00:00 +0000\r\nMessage-ID: <1@partner.org>\r\n\r\nHello\r\n")
OUTBOUND = (b"From: Clerk <clerk@example.com>\r\nTo: buyer@external.net\r\nSubject: Invoice\r\n"
            b"Date: Thu, 16 Oct 2026 10:00:00 +0000\r\nMessage-ID: <2@example.com>\r\n\r\nPlease pay\r\n")


def _dns(records):
    def lookup(name, timeout=5):
        return records.get(name.decode().rstrip(".")) if isinstance(name, bytes) else records.get(name)
    return lookup


def _txt(private_pem):
    return f"v=DKIM1; k=rsa; p={dkim.public_key_b64(private_pem)}".encode()


@pytest.fixture(scope="module")
def keypair():
    pem, _ = dkim.generate_private_key(2048)
    return pem


@pytest.fixture
def domain(app):
    d = Domain(name="example.com", destination_host="mx.internal")
    db.session.add(d)
    db.session.commit()
    return d


# --- headers ---------------------------------------------------------------

def test_prepend_keeps_line_endings_and_bytes():
    assert prepend_header(ORIGINAL, "X-Test", "a\r\nb") == b"X-Test: a b\r\n" + ORIGINAL
    lf = ORIGINAL.replace(b"\r\n", b"\n")
    assert prepend_header(lf, "X-Test", "v") == b"X-Test: v\n" + lf


def test_remove_header_only_touches_that_header():
    assert remove_header(ORIGINAL, RELEASE_HEADER) is ORIGINAL  # untouched when absent
    forged = b"X-Quarantine-Released: by admin\r\n  folded part\r\n" + ORIGINAL
    assert remove_header(forged, RELEASE_HEADER) == ORIGINAL
    spaced = b"x-quarantine-released : fake\r\n" + ORIGINAL
    assert remove_header(spaced, RELEASE_HEADER) == ORIGINAL
    body_mention = ORIGINAL + b"X-Quarantine-Released: in the body stays\r\n"
    assert remove_header(body_mention, RELEASE_HEADER) is body_mention


def _item(raw, direction="inbound", rcpt="alice@example.com"):
    item = QuarantineItem(rcpt=rcpt, domain=rcpt.split("@")[1], direction=direction, subject="s",
                          sender="news@partner.org", symbols=json.dumps([]), message=raw)
    db.session.add(item)
    db.session.commit()
    return item


def test_release_keeps_original_senders_signature_valid(app, domain, keypair):
    signed = dkimpy.sign(ORIGINAL, b"s1", b"partner.org", keypair.encode()) + ORIGINAL
    item = _item(b"X-Quarantine-Released: forged\r\n" + signed)
    message, signed_by = prepare_release(item, "admin")
    assert signed_by is None
    assert message.startswith(b"X-Quarantine-Released: ")
    assert b"by admin on" in message.split(b"\r\n", 1)[0]
    assert message.count(b"X-Quarantine-Released") == 1
    assert dkimpy.verify(message, dnsfunc=_dns({"s1._domainkey.partner.org": _txt(keypair)}))


def test_outbound_release_header_hides_admin(app, domain):
    item = _item(OUTBOUND, direction="outbound", rcpt="buyer@external.net")
    message, signed_by = prepare_release(item, "secret-admin")
    assert b"secret-admin" not in message and signed_by is None  # no key configured


# --- DKIM keys -------------------------------------------------------------

def test_generate_key_via_ui_publishes_to_redis(logged_in, domain, fake_redis):
    response = logged_in.post(f"/domains/{domain.id}/dkim", data={"dkim-selector": "SF202610", "dkim-key_size": "2048"})
    assert response.status_code == 302
    key = DkimKey.query.one()
    assert key.selector == "sf202610" and key.key_size == 2048
    assert key.private_key.startswith("-----BEGIN RSA PRIVATE KEY-----")
    assert fake_redis.hget("DKIM_SELECTORS", "example.com") == "sf202610"
    assert fake_redis.hget("DKIM_PRIV_KEYS", "sf202610.example.com") == key.private_key

    page = logged_in.get(f"/domains/{domain.id}").data
    assert b"sf202610._domainkey.example.com" in page
    assert dkim.public_key_b64(key.private_key).encode() in page
    assert b"BEGIN RSA PRIVATE KEY" not in page  # private key is never shown


def test_rotate_and_delete_key(logged_in, domain, fake_redis):
    logged_in.post(f"/domains/{domain.id}/dkim", data={"dkim-selector": "old", "dkim-key_size": "2048"})
    logged_in.post(f"/domains/{domain.id}/dkim", data={"dkim-selector": "new", "dkim-key_size": "2048"})
    assert DkimKey.query.one().selector == "new"
    assert set(fake_redis.hkeys("DKIM_PRIV_KEYS")) == {"new.example.com"}
    logged_in.post(f"/domains/{domain.id}/dkim/delete")
    assert DkimKey.query.count() == 0
    assert fake_redis.hkeys("DKIM_PRIV_KEYS") == [] and fake_redis.hkeys("DKIM_SELECTORS") == []


def test_import_key(logged_in, domain, keypair):
    from cryptography.hazmat.primitives import serialization
    pkcs8 = serialization.load_pem_private_key(keypair.encode(), None).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    logged_in.post(f"/domains/{domain.id}/dkim/import",
                   data={"dkimimport-selector": "legacy", "dkimimport-private_key": pkcs8})
    key = DkimKey.query.one()
    assert key.selector == "legacy" and key.private_key == keypair  # normalised to PKCS#1


@pytest.mark.parametrize("selector,pem,message", [
    ("bad selector", None, b"may only contain"),
    ("ok", "not a key", b"not a valid unencrypted PEM"),
])
def test_invalid_key_input(logged_in, domain, selector, pem, message):
    if pem is None:
        response = logged_in.post(f"/domains/{domain.id}/dkim", follow_redirects=True,
                                  data={"dkim-selector": selector, "dkim-key_size": "2048"})
    else:
        response = logged_in.post(f"/domains/{domain.id}/dkim/import", follow_redirects=True,
                                  data={"dkimimport-selector": selector, "dkimimport-private_key": pem})
    assert message in response.data
    assert DkimKey.query.count() == 0


def test_mailbox_user_cannot_manage_keys(app, domain):
    user = MailboxUser(email="alice@example.com", domain=domain)
    user.set_password("alice-password")
    db.session.add(user)
    db.session.commit()
    client = app.test_client()
    client.post("/login", data={"username": "alice@example.com", "password": "alice-password"})
    assert client.post(f"/domains/{domain.id}/dkim", data={"dkim-selector": "x"}).status_code == 403


def test_domain_delete_removes_key_from_redis(logged_in, domain, fake_redis):
    logged_in.post(f"/domains/{domain.id}/dkim", data={"dkim-selector": "s", "dkim-key_size": "2048"})
    logged_in.post(f"/domains/{domain.id}/delete")
    assert DkimKey.query.count() == 0 and fake_redis.hkeys("DKIM_PRIV_KEYS") == []


# --- signing ---------------------------------------------------------------

def test_include_headers_oversigning():
    h = dkim.include_headers(["From", "To", "To", "Subject", "Date"])
    assert h.count(b"from") == 2       # (o): present once -> signed twice
    assert h.count(b"to") == 3         # (o): present twice -> signed three times
    assert h.count(b"reply-to") == 1   # (o): absent -> still signed once (cannot be added)
    assert h.count(b"date") == 2       # (x): present -> oversigned
    assert h.count(b"sender") == 0     # (x): absent -> not signed
    assert h.count(b"list-id") == 0    # plain: absent -> not signed


def test_released_outbound_mail_is_signed(app, domain, keypair, monkeypatch):
    db.session.add(DkimKey(domain=domain, selector="sf1", private_key=keypair, key_size=2048))
    db.session.commit()
    sent = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, msg: sent.append(msg))
    item = _item(OUTBOUND, direction="outbound", rcpt="buyer@external.net")

    client = app.test_client()
    client.post("/login", data={"username": "admin", "password": "initial-password"})
    response = client.post(f"/quarantine/{item.id}/action", data={"action": "release"}, follow_redirects=True)
    assert b"DKIM-signed for example.com" in response.data

    message = sent[0]
    assert message.startswith(b"DKIM-Signature:")
    dns = _dns({"sf1._domainkey.example.com": _txt(keypair)})
    assert dkimpy.verify(message, dnsfunc=dns)
    # oversigned From: a second From header added later breaks the signature
    head, body = message.split(b"\r\n\r\n", 1)
    assert not dkimpy.verify(head + b"\r\nFrom: ceo@example.com\r\n\r\n" + body, dnsfunc=dns)


def test_inbound_release_is_not_signed_by_gateway(app, domain, keypair):
    db.session.add(DkimKey(domain=domain, selector="sf1", private_key=keypair, key_size=2048))
    db.session.commit()
    # From a protected domain but inbound (e.g. spoofed): must not get our signature
    item = _item(OUTBOUND.replace(b"buyer@external.net", b"alice@example.com"))
    message, signed_by = prepare_release(item, "admin")
    assert signed_by is None and b"DKIM-Signature" not in message


@pytest.mark.parametrize("from_header", [
    b"From: a@example.com, b@example.com",   # multiple addresses
    b"From: a@unknown.org",                   # no key for this domain
])
def test_ambiguous_or_foreign_from_is_not_signed(app, domain, keypair, from_header):
    db.session.add(DkimKey(domain=domain, selector="sf1", private_key=keypair, key_size=2048))
    db.session.commit()
    raw = OUTBOUND.replace(b"From: Clerk <clerk@example.com>", from_header)
    assert dkim.sign_outbound(raw) == (raw, None)
