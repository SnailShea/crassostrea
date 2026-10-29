"""Quarantine digests.

Every recipient with new inbound quarantined mail receives a summary mail at
the effective interval: mailbox user override -> domain -> global setting.
Recipients do not need an account; the digest contains a link with a token
that opens their quarantine in the web interface (views/token.py).

Run periodically with ``flask --app crassostrea send-digests`` (crassostrea-job-digests.timer).
"""
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from flask import current_app, render_template

from ..extensions import db
from ..models import (DIGEST_SECONDS, AccountToken, DigestState, DigestToken, Domain, MailboxUser, QuarantineItem,
                      get_setting, hash_token, utcnow)
from . import mailer
from .branding import get_branding, text_on
from .quarantine import base_address


def sender_address():
    return get_setting("digest_sender") or f"quarantine@{current_app.config['HOSTNAME']}"


def effective_interval(domain, user=None):
    if user is not None and user.digest_interval:
        return user.digest_interval
    if domain is not None and domain.digest_interval:
        return domain.digest_interval
    return get_setting("digest_interval")


def pending_by_address():
    """{base address: [inbound items, newest first]}"""
    items = (QuarantineItem.query
             .filter(QuarantineItem.direction == "inbound")
             .order_by(QuarantineItem.created_at.desc()).all())
    grouped = {}
    for item in items:
        grouped.setdefault(base_address(item.rcpt), []).append(item)
    return grouped


def due_digests(now=None):
    """[(address, new items, all pending items)] that should be sent now."""
    now = now or utcnow()
    domains = {d.name: d for d in Domain.query.filter_by(active=True)}
    users = {u.email: u for u in MailboxUser.query}
    states = {s.rcpt: s for s in DigestState.query}
    due = []
    for address, items in pending_by_address().items():
        domain = domains.get(address.rsplit("@", 1)[1])
        user = users.get(address)
        if domain is None or (user is not None and not user.active):
            continue
        seconds = DIGEST_SECONDS.get(effective_interval(domain, user))
        if not seconds:
            continue
        state = states.get(address)
        if state is not None and now - state.last_sent_at < timedelta(seconds=seconds):
            continue
        since = state.last_sent_at if state is not None else now - timedelta(seconds=seconds)
        new_items = [i for i in items if i.created_at > since]
        if new_items:
            due.append((address, new_items, items))
    return due


def build_message(address, token, new_items, pending):
    base = current_app.config["PUBLIC_URL"]
    brand = get_branding()
    accent = brand["accent"] or "#2557d6"
    context = {
        "brand": brand,
        "accent": accent,
        "accent_text": text_on(accent),
        "logo_url": f"{base}/branding/logo?v={brand['version']}" if brand["has_logo"] else None,
        "address": address,
        "new_items": new_items,
        "pending_count": len(pending),
        "manage_url": f"{base}/q/{token}/",
        "item_url": lambda item: f"{base}/q/{token}/{item.id}",
        "valid_days": get_setting("digest_token_days"),
        "hostname": current_app.config["HOSTNAME"],
    }
    msg = EmailMessage()
    msg["From"] = formataddr((brand["name"], sender_address()))
    msg["To"] = address
    msg["Subject"] = f"Quarantine digest: {len(new_items)} new message(s) held for {address}"
    msg["Date"] = formatdate(localtime=False, usegmt=True)
    msg["Message-ID"] = make_msgid(domain=current_app.config["HOSTNAME"])
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Auto-Response-Suppress"] = "All"
    msg.set_content(render_template("emails/digest.txt", **context))
    msg.add_alternative(render_template("emails/digest.html", **context), subtype="html")
    return msg


def send_digest(address, new_items, pending, now=None):
    """Create a token, send the mail and record the state. Raises mailer.ReleaseError."""
    now = now or utcnow()
    token_row, token = DigestToken.create(address, now + timedelta(days=get_setting("digest_token_days")))
    message = build_message(address, token, new_items, pending)
    mailer.reinject(sender_address(), address, message.as_bytes())
    db.session.add(token_row)
    state = db.session.get(DigestState, address)
    if state is None:
        db.session.add(DigestState(rcpt=address, last_sent_at=now))
    else:
        state.last_sent_at = now
    db.session.commit()


def send_due_digests(now=None):
    """Returns (sent addresses, {address: error})."""
    sent, failed = [], {}
    for address, new_items, pending in due_digests(now):
        try:
            send_digest(address, new_items, pending, now)
            sent.append(address)
        except mailer.ReleaseError as exc:
            db.session.rollback()
            failed[address] = str(exc)
            current_app.logger.error("digest for %s failed: %s", address, exc)
    return sent, failed


def resolve_token(token):
    """Valid DigestToken for a token string, or None."""
    if not token or len(token) > 128:
        return None
    row = DigestToken.query.filter_by(token_hash=hash_token(token)).first()
    if row is None or row.expires_at < utcnow():
        return None
    user = MailboxUser.query.filter_by(email=row.rcpt).first()
    if user is not None and not user.active:
        return None
    return row


def cleanup_tokens():
    """Expired digest tokens and expired or used links to set a password."""
    now = utcnow()
    expired = DigestToken.query.filter(DigestToken.expires_at < now).delete(synchronize_session=False)
    return expired + AccountToken.query.filter(db.or_(AccountToken.expires_at < now, AccountToken.used_at.isnot(None))
                                               ).delete(synchronize_session=False)
