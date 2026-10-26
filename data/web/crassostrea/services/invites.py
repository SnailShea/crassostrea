"""Mailbox accounts for recipients of quarantined mail, and links to set a
password.

With Settings -> create accounts for recipients of quarantined mail
(mailbox_auto_create), ``flask provision-accounts``
(crassostrea-job-accounts.timer, every 5 minutes) looks at the inbound mail
quarantined in the last day. A recipient without a mailbox user gets one when
the mailbox exists on the domain's destination server:

- recipient check "list" or "directory": an active entry in the recipients;
- "verify": Postfix verified the address with the destination server before
  it accepted the mail, so it exists;
- "any": the gateway asks the destination server (MAIL FROM:<>, RCPT TO). A
  server that also accepts a made-up address of the domain cannot tell, and
  no account is created.

The account gets a random password nobody knows and the recipient a mail with
a link to set one (AccountToken, valid for mailbox_invite_days). The answers
that did not create an account are kept for a day in Valkey, so a server is
not asked again on every run. Administrators send the same link from the
mailbox users page (``send_link``), also to reset a password.
"""
import secrets
import smtplib
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

from flask import current_app, render_template

from ..extensions import db
from ..models import AccountToken, Domain, MailboxUser, QuarantineItem, Recipient, get_setting, hash_token, utcnow
from . import accounts, mailer, store
from .branding import get_branding, text_on
from .destination import destinations
from .digest import sender_address
from .quarantine import base_address

CHECKED_PREFIX = "sf_invite_checked:"
CHECKED_SECONDS = 86400
# Quarantined mail of this age is looked at, at most this many recipients a run
WINDOW = timedelta(days=1)
MAX_PER_RUN = 100
CALLOUT_TIMEOUT = 20


class InviteError(Exception):
    pass


# ---------------------------------------------------------------------------
# Does the mailbox exist downstream?
# ---------------------------------------------------------------------------

def callout(domain, address):
    """Ask the destination server whether it has ``address``: True, False, or
    None when it cannot tell (no answer, 4xx, or it accepts any address)."""
    probe = f"sf-probe-{secrets.token_hex(8)}@{domain.name}"
    for host, port in destinations(domain):
        try:
            with smtplib.SMTP(host, port, timeout=CALLOUT_TIMEOUT,
                              local_hostname=current_app.config["HOSTNAME"]) as smtp:
                smtp.ehlo_or_helo_if_needed()
                code, _ = smtp.mail("")
                if code >= 400:
                    return None
                code, _ = smtp.rcpt(address)
                if code >= 500:
                    return False
                if not 200 <= code < 300:
                    return None
                probe_code, _ = smtp.rcpt(probe)
                return None if 200 <= probe_code < 300 else True
        except (OSError, smtplib.SMTPException):
            continue
    return None


def mailbox_exists(domain, address):
    if domain.recipient_check in ("list", "directory"):
        return Recipient.query.filter_by(address=address, active=True).first() is not None
    if domain.recipient_check == "verify":
        return True
    return callout(domain, address)


# ---------------------------------------------------------------------------
# Accounts and links
# ---------------------------------------------------------------------------

def candidates(now=None):
    """Base addresses of recent inbound quarantined mail without a mailbox
    user, on active domains: [(address, domain)]."""
    now = now or utcnow()
    rcpts = (db.session.query(QuarantineItem.rcpt)
             .filter(QuarantineItem.direction == "inbound", QuarantineItem.created_at >= now - WINDOW)
             .distinct().all())
    addresses = sorted({base_address(rcpt.lower()) for (rcpt,) in rcpts})
    if not addresses:
        return []
    existing = {email for (email,) in db.session.query(MailboxUser.email).filter(MailboxUser.email.in_(addresses))}
    domains = {d.name: d for d in Domain.query.filter_by(active=True)}
    result = []
    for address in addresses:
        domain = domains.get(address.rpartition("@")[2])
        if address not in existing and domain is not None:
            result.append((address, domain))
    return result


def build_message(user, token, invited, requested=False):
    base = current_app.config["PUBLIC_URL"]
    brand = get_branding()
    accent = brand["accent"] or "#2557d6"
    days = get_setting("mailbox_invite_days")
    context = {"brand": brand, "accent": accent, "accent_text": text_on(accent),
               "logo_url": f"{base}/branding/logo?v={brand['version']}" if brand["has_logo"] else None,
               "address": user.email, "link": f"{base}/account/set-password/{token}", "valid_days": days,
               "invited": invited, "requested": requested, "hostname": current_app.config["HOSTNAME"],
               "portal_url": f"{base}/login"}
    msg = EmailMessage()
    msg["From"] = formataddr((brand["name"], sender_address()))
    msg["To"] = user.email
    msg["Subject"] = (f"Your {brand['name']} account: set a password" if invited
                      else f"Set a new password for {brand['name']}")
    msg["Date"] = formatdate(localtime=False, usegmt=True)
    msg["Message-ID"] = make_msgid(domain=current_app.config["HOSTNAME"])
    msg["Auto-Submitted"] = "auto-generated"
    msg["X-Auto-Response-Suppress"] = "All"
    msg.set_content(render_template("emails/invite.txt", **context))
    msg.add_alternative(render_template("emails/invite.html", **context), subtype="html")
    return msg


def send_link(user, invited=False, now=None, requested=False):
    """A new link to set the password of ``user`` by mail; earlier links stop
    working. Raises InviteError when Postfix does not take the mail. The
    caller commits."""
    if not user.active:
        raise InviteError("The account is disabled")
    now = now or utcnow()
    AccountToken.query.filter_by(user_id=user.id, used_at=None).delete()
    row, token = AccountToken.create(user.id, now + timedelta(days=get_setting("mailbox_invite_days")))
    try:
        mailer.reinject(sender_address(), user.email, build_message(user, token, invited, requested).as_bytes())
    except mailer.ReleaseError as exc:
        raise InviteError(str(exc)) from exc
    db.session.add(row)
    if invited:
        user.invited_at = now
    return token


def provision(now=None):
    """Create the accounts of mailbox_auto_create. Returns (created
    addresses, {address: error})."""
    created, failed = [], {}
    if not get_setting("mailbox_auto_create"):
        return created, failed
    r = store.get_redis()
    for address, domain in candidates(now)[:MAX_PER_RUN]:
        if r.exists(CHECKED_PREFIX + address):
            continue
        exists = mailbox_exists(domain, address)
        if not exists:
            r.set(CHECKED_PREFIX + address, "0" if exists is False else "?", ex=CHECKED_SECONDS)
            continue
        try:
            user = accounts.create_mailbox_user(address, secrets.token_urlsafe(24))
            db.session.flush()
            send_link(user, invited=True, now=now)
            db.session.commit()
            created.append(address)
        except (accounts.AccountError, InviteError) as exc:
            db.session.rollback()
            failed[address] = str(exc)
            current_app.logger.error("account for %s not created: %s", address, exc)
    if created:
        from . import audit
        try:
            audit.record("mailbox_user.auto_create", target=", ".join(created[:20]),
                         message=f"{len(created)} account(s) for recipients of quarantined mail")
            db.session.commit()
        except Exception:  # the accounts exist either way
            db.session.rollback()
    return created, failed


# "Forgot password": links per address and per client address in an hour
RESET_PER_ADDRESS = 3
RESET_PER_IP = 10
RESET_PREFIX = "sf_pwreset:"


def request_reset(address, ip):
    """Mail a link to set a new password when ``address`` is an active
    mailbox user. The caller tells nobody whether it was: the answer is the
    same for any address. Returns True when a link was sent."""
    address = (address or "").strip().lower()
    if "@" not in address or len(address) > 320:
        return False
    r = store.get_redis()
    for key, limit in ((f"{RESET_PREFIX}addr:{address}", RESET_PER_ADDRESS), (f"{RESET_PREFIX}ip:{ip}", RESET_PER_IP)):
        count = r.incr(key)
        if count == 1:
            r.expire(key, 3600)
        if count > limit:
            current_app.logger.warning("password reset for %s from %s refused: too many requests", address, ip)
            return False
    user = MailboxUser.query.filter_by(email=address).first()
    if user is None or not user.active:
        return False
    try:
        send_link(user, requested=True)
    except InviteError as exc:
        db.session.rollback()
        current_app.logger.error("password reset link for %s not sent: %s", address, exc)
        return False
    db.session.commit()
    return True


def resolve(token):
    """(AccountToken, MailboxUser) of a valid, unused link, or (None, None)."""
    if not token or len(token) > 128:
        return None, None
    row = AccountToken.query.filter_by(token_hash=hash_token(token)).first()
    if row is None or row.used_at is not None or row.expires_at < utcnow():
        return None, None
    user = db.session.get(MailboxUser, row.user_id)
    if user is None or not user.active:
        return None, None
    return row, user


def use(row, user, password):
    """Set the password of a link's user; the link is spent."""
    accounts.update_mailbox_user(user, password=password)
    row.used_at = utcnow()
    user.invited_at = None
