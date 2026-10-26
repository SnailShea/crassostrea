"""Messages users report from their mail client: forwarded as an attachment
to spam@<hostname> or ham@<hostname> (Outlook's and Microsoft 365's Report
button can send there too), every attached message is learned as spam or
ham, as on the Training page.

Postfix accepts both addresses and discards the mail after rspamd handed it
to the internal API (intake.json) unfiltered, with the envelope sender, the
client and whether it is a relay network. Only users of a protected domain
may report, so outsiders cannot teach the filter: the sender's domain must
be one of this gateway's and the mail come from a relay network, or pass
SPF for it, or carry a DKIM signature of it. Reports are limited per
reporter and hour; a reporter may get a confirmation. Inline forwards carry
the reporter's headers instead of the original's and are not learned.
"""
import email
import re
import time
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid, parseaddr

import dkim as dkimpy
from flask import current_app

from ..extensions import db
from ..models import Domain, UserReport, get_setting
from . import mailer, netcheck, store
from .rspamd import RspamdError, train

KINDS = {"spam": "spam", "ham": "not spam"}
MAX_MESSAGES = 20
RATE_PREFIX = "sf_user_reports:"


def addresses():
    hostname = current_app.config["HOSTNAME"]
    return {kind: f"{kind}@{hostname}" for kind in KINDS}


def _domain(address):
    return address.rsplit("@", 1)[-1].lower() if "@" in (address or "") else ""


def _protected(domain):
    names = {name for name, in db.session.query(Domain.name).filter(Domain.active.is_(True))}
    return any(domain == name or domain.endswith("." + name) for name in names)


def _dkim_txt(name, timeout=5):
    """The DNS lookup of DKIM keys (replaced in the tests)."""
    return dkimpy.dnsplug.get_txt(name, timeout=timeout)


def authorize(sender, ip, relay, raw):
    """Why the reporter may report (None: may not) - the sender's domain is
    protected and the mail comes from a relay network, passes SPF or has a
    DKIM signature of the domain."""
    domain = _domain(sender)
    if not domain or not _protected(domain):
        return None
    if relay:
        return "relay network"
    if ip:
        try:
            if netcheck.spf_evaluate(ip, domain) == "pass":
                return "SPF"
        except Exception:  # unsupported macros, no answer: try DKIM
            pass
    try:
        signature = dkimpy.DKIM(raw)
        if signature.verify(dnsfunc=_dkim_txt):
            signed = (signature.domain or b"").decode().lower()
            if signed and (domain == signed or domain.endswith("." + signed)):
                return "DKIM"
    except Exception:
        pass
    return None


def attached_messages(raw):
    """The messages attached to a report: message/rfc822 parts and .eml files."""
    found = []
    msg = email.message_from_bytes(raw)
    for part in msg.walk():
        if part.get_content_type() == "message/rfc822":
            inner = part.get_payload()
            if isinstance(inner, list) and inner:
                found.append(inner[0].as_bytes())
        elif (part.get_filename() or "").lower().endswith(".eml"):
            payload = part.get_payload(decode=True)
            if payload:
                found.append(payload)
        if len(found) >= MAX_MESSAGES:
            break
    return found


def _subject(message):
    try:
        return str(email.message_from_bytes(message).get("Subject", ""))[:200]
    except Exception:
        return ""


def _within_limit(sender, count):
    r = store.get_redis()
    key = f"{RATE_PREFIX}{sender}:{int(time.time() // 3600)}"
    used = r.incrby(key, count)
    if used == count:
        r.expire(key, 3600)
    return used <= get_setting("user_reports_per_hour")


def _confirm(sender, kind, learned, reason=None):
    hostname = current_app.config["HOSTNAME"]
    msg = EmailMessage()
    msg["From"] = formataddr(("Mail gateway", f"{kind}@{hostname}"))
    msg["To"] = sender
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=hostname)
    msg["Auto-Submitted"] = "auto-replied"
    if learned:
        msg["Subject"] = f"Thank you: {learned} message(s) learned as {KINDS[kind]}"
        msg.set_content(f"The spam filter learned {learned} message(s) you reported as {KINDS[kind]}.\n")
    else:
        msg["Subject"] = "Your report could not be used"
        msg.set_content(f"{reason}\n\nForward the message as an attachment (in Outlook: More > Forward as "
                        f"attachment) to {kind}@{hostname}.\n")
    try:
        mailer.reinject(f"{kind}@{hostname}", sender, msg.as_bytes())
    except mailer.ReleaseError as exc:
        current_app.logger.warning("user report: no confirmation to %s: %s", sender, exc)


def handle(kind, raw, sender, ip="", relay=False):
    """Learn the messages of a report. Returns the stored UserReport."""
    sender = parseaddr(sender or "")[1].lower()
    report = UserReport(reporter=sender[:320] or "<>", kind=kind, status="refused", learned=0)
    db.session.add(report)
    if not get_setting("user_reports_enabled"):
        report.detail = "Reports are turned off"
    elif not (reason := authorize(sender, ip, relay, raw)):
        report.detail = "Not from a user of a protected domain (relay network, SPF or DKIM)"
    else:
        messages = attached_messages(raw)
        report.subjects = "; ".join(filter(None, (_subject(m) for m in messages)))[:1000]
        if not messages:
            report.status, report.detail = "empty", "No attached message (forward it as an attachment)"
        elif not _within_limit(sender, len(messages)):
            report.detail = f"More than {get_setting('user_reports_per_hour')} reports in an hour"
        else:
            errors = []
            for message in messages:
                try:
                    train(message, spam=kind == "spam")
                    report.learned += 1
                except RspamdError as exc:
                    errors.append(str(exc))
            report.status = "learned" if report.learned else "refused"
            report.detail = f"Accepted ({reason})" + (f"; {errors[0]}" if errors else "")
        if get_setting("user_reports_confirm"):
            _confirm(sender, kind, report.learned, None if report.learned else report.detail)
    report.detail = re.sub(r"\s+", " ", report.detail)[:1000]
    db.session.commit()
    current_app.logger.info("user report from %s as %s: %s, %d learned", report.reporter, kind, report.status,
                            report.learned)
    return report


def recent(limit=100):
    return UserReport.query.order_by(UserReport.at.desc(), UserReport.id.desc()).limit(limit).all()
