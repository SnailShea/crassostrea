"""Quarantine operations shared by the admin area and the mailbox user portal."""
import email
import email.policy
from email.utils import formatdate

from flask import current_app

from ..extensions import db
from ..models import QuarantineItem, utcnow
from . import dkim, mailer
from .headers import RELEASE_HEADER, prepend_header, remove_header
from .rspamd import RspamdError, train

PREVIEW_LIMIT = 20000


def base_address(rcpt):
    """alice+tag@example.com -> alice@example.com"""
    local, _, domain = rcpt.rpartition("@")
    return f"{local.split('+', 1)[0]}@{domain}"


def _escape_like(text):
    return text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def owned_by(email):
    """Filter for inbound items of a mailbox, including sub-addresses."""
    local, domain = email.rsplit("@", 1)
    pattern = f"{_escape_like(local)}+%@{_escape_like(domain)}"
    return db.and_(QuarantineItem.direction == "inbound",
                   db.or_(QuarantineItem.rcpt == email, QuarantineItem.rcpt.like(pattern, escape="\\")))


def parse_message(raw):
    """Headers, plain text preview, truncation flag and attachment list.

    HTML is returned as source text and never rendered.
    """
    msg = email.message_from_bytes(raw, policy=email.policy.default)
    headers = [(k, str(v)) for k, v in msg.items()]
    body, attachments = "", []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename or part.get_content_disposition() == "attachment":
            attachments.append({"name": filename or "(unnamed)", "type": part.get_content_type(),
                                "size": len(part.get_payload(decode=True) or b"")})
            continue
        if not body and part.get_content_type() in ("text/plain", "text/html"):
            try:
                text = part.get_content()
            except (LookupError, ValueError, AssertionError):
                text = (part.get_payload(decode=True) or b"").decode("utf-8", "replace")
            if part.get_content_type() == "text/html":
                text = "[HTML part, shown as source]\n\n" + text
            body = text
    return {"headers": headers, "body": body[:PREVIEW_LIMIT], "truncated": len(body) > PREVIEW_LIMIT,
            "attachments": attachments}


def prepare_reinjection(raw, direction, header, released_by, reference):
    """The message as it is re-injected: original + ``header`` (+ DKIM).

    Only a header is added, the sender's DKIM signature stays valid. A copy
    of the header that came with the message is dropped so it cannot be
    forged. Outbound mail goes to external recipients: their header does not
    name the administrator, and it is signed with the domain's DKIM key
    because the re-injection listener bypasses rspamd.
    """
    hostname = current_app.config["HOSTNAME"]
    message = remove_header(raw, header)
    if direction == "outbound":
        value = f"{formatdate(usegmt=True)} by {hostname}"
    else:
        value = f"{formatdate(usegmt=True)} by {released_by} on {hostname} ({reference})"
    message = prepend_header(message, header, value)
    signed_by = None
    if direction == "outbound":
        message, signed_by = dkim.sign_outbound(message)
    return message, signed_by


def prepare_release(item, released_by):
    return prepare_reinjection(item.message, item.direction, RELEASE_HEADER, released_by,
                               f"quarantine #{item.id}")


def release(item, released_by, learn_ham=False):
    """Deliver the message to its recipient (see prepare_release)."""
    message, signed_by = prepare_release(item, released_by)
    mailer.reinject(item.sender, item.rcpt, message)
    item.released_at = utcnow()
    item.released_by = released_by[:64]
    notes = [f"DKIM-signed for {signed_by}"] if signed_by else []
    if learn_ham:
        try:
            notes += train(item.message, spam=False)
        except RspamdError as exc:
            notes.append(f"learning failed: {exc}")
    return notes


def learn_spam_and_delete(item):
    """Learn the message as spam (Bayes and fuzzy hash), then delete it."""
    notes = train(item.message, spam=True)
    db.session.delete(item)
    return notes


# Where "allow/block sender" of a quarantined message adds its sender
SENDER_SCOPES = {"mailbox": "this recipient", "domain": "the recipient's domain", "global": "every domain"}


def sender_mailbox(item):
    """The mailbox user an inbound item belongs to, or None."""
    from ..models import MailboxUser
    if item.direction != "inbound":
        return None
    return MailboxUser.query.filter_by(email=base_address(item.rcpt.lower())).first()


def list_sender(item, list_type, scope):
    """Add the envelope sender of an inbound item to an allow or block list:
    the recipient's own (``mailbox``, needs a mailbox user), its domain's or
    the global one. Returns a sentence for the flash; an entry that exists
    already is no error. Raises ServiceError. The caller commits and syncs
    the maps."""
    from ..models import Domain
    from . import accounts, filters
    from .errors import ServiceError
    if list_type not in ("allow", "block") or scope not in SENDER_SCOPES:
        raise ServiceError("Unknown list or scope", status=400)
    if item.direction != "inbound":
        raise ServiceError("Only the senders of inbound mail can be listed")
    sender = (item.sender or "").strip().lower()
    if not sender or "@" not in sender:
        raise ServiceError("The message has no sender address (it is a bounce)")
    comment = f"From quarantined message #{item.id}"
    if scope == "mailbox":
        user = sender_mailbox(item)
        if user is None:
            raise ServiceError(f"{base_address(item.rcpt)} has no mailbox user for a personal list")
        where = f"the {list_type} list of {user.email}"
    else:
        domain = None
        if scope == "domain":
            domain = Domain.query.filter_by(name=item.domain).first()
            if domain is None:
                raise ServiceError(f"{item.domain} is not a domain of the gateway")
        where = f"the {list_type} list of {domain.name}" if domain else f"the global {list_type} list"
    try:
        if scope == "mailbox":
            accounts.add_user_list_entry(user, list_type, sender, comment)
        else:
            filters.add_list_entry(list_type, "sender", sender, comment, domain=domain)
    except ServiceError as exc:
        if exc.status != 409:
            raise
        return f"{sender} already is on {where}."
    return f"{sender} added to {where}."


def self_service_release(item, released_by):
    """Release by the recipient (portal or digest link). Returns an error or None.

    Viruses can only be released by administrators. Commits on success.
    """
    if item.is_virus:
        return "This message contains a virus and can only be released by an administrator."
    if item.released_at is not None:
        return None
    try:
        release(item, released_by)
    except mailer.ReleaseError:
        db.session.rollback()
        return "The message could not be delivered right now, please try again later."
    db.session.commit()
    return None
