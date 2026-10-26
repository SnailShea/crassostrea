"""Journaling: a copy of every message to an archive (journal_address),
e.g. MailStore, an Exchange or Microsoft 365 journal mailbox, or any
archive that accepts mail.

When the mail log stores a message (internal API), ``enqueue`` queues its
id in Valkey (sf_journal) if the direction is journaled (and the message
was accepted, unless journal_rejected); ``forward`` (flask journal-send,
crassostrea-journal.service, on every node: the queue is shared) sends it
through Postfix's local port without the content filter, so a journal copy
is neither scanned nor logged again. Mail is never held up by the archive.

Formats: "envelope", a report with the envelope sender and every
recipient (Bcc ones too, which the message itself does not show) and the
original attached unchanged as message/rfc822; or "copy", the message
itself. The mail log keeps messages at most 31 days and is no archive.
"""
import json
import re
import secrets
import time
from email.message import EmailMessage
from email.policy import SMTP
from email.utils import formataddr, formatdate, make_msgid

from flask import current_app

from ..extensions import db
from ..models import MailLogEntry, get_setting, utcnow
from . import mailer, store

QUEUE = "sf_journal"
STATUS = "sf_journal_status"
ACCEPTED = ("no action", "add header", "rewrite subject")


def sender():
    return f"journal@{current_app.config['HOSTNAME']}"


def wanted(entry):
    if not get_setting("journal_address"):
        return False
    if not get_setting(f"journal_{entry.direction}"):
        return False
    return entry.action in ACCEPTED or bool(get_setting("journal_rejected"))


def enqueue(entry):
    """Queue a logged message for the archive. Never raises."""
    try:
        if wanted(entry):
            store.get_redis().rpush(QUEUE, entry.id)
            return True
    except Exception as exc:
        current_app.logger.warning("journal: message %s not queued: %s", entry.id, exc)
    return False


def build(entry, fmt=None):
    """The message sent to the archive for a mail log entry. The envelope
    report is put together by hand: the original must stay byte for byte
    (the email library would re-encode or re-serialise it)."""
    original = entry.message
    if (fmt or get_setting("journal_format")) == "copy":
        return original
    hostname = current_app.config["HOSTNAME"]
    headers = EmailMessage()
    headers["From"] = formataddr(("Mail gateway journal", sender()))
    headers["To"] = get_setting("journal_address")
    headers["Subject"] = f"Journal: {entry.subject}"[:900]
    headers["Date"] = formatdate(localtime=False)
    headers["Message-ID"] = make_msgid(domain=hostname)
    headers["X-Crassostrea-Journal"] = entry.direction
    headers["MIME-Version"] = "1.0"
    boundary = "=_journal_" + secrets.token_hex(12)
    while boundary.encode() in original:
        boundary = "=_journal_" + secrets.token_hex(12)
    headers["Content-Type"] = f'multipart/mixed; boundary="{boundary}"'
    lines = [f"Sender: {entry.sender or '<>'}", f"Recipients: {', '.join(entry.rcpt_list)}",
             f"Message-ID: {entry.message_id}", f"Subject: {entry.subject}", f"Direction: {entry.direction}",
             f"Received: {entry.created_at:%Y-%m-%d %H:%M:%S} UTC by {hostname}", f"Client: {entry.ip}",
             f"Queue ID: {entry.qid}", f"Spam filter: {entry.action} (score {entry.score:g})"]
    cte = "8bit" if re.search(rb"[\x80-\xff]", original) else "7bit"
    head = headers.as_bytes(policy=SMTP).split(b"\r\n\r\n", 1)[0].rstrip(b"\r\n")
    return b"\r\n".join([
        head, b"",
        f"--{boundary}".encode(), b'Content-Type: text/plain; charset="utf-8"', b"Content-Transfer-Encoding: 8bit",
        b"", "\r\n".join(lines).encode(),
        f"--{boundary}".encode(), b"Content-Type: message/rfc822",
        b'Content-Disposition: attachment; filename="message.eml"', f"Content-Transfer-Encoding: {cte}".encode(),
        b"", original.rstrip(b"\r\n"),
        f"--{boundary}--".encode(), b""])


def _status(**fields):
    store.get_redis().hset(STATUS, mapping={k: json.dumps(v) for k, v in fields.items()})


def status():
    """{queued, sent_at, sent, error, error_at} (None where unknown). Raises redis.RedisError."""
    r = store.get_redis()
    data = {k: json.loads(v) for k, v in r.hgetall(STATUS).items()}
    return {"queued": r.llen(QUEUE), "sent_at": data.get("sent_at"), "sent": data.get("sent", 0),
            "error": data.get("error"), "error_at": data.get("error_at")}


def send_test():
    """A journal report of a test message to the archive. Raises mailer.ReleaseError."""
    hostname = current_app.config["HOSTNAME"]
    original = (f"From: Mail gateway <{sender()}>\r\nTo: {get_setting('journal_address')}\r\n"
                f"Subject: Journal test\r\nDate: {formatdate(localtime=False)}\r\n"
                f"Message-ID: {make_msgid(domain=hostname)}\r\n\r\n"
                "A test of the journaling of the mail gateway.\r\n").encode()
    entry = MailLogEntry(direction="inbound", qid="TEST", message_id="", sender=sender(),
                         rcpts=get_setting("journal_address"), subject="Journal test", score=0.0,
                         action="no action", ip="127.0.0.1", message=original, created_at=utcnow())
    mailer.reinject(sender(), get_setting("journal_address"), build(entry))


def send(entry_id):
    """Send one queued message. Returns False if it no longer exists.
    Raises mailer.ReleaseError (try again later)."""
    entry = db.session.get(MailLogEntry, int(entry_id))
    if entry is None:
        return False
    address = get_setting("journal_address")
    if not address:
        return False
    # the journal's own sender, so the archive's bounces never reach the original sender
    mailer.reinject(sender(), address, build(entry))
    return True


def forward(stop=lambda: False, idle=5):
    """Send queued messages until ``stop()``; keeps them while the archive is away."""
    backoff = 1
    while not stop():
        r = store.get_redis()
        item = r.blpop(QUEUE, timeout=idle)
        if item is None:
            db.session.rollback()
            continue
        try:
            if send(item[1]):
                r.hincrby(STATUS, "sent", 1)
                _status(sent_at=int(time.time()), error=None)
            backoff = 1
        except mailer.ReleaseError as exc:
            current_app.logger.warning("journal: message %s not sent, kept: %s", item[1], exc)
            r.lpush(QUEUE, item[1])
            _status(error=str(exc)[:500], error_at=int(time.time()))
            time.sleep(backoff)
            backoff = min(backoff * 2, 300)
        finally:
            db.session.rollback()
