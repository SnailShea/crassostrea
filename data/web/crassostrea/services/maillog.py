"""Mail log: every message Rspamd scanned for a protected domain or from a
relay network, with its content, kept for ``maillog_retention_days``
(crassostrea-job@cleanup).

Rspamd's metadata_exporter posts each message to the internal API
(/internal/mail-log, see data/conf/rspamd/local.d/metadata_exporter.conf).
Shared by the admin area and the REST API.
"""
import email.parser
import json
import re
from datetime import timedelta

from ..extensions import db
from ..models import DIRECTIONS, MailLogEntry, QuarantineItem, get_setting, utcnow
from . import mailer, stats
from .errors import ServiceError
from .headers import REQUEUE_HEADER
from .quarantine import _escape_like, prepare_reinjection

ACTIONS = ("no action", "greylist", "add header", "rewrite subject", "soft reject", "reject")


def _known(value):
    """Rspamd's metadata says 'unknown' for missing values."""
    return "" if value in (None, "unknown") else str(value)


def _first(meta, name):
    """First value of a decoded header in the metadata (a list, or 'unknown')."""
    values = meta.get(name)
    return str(values[0]) if isinstance(values, list) and values else ""


def header_block(raw):
    """The message's header block including the empty line after it (parsed
    for the Message-ID)."""
    match = re.search(rb"\r?\n\r?\n", raw)
    return raw if match is None else raw[:match.end()]


def store(meta, raw, direction):
    """Add a scanned message (rspamd metadata + the message as scanned)."""
    rcpts = meta.get("rcpt")
    if isinstance(rcpts, str):
        rcpts = [] if rcpts == "unknown" else [rcpts]
    rcpts = sorted({str(r).strip().lower() for r in rcpts or [] if r})
    headers = email.parser.BytesHeaderParser().parsebytes(header_block(raw))
    try:
        scan_ms = int(meta.get("scan_time") or 0)
    except (TypeError, ValueError):
        scan_ms = 0
    entry = MailLogEntry(
        direction=direction,
        qid=_known(meta.get("qid"))[:64],
        message_id=str(headers.get("Message-ID") or "").strip()[:255],
        sender=_known(meta.get("from"))[:320],
        rcpts=",".join(rcpts),
        header_from=_first(meta, "header_from")[:500],
        subject=(_first(meta, "header_subject") or _known(meta.get("subject")))[:500],
        score=float(meta.get("score") or 0),
        action=_known(meta.get("action"))[:32],
        ip=_known(meta.get("ip"))[:64],
        symbols=json.dumps(meta.get("symbols") or []),
        size=len(raw),
        scan_ms=max(scan_ms, 0),
        message=raw,
    )
    db.session.add(entry)
    stats.record(entry)
    return entry


def _domain_condition(domain):
    # a recipient's domain (the list is comma separated) or the sender's
    d = _escape_like(domain)
    return db.or_(MailLogEntry.rcpts.like(f"%@{d}", escape="\\"), MailLogEntry.rcpts.like(f"%@{d},%", escape="\\"),
                  MailLogEntry.sender.like(f"%@{d}", escape="\\"))


def in_scope(entry, domains):
    """Whether a domain administrator of ``domains`` (None: all) sees the entry."""
    if domains is None:
        return True
    involved = {a.rsplit("@", 1)[-1] for a in entry.rcpt_list + [entry.sender] if "@" in a}
    return bool(involved & set(domains))


def filtered(direction="", action="", domain="", search="", strict=False, domains=None):
    """Entries matching the filters; ``strict`` rejects unknown values (API);
    ``domains``: only entries of these domains (a domain administrator's)."""
    query = MailLogEntry.query
    if domains is not None:
        query = query.filter(db.or_(*[_domain_condition(d) for d in sorted(domains)])
                             if domains else db.false())
    if direction:
        if direction in DIRECTIONS:
            query = query.filter(MailLogEntry.direction == direction)
        elif strict:
            raise ServiceError("direction must be inbound or outbound", "direction", 400)
    if action:
        if action in ACTIONS:
            query = query.filter(MailLogEntry.action == action)
        elif strict:
            raise ServiceError(f"action must be one of: {', '.join(ACTIONS)}", "action", 400)
    domain = domain.strip().lower()
    if domain:
        query = query.filter(_domain_condition(domain))
    search = search.strip()
    if search:
        like = f"%{_escape_like(search)}%"
        query = query.filter(db.or_(MailLogEntry.subject.ilike(like, escape="\\"),
                                    MailLogEntry.sender.ilike(like, escape="\\"),
                                    MailLogEntry.rcpts.ilike(like, escape="\\"),
                                    MailLogEntry.header_from.ilike(like, escape="\\"),
                                    MailLogEntry.message_id.ilike(like, escape="\\"),
                                    MailLogEntry.qid == search, MailLogEntry.ip == search))
    return query.order_by(MailLogEntry.created_at.desc(), MailLogEntry.id.desc())


def quarantined(entry):
    """Quarantine items of the same message (by queue ID)."""
    if not entry.qid:
        return []
    return QuarantineItem.query.filter_by(qid=entry.qid).order_by(QuarantineItem.rcpt).all()


def requeue(entry, rcpts, requeued_by, allow_virus=False):
    """Deliver the stored message again to some of its recipients through
    Postfix's re-injection listener (no second scan). Returns notes; raises
    ServiceError for invalid requests, mailer.ReleaseError if Postfix refuses
    every recipient."""
    if entry.is_virus and not allow_virus:
        raise ServiceError("This message contains a virus; confirm to queue it anyway", "allow_virus", 409)
    rcpts = [r.strip().lower() for r in rcpts]
    unknown = sorted(set(rcpts) - set(entry.rcpt_list))
    if unknown:
        raise ServiceError(f"{unknown[0]} is not a recipient of this message", "rcpts")
    if not rcpts:
        raise ServiceError("Select at least one recipient", "rcpts")
    message, signed_by = prepare_reinjection(entry.message, entry.direction, REQUEUE_HEADER, requeued_by,
                                             f"mail log #{entry.id}")
    delivered, notes = [], []
    for rcpt in rcpts:
        try:
            mailer.reinject(entry.sender, rcpt, message)
            delivered.append(rcpt)
        except mailer.ReleaseError as exc:
            notes.append(f"{rcpt}: {exc}")
    if not delivered:
        raise mailer.ReleaseError("; ".join(notes))
    entry.requeued_at = utcnow()
    entry.requeued_by = requeued_by[:64]
    notes.insert(0, f"queued for {', '.join(delivered)}")
    if signed_by:
        notes.append(f"DKIM-signed for {signed_by}")
    return notes


def cleanup():
    """Delete entries older than the retention period; returns (count, days)."""
    days = get_setting("maillog_retention_days")
    cutoff = utcnow() - timedelta(days=days)
    return MailLogEntry.query.filter(MailLogEntry.created_at < cutoff).delete(synchronize_session=False), days
