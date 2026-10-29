"""What happened to logged mail after it was scanned: Postfix's delivery
attempts and the notices it sent the sender (bounces, delay warnings).

system/libexec/logship reads them from the Postfix log of its node and posts
them to /internal/delivery (``record``):

- ``delivery``: a delivery attempt to a recipient: sent, deferred or bounced,
  with the relay, the DSN code, the remote server's answer and Postfix's
  delay (seconds since the message arrived). One row per queue ID and
  recipient keeps the latest attempt and counts them; the dashboard averages
  the delay of the sent ones (``average_delay``).
- ``bounce_notice``, ``delay_notice``, ``dsn_notice``: Postfix sent the sender
  a non-delivery notice, a delay warning or a delivery status notification.
  The notice is a message of its own (``notice_qid``); its delivery is
  recorded like any other.
- ``expired``: the message stayed in the queue too long and was returned to
  the sender.

The mail log joins them by queue ID (``summary``). Long queue IDs
(enable_long_queue_ids) are never reused; for older short ones only rows
within ``WINDOW`` of the logged message count. Rows go with the mail log's
retention (``cleanup``).
"""
import re
from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError

from ..extensions import db
from ..models import MAX_MAILLOG_DAYS, MailDelivery, MailLogEntry, get_setting, utcnow

QID_RE = re.compile(r"^[0-9A-Za-z]{6,32}$")
DSN_RE = re.compile(r"^[245]\.\d{1,3}\.\d{1,3}$")
DELIVERY_STATUSES = ("sent", "deferred", "bounced")
NOTICES = {"non-delivery": "bounce_notice", "delay": "delay_notice", "delivery status": "dsn_notice"}
NOTICE_LABELS = {"bounce_notice": "Non-delivery notice (bounce)", "delay_notice": "Delay warning",
                 "dsn_notice": "Delivery status notification"}
KINDS = ("delivery", "expired", *NOTICE_LABELS)
# Delivery lines of a logged message: from shortly before it was logged (the
# export can lag behind Postfix) until the queue gives up (5 days)
WINDOW = (timedelta(minutes=10), timedelta(days=7))
# Mail log filter: entries with at least one recipient in this state
STATES = ("delivered", "deferred", "bounced")


def record(event, now=None):
    """Store one event of logship: {time, qid, kind, rcpt, status, dsn,
    relay, detail, delay, notice_qid}. Returns the row, or None if invalid."""
    now = now or utcnow()
    try:
        moment = datetime.fromtimestamp(int(event["time"]), timezone.utc).replace(tzinfo=None)
        qid = str(event["qid"])
        kind = str(event["kind"])
    except (KeyError, TypeError, ValueError):
        return None
    if not QID_RE.match(qid) or kind not in KINDS:
        return None
    if not now - timedelta(days=MAX_MAILLOG_DAYS) <= moment <= now + timedelta(minutes=5):
        return None
    values = {"status": "", "dsn": "", "relay": "", "detail": "", "notice_qid": "", "rcpt": "", "delay": None}
    if kind == "delivery":
        values.update(rcpt=str(event.get("rcpt") or "").strip().lower(), status=str(event.get("status") or ""),
                      dsn=str(event.get("dsn") or ""), relay=str(event.get("relay") or "")[:255],
                      detail=" ".join(str(event.get("detail") or "").split())[:500], delay=_delay(event.get("delay")))
        if (values["status"] not in DELIVERY_STATUSES or not DSN_RE.match(values["dsn"])
                or not 0 < len(values["rcpt"]) <= 320 or any(c.isspace() or c in "<>" for c in values["rcpt"])):
            return None
    elif kind == "expired":
        values["status"] = "expired"
    else:
        values.update(status="sent", notice_qid=str(event.get("notice_qid") or ""))
        if not QID_RE.match(values["notice_qid"]):
            return None
    for _ in range(2):
        row = MailDelivery.query.filter_by(qid=qid, kind=kind, rcpt=values["rcpt"]).first()
        if row is None:
            row = MailDelivery(qid=qid, kind=kind, first_at=moment, last_at=moment, attempts=1, **values)
            db.session.add(row)
        else:
            # an attempt that arrives late counts, but does not replace the latest
            if moment >= row.last_at:
                for key, value in values.items():
                    setattr(row, key, value)
                row.last_at = moment
            row.first_at = min(row.first_at, moment)
            row.attempts += 1
        try:
            db.session.flush()
            return row
        except IntegrityError:  # another worker added it meanwhile
            db.session.rollback()
    return None


def _delay(value):
    """Seconds, or None when missing or not a plausible delay."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    return float(value) if 0 <= value <= MAX_MAILLOG_DAYS * 86400 else None


def average_delay(start, end, direction="", domain="", domains=None):
    """(average seconds, deliveries) from arrival to delivery of the logged
    mail's recipients delivered between start and end, with the mail log's
    filters; (None, 0) without any."""
    from . import maillog
    query = (maillog.filtered(direction=direction, domain=domain, domains=domains).order_by(None)
             .join(MailDelivery, db.and_(MailDelivery.qid == MailLogEntry.qid, MailLogEntry.qid != ""))
             .filter(MailDelivery.kind == "delivery", MailDelivery.status == "sent", MailDelivery.delay.isnot(None),
                     MailDelivery.last_at >= start, MailDelivery.last_at < end,
                     # a reused short queue ID: only its own message (see WINDOW)
                     MailLogEntry.created_at >= start - WINDOW[1], MailLogEntry.created_at < end + WINDOW[0])
             .with_entities(db.func.avg(MailDelivery.delay), db.func.count(MailDelivery.id)))
    average, count = query.one()
    return (float(average) if count else None), int(count or 0)


def _rows(qid, around):
    return (MailDelivery.query
            .filter(MailDelivery.qid == qid, MailDelivery.first_at >= around - WINDOW[0],
                    MailDelivery.first_at <= around + WINDOW[1])
            .order_by(MailDelivery.kind, MailDelivery.rcpt).all())


def state(deliveries, expired=False):
    """The entry's delivery state from its recipients' latest attempts:
    bounced (any), deferred (any still waiting), delivered (all), or None."""
    statuses = {d.status for d in deliveries}
    if expired or "bounced" in statuses:
        return "bounced"
    if "deferred" in statuses:
        return "deferred"
    if statuses == {"sent"}:
        return "delivered"
    return None


def summary(entry):
    """{state, deliveries, notices: [{kind, label, qid, at, deliveries, state}],
    expired} of a mail log entry; state None when nothing was delivered yet
    (or the message was rejected, or never queued)."""
    if not entry.qid or entry.refused:
        return {"state": None, "deliveries": [], "notices": [], "expired": None}
    rows = _rows(entry.qid, entry.created_at)
    deliveries = [r for r in rows if r.kind == "delivery"]
    expired = next((r for r in rows if r.kind == "expired"), None)
    notices = []
    for row in rows:
        if row.kind in NOTICE_LABELS:
            own = [d for d in _rows(row.notice_qid, row.first_at) if d.kind == "delivery"]
            notices.append({"kind": row.kind, "label": NOTICE_LABELS[row.kind], "qid": row.notice_qid,
                            "at": row.last_at, "deliveries": own, "state": state(own)})
    return {"state": state(deliveries, expired is not None), "deliveries": deliveries, "notices": notices,
            "expired": expired}


def states(entries):
    """{entry id: (state, bounce notice sent)} for a page of the mail log, in
    one query."""
    qids = {e.qid for e in entries if e.qid and not e.refused}
    rows = {}
    if qids:
        for row in MailDelivery.query.filter(MailDelivery.qid.in_(sorted(qids))):
            rows.setdefault(row.qid, []).append(row)
    result = {}
    for entry in entries:
        mine = [r for r in rows.get(entry.qid, []) if not entry.refused
                and entry.created_at - WINDOW[0] <= r.first_at <= entry.created_at + WINDOW[1]]
        result[entry.id] = (state([r for r in mine if r.kind == "delivery"], any(r.kind == "expired" for r in mine)),
                            any(r.kind == "bounce_notice" for r in mine))
    return result


def filter_state(query, wanted):
    """Mail log entries with a recipient in the delivery state ``wanted``
    (delivered: every recipient's latest attempt was sent). By queue ID only:
    date arithmetic differs between the databases, and long queue IDs are
    unique anyway."""
    if wanted not in STATES:
        return query
    window = db.and_(MailDelivery.qid == MailLogEntry.qid, MailLogEntry.qid != "")
    if wanted == "bounced":
        cond = db.or_(db.and_(MailDelivery.kind == "delivery", MailDelivery.status == "bounced"),
                      MailDelivery.kind == "expired")
        return query.filter(db.exists().where(db.and_(window, cond)))
    if wanted == "deferred":
        cond = db.and_(MailDelivery.kind == "delivery", MailDelivery.status == "deferred")
        return query.filter(db.exists().where(db.and_(window, cond)))
    sent = db.and_(MailDelivery.kind == "delivery", MailDelivery.status == "sent")
    other = db.or_(db.and_(MailDelivery.kind == "delivery", MailDelivery.status != "sent"),
                   MailDelivery.kind == "expired")
    return query.filter(db.exists().where(db.and_(window, sent)), ~db.exists().where(db.and_(window, other)))


def as_json(summary_):
    def delivery(d):
        return {"rcpt": d.rcpt, "status": d.status, "dsn": d.dsn, "relay": d.relay, "detail": d.detail,
                "attempts": d.attempts, "first_at": _iso(d.first_at), "last_at": _iso(d.last_at)}
    return {"state": summary_["state"], "deliveries": [delivery(d) for d in summary_["deliveries"]],
            "expired_at": _iso(summary_["expired"].last_at) if summary_["expired"] else None,
            "notices": [{"kind": n["kind"], "queue_id": n["qid"], "at": _iso(n["at"]), "state": n["state"],
                         "deliveries": [delivery(d) for d in n["deliveries"]]} for n in summary_["notices"]]}


def _iso(value):
    return value.isoformat(timespec="seconds") + "Z" if value else None


def cleanup():
    """Rows older than the mail log's retention."""
    cutoff = utcnow() - timedelta(days=get_setting("maillog_retention_days"))
    return MailDelivery.query.filter(MailDelivery.last_at < cutoff).delete(synchronize_session=False)
