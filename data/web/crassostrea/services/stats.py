"""Statistics over time: how many messages the gateway scanned per hour,
domain, direction and outcome, counted when the mail log stores a message
(maillog.store) and kept stats_retention_days (two years by default), much
longer than the mail log itself. The first start after an update fills the
counts from the mail log once.

Outcomes: clean (no action), spam (marked: add header, rewrite subject),
deferred (greylist, soft reject) and rejected; viruses and rspamd's scan
time are counted besides.
Mail refused before rspamd saw it (postscreen, unknown recipients) is not
in here.

The delivery time is counted per hour too (``record_delivery``, from
services/deliveries.py): the recipients of logged mail Postfix delivered and
the time from their message's arrival (Postfix's delay), per domain and
direction.
"""
from datetime import timedelta

from ..extensions import db
from ..models import DeliveryBucket, Domain, StatBucket, get_setting, utcnow

CATEGORIES = {"clean": "Clean", "spam": "Marked as spam", "deferred": "Greylisted or deferred",
              "rejected": "Rejected"}
_ACTION_CATEGORY = {"no action": "clean", "add header": "spam", "rewrite subject": "spam", "greylist": "deferred",
                    "soft reject": "deferred", "reject": "rejected"}
# range: (length, bucket size in hours)
RANGES = {"24h": (timedelta(hours=24), 1), "7d": (timedelta(days=7), 6), "30d": (timedelta(days=30), 24),
          "12m": (timedelta(days=365), 24 * 30)}


def category(action):
    return _ACTION_CATEGORY.get(action or "", "clean")


def _hour(moment):
    return moment.replace(minute=0, second=0, microsecond=0)


def _domain(direction, sender, rcpts, protected):
    if direction == "outbound":
        return sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
    domains = [r.rsplit("@", 1)[-1].lower() for r in rcpts if "@" in r]
    return next((d for d in domains if d in protected), domains[0] if domains else "")


def _add(model, keys, counts):
    """Add ``counts`` to the row of ``keys`` (the unique key), creating it."""
    table = model.__table__
    increments = {name: table.c[name] + value for name, value in counts.items()}
    if db.engine.dialect.name in ("mysql", "mariadb"):
        from sqlalchemy.dialects.mysql import insert
        statement = insert(table).values(**keys, **counts).on_duplicate_key_update(**increments)
    else:
        from sqlalchemy.dialects.sqlite import insert
        statement = insert(table).values(**keys, **counts).on_conflict_do_update(index_elements=list(keys),
                                                                                 set_=increments)
    db.session.execute(statement)


def _protected():
    return {name for name, in db.session.query(Domain.name)}


def record(entry):
    """Count a mail log entry (in the caller's transaction)."""
    domain = _domain(entry.direction, entry.sender, entry.rcpt_list, _protected())
    _add(StatBucket, {"hour": _hour(entry.created_at or utcnow()), "domain": domain[:253],
                      "direction": entry.direction, "category": category(entry.action)},
         {"messages": 1, "bytes": entry.size or 0, "viruses": int(entry.is_virus), "scan_ms": entry.scan_ms or 0})


def record_delivery(entry, rcpt, moment, delay):
    """Count a recipient of a mail log entry delivered at ``moment``,
    ``delay`` seconds after the message arrived (in the caller's transaction)."""
    domain = _domain(entry.direction, entry.sender, [rcpt], _protected())
    _add(DeliveryBucket, {"hour": _hour(moment), "domain": domain[:253], "direction": entry.direction},
         {"deliveries": 1, "delay": float(delay)})


def cleanup():
    days = get_setting("stats_retention_days")
    cutoff = utcnow() - timedelta(days=days)
    deleted = StatBucket.query.filter(StatBucket.hour < cutoff).delete(synchronize_session=False)
    deleted += DeliveryBucket.query.filter(DeliveryBucket.hour < cutoff).delete(synchronize_session=False)
    return deleted, days


def _filter(query, model, start, end, domain, direction, domains):
    query = query.filter(model.hour >= start, model.hour < end)
    if domain:
        query = query.filter(model.domain == domain)
    if domains is not None:
        query = query.filter(model.domain.in_(sorted(domains) or [""]))
    if direction:
        query = query.filter(model.direction == direction)
    return query


def _average(total, count, digits=None):
    return round(total / count, digits) if count else None


def series(range_key="7d", domain="", direction="", now=None, domains=None):
    """Bars of the range: {"buckets": [{start, clean, spam, deferred, rejected,
    viruses, total, scan_ms, delivery_s, delivered}], "totals": {..., bytes},
    "top": [(domain, messages)]}; scan_ms and delivery_s are averages (None
    without any), delivered the recipients delivered. ``domains`` limits them
    to those domains (a domain administrator's)."""
    length, size = RANGES[range_key]
    now = _hour(now or utcnow()) + timedelta(hours=1)
    start = now - length
    # align buckets of a day or more to midnight
    if size >= 24:
        start = start.replace(hour=0)
    count = max(1, int((now - start).total_seconds() // 3600 + size - 1) // size)
    buckets = [{"start": start + timedelta(hours=i * size), **{c: 0 for c in CATEGORIES}, "viruses": 0, "total": 0}
               for i in range(count)]
    totals = {**{c: 0 for c in CATEGORIES}, "viruses": 0, "total": 0, "bytes": 0}
    # [scan ms, messages with a scan time, delay s, deliveries] per bucket and in all
    sums = [[0, 0, 0.0, 0] for _ in buckets]
    overall = [0, 0, 0.0, 0]

    def index(hour):
        return min(int((hour - start).total_seconds() // 3600) // size, count - 1)

    # the average scan time leaves out hours without one (rspamd did not report it)
    timed = db.func.sum(db.case((StatBucket.scan_ms > 0, StatBucket.messages), else_=0))
    query = _filter(db.session.query(StatBucket.hour, StatBucket.category, db.func.sum(StatBucket.messages),
                                     db.func.sum(StatBucket.viruses), db.func.sum(StatBucket.bytes),
                                     db.func.sum(StatBucket.scan_ms), timed),
                    StatBucket, start, now, domain, direction, domains)
    for hour, cat, messages, viruses, total_bytes, ms, timed_messages in query.group_by(StatBucket.hour,
                                                                                          StatBucket.category):
        i = index(hour)
        bucket = buckets[i]
        bucket[cat] += int(messages or 0)
        bucket["viruses"] += int(viruses or 0)
        bucket["total"] += int(messages or 0)
        totals[cat] += int(messages or 0)
        totals["viruses"] += int(viruses or 0)
        totals["total"] += int(messages or 0)
        totals["bytes"] += int(total_bytes or 0)
        for target in (sums[i], overall):
            target[0] += int(ms or 0)
            target[1] += int(timed_messages or 0)
    query = _filter(db.session.query(DeliveryBucket.hour, db.func.sum(DeliveryBucket.delay),
                                     db.func.sum(DeliveryBucket.deliveries)),
                    DeliveryBucket, start, now, domain, direction, domains)
    for hour, delay, delivered in query.group_by(DeliveryBucket.hour):
        for target in (sums[index(hour)], overall):
            target[2] += float(delay or 0)
            target[3] += int(delivered or 0)
    for target, (ms, timed_messages, delay, delivered) in [*zip(buckets, sums), (totals, overall)]:
        target.update(scan_ms=_average(ms, timed_messages), delivery_s=_average(delay, delivered, 1),
                      delivered=delivered)
    top = _filter(db.session.query(StatBucket.domain, db.func.sum(StatBucket.messages)), StatBucket, start, now,
                  "", direction, domains).filter(StatBucket.domain != "")
    top = [(d, int(n)) for d, n in top.group_by(StatBucket.domain).order_by(db.func.sum(StatBucket.messages).desc())
           .limit(15)]
    return {"range": range_key, "bucket_hours": size, "start": start, "end": now, "buckets": buckets,
            "totals": totals, "top": top}


def chart(data, width=720, height=200):
    """Stacked bars for an SVG (the template draws them): [{x, w, label,
    total, segments: [(category, y, h)]}] and the scale's maximum."""
    peak = max([b["total"] for b in data["buckets"]] + [1])
    step = width / len(data["buckets"])
    bars = []
    for i, bucket in enumerate(data["buckets"]):
        y = height
        segments = []
        for cat in ("clean", "spam", "deferred", "rejected"):
            h = bucket[cat] / peak * height
            if h > 0:
                y -= h
                segments.append((cat, round(y, 2), round(h, 2)))
        bars.append({"x": round(i * step + step * 0.1, 2), "w": round(step * 0.8, 2), "segments": segments,
                     "total": bucket["total"], "start": bucket["start"]})
    return {"bars": bars, "peak": peak, "width": width, "height": height}


def latency_chart(data, key, width=720, height=80):
    """Bars of an average per bucket (``key``: scan_ms or delivery_s); a
    bucket without one has no bar."""
    values = [b[key] for b in data["buckets"]]
    peak = max([v for v in values if v is not None] + [0])
    step = width / len(values)
    bars = []
    for bucket, value in zip(data["buckets"], values):
        h = round(value / peak * height, 2) if value is not None and peak else 0
        bars.append({"x": round(len(bars) * step + step * 0.1, 2), "w": round(step * 0.8, 2), "y": round(height - h, 2),
                     "h": h, "value": value, "start": bucket["start"]})
    return {"bars": bars, "peak": peak, "width": width, "height": height}

