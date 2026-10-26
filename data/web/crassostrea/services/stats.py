"""Statistics over time: how many messages the gateway scanned per hour,
domain, direction and outcome, counted when the mail log stores a message
(maillog.store) and kept stats_retention_days (two years by default), much
longer than the mail log itself. The first start after an update fills the
counts from the mail log once.

Outcomes: clean (no action), spam (marked: add header, rewrite subject),
deferred (greylist, soft reject) and rejected; viruses are counted besides.
Mail refused before rspamd saw it (postscreen, unknown recipients) is not
in here.
"""
from datetime import timedelta

from ..extensions import db
from ..models import Domain, MailLogEntry, StatBucket, get_setting, utcnow

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


def _upsert(hour, domain, direction, cat, messages, size, viruses):
    table = StatBucket.__table__
    values = {"hour": hour, "domain": domain[:253], "direction": direction, "category": cat, "messages": messages,
              "bytes": size, "viruses": viruses}
    increments = {"messages": table.c.messages + messages, "bytes": table.c.bytes + size,
                  "viruses": table.c.viruses + viruses}
    if db.engine.dialect.name in ("mysql", "mariadb"):
        from sqlalchemy.dialects.mysql import insert
        statement = insert(table).values(**values).on_duplicate_key_update(**increments)
    else:
        from sqlalchemy.dialects.sqlite import insert
        statement = insert(table).values(**values).on_conflict_do_update(
            index_elements=["hour", "domain", "direction", "category"], set_=increments)
    db.session.execute(statement)


def record(entry):
    """Count a mail log entry (in the caller's transaction)."""
    protected = {name for name, in db.session.query(Domain.name)}
    _upsert(_hour(entry.created_at or utcnow()), _domain(entry.direction, entry.sender, entry.rcpt_list, protected),
            entry.direction, category(entry.action), 1, entry.size or 0, int(entry.is_virus))


def cleanup():
    days = get_setting("stats_retention_days")
    deleted = StatBucket.query.filter(StatBucket.hour < utcnow() - timedelta(days=days)).delete(
        synchronize_session=False)
    return deleted, days


def series(range_key="7d", domain="", direction="", now=None, domains=None):
    """Bars of the range: {"buckets": [{start, clean, spam, deferred, rejected,
    viruses, total}], "totals": {...}, "top": [(domain, messages)]};
    ``domains`` limits them to those domains (a domain administrator's)."""
    length, size = RANGES[range_key]
    now = _hour(now or utcnow()) + timedelta(hours=1)
    start = now - length
    # align buckets of a day or more to midnight
    if size >= 24:
        start = start.replace(hour=0)
    query = db.session.query(StatBucket.hour, StatBucket.category, db.func.sum(StatBucket.messages),
                             db.func.sum(StatBucket.viruses), db.func.sum(StatBucket.bytes)
                             ).filter(StatBucket.hour >= start, StatBucket.hour < now)
    if domain:
        query = query.filter(StatBucket.domain == domain)
    if domains is not None:
        query = query.filter(StatBucket.domain.in_(sorted(domains) or [""]))
    if direction:
        query = query.filter(StatBucket.direction == direction)
    count = max(1, int((now - start).total_seconds() // 3600 + size - 1) // size)
    buckets = [{"start": start + timedelta(hours=i * size), **{c: 0 for c in CATEGORIES}, "viruses": 0, "total": 0}
               for i in range(count)]
    totals = {**{c: 0 for c in CATEGORIES}, "viruses": 0, "total": 0, "bytes": 0}
    for hour, cat, messages, viruses, total_bytes in query.group_by(StatBucket.hour, StatBucket.category):
        index = min(int((hour - start).total_seconds() // 3600) // size, count - 1)
        bucket = buckets[index]
        bucket[cat] += int(messages or 0)
        bucket["viruses"] += int(viruses or 0)
        bucket["total"] += int(messages or 0)
        totals[cat] += int(messages or 0)
        totals["viruses"] += int(viruses or 0)
        totals["total"] += int(messages or 0)
        totals["bytes"] += int(total_bytes or 0)
    top = (db.session.query(StatBucket.domain, db.func.sum(StatBucket.messages))
           .filter(StatBucket.hour >= start, StatBucket.hour < now, StatBucket.domain != ""))
    if direction:
        top = top.filter(StatBucket.direction == direction)
    if domains is not None:
        top = top.filter(StatBucket.domain.in_(sorted(domains) or [""]))
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

