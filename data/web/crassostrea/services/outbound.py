"""Outbound limits: how many recipients a sender of the relay networks may
send to per minute, hour or day.

The default (settings outbound_limit and outbound_limit_period, 0: none)
applies to every sender; a limit for an address or a domain (each of its
senders) replaces it. They are written to outbound_limits.map; rspamd
(data/conf/rspamd/lua/rspamd.local.lua) counts each sender's recipients in
Valkey with outbound_limit.redis.lua and defers mail over the limit. Bounces
(empty sender) count per client IP as "bounces:<ip>".
"""
import time

from ..extensions import db
from ..models import LIMIT_PERIODS, MAX_OUTBOUND_LIMIT, OutboundLimit, get_setting
from .. import validators as v
from . import store
from .errors import ServiceError

HITS = "sf_rl_hits"
HIT_PREFIX = "sf_rl_hit:"
COUNTER_PREFIX = "sf_rl:"
# Senders shown with their current counts
USAGE_MAX = 50


def normalize_sender(value):
    """An address, or a domain (also written as @domain or *@domain)."""
    value = (value if isinstance(value, str) else "").strip().lower()
    try:
        if value.startswith(("@", "*@")):
            return v.normalize_domain(value.split("@", 1)[1])
        return v.normalize_email(value) if "@" in value else v.normalize_domain(value)
    except v.ValidationError as exc:
        raise ServiceError(f"{exc}: enter an address or a domain", "sender") from exc


def _limit(value):
    if isinstance(value, bool):
        raise ServiceError("max_recipients must be a whole number", "max_recipients")
    try:
        number = int(value)
    except (TypeError, ValueError):
        raise ServiceError("max_recipients must be a whole number", "max_recipients") from None
    if not 0 <= number <= MAX_OUTBOUND_LIMIT:
        raise ServiceError(f"max_recipients must be from 0 to {MAX_OUTBOUND_LIMIT}", "max_recipients")
    return number


def _period(value):
    if value not in LIMIT_PERIODS:
        raise ServiceError(f"period must be one of {', '.join(LIMIT_PERIODS)}", "period")
    return value


def _comment(value):
    value = (value if isinstance(value, str) else "").strip()
    if len(value) > 255:
        raise ServiceError("The comment is too long (at most 255 characters)", "comment")
    return value


def add_limit(sender, max_recipients, period="hour", comment=""):
    sender = normalize_sender(sender)
    if OutboundLimit.query.filter_by(sender=sender).first():
        raise ServiceError(f"There already is a limit for {sender}", "sender", 409)
    limit = OutboundLimit(sender=sender, max_recipients=_limit(max_recipients), period=_period(period),
                          comment=_comment(comment))
    db.session.add(limit)
    return limit


def update_limit(limit, **changes):
    if "max_recipients" in changes:
        limit.max_recipients = _limit(changes["max_recipients"])
    if "period" in changes:
        limit.period = _period(changes["period"])
    if "comment" in changes:
        limit.comment = _comment(changes["comment"])
    return limit


def delete_limit(limit):
    db.session.delete(limit)


def limits():
    return OutboundLimit.query.order_by(OutboundLimit.sender).all()


def default():
    """(recipients, period) of every other sender; recipients 0: no limit."""
    return get_setting("outbound_limit"), get_setting("outbound_limit_period")


def build_map():
    """outbound_limits.map: "<key> <limit>:<seconds>", key an address,
    @domain or * (the default)."""
    lines = []
    count, period = default()
    if count:
        lines.append(f"* {count}:{LIMIT_PERIODS[period]}")
    for limit in limits():
        key = limit.sender if "@" in limit.sender else f"@{limit.sender}"
        lines.append(f"{key} {limit.max_recipients}:{LIMIT_PERIODS[limit.period]}")
    return lines


def limit_for(sender, rules=None):
    """The limit that applies to ``sender`` as rspamd chooses it: (recipients,
    period, source), source the address, the domain or "default"; None if
    there is none."""
    rules = rules if rules is not None else {limit.sender: limit for limit in limits()}
    domain = sender.rsplit("@", 1)[1] if "@" in sender else None
    for key in (sender, domain):
        if key and key in rules:
            rule = rules[key]
            return (rule.max_recipients, rule.period, key) if rule.max_recipients else None
    count, period = default()
    return (count, period, "default") if count else None


# ---------------------------------------------------------------------------
# Counts in Valkey
# ---------------------------------------------------------------------------

def _glob_escape(value):
    return "".join(f"\\{c}" if c in "*?[]\\" else c for c in value)


def usage(now=None):
    """Senders with recipients in their current period, most first:
    [{sender, count, period, limit}]. Raises redis.RedisError."""
    now = int(now or time.time())
    names = {seconds: name for name, seconds in LIMIT_PERIODS.items()}
    rules = {limit.sender: limit for limit in limits()}
    found = []
    r = store.get_redis()
    for key in r.scan_iter(match=f"{COUNTER_PREFIX}*", count=500):
        try:
            seconds, rest = key[len(COUNTER_PREFIX):].split(":", 1)
            sender, window = rest.rsplit(":", 1)
            seconds, window = int(seconds), int(window)
        except ValueError:
            continue
        if seconds not in names or window != now // seconds:
            continue
        count = int(r.get(key) or 0)
        applies = limit_for(sender, rules)
        found.append({"sender": sender, "count": count, "period": names[seconds],
                      "limit": applies[0] if applies and applies[1] == names[seconds] else None})
        if len(found) >= 2000:
            break
    found.sort(key=lambda item: (-item["count"], item["sender"]))
    return found[:USAGE_MAX]


def hits(days=7):
    """Senders whose mail was deferred in the last ``days``, latest first:
    [{sender, at, count, limit, period}]. Raises redis.RedisError."""
    names = {seconds: name for name, seconds in LIMIT_PERIODS.items()}
    r = store.get_redis()
    found = []
    for sender, at in r.zrevrangebyscore(HITS, "+inf", time.time() - days * 86400, withscores=True):
        entry = r.hgetall(HIT_PREFIX + sender)
        if not entry:
            r.zrem(HITS, sender)
            continue
        seconds = int(entry.get("seconds") or 0)
        found.append({"sender": sender, "at": int(at), "count": int(entry.get("count") or 0),
                      "limit": int(entry.get("limit") or 0),
                      "period": names.get(seconds, f"{seconds} seconds")})
    return found


def reset(sender):
    """Let ``sender`` send again now: removes its counters and its record of
    deferred mail. Returns whether there was anything. Raises redis.RedisError."""
    if not isinstance(sender, str) or not sender.strip():
        raise ServiceError("Give the sender to reset", "sender")
    sender = sender.strip().lower()
    r = store.get_redis()
    keys = [key for seconds in LIMIT_PERIODS.values()
            for key in r.scan_iter(match=f"{COUNTER_PREFIX}{seconds}:{_glob_escape(sender)}:*", count=500)]
    removed = r.delete(*keys, HIT_PREFIX + sender) if keys else r.delete(HIT_PREFIX + sender)
    removed += r.zrem(HITS, sender)
    return bool(removed)


def valkey_error(exc):
    return ServiceError(f"Valkey cannot be reached ({exc})", "valkey", 503)
