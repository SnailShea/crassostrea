"""Rate limits of inbound mail (Rate limits page), in two layers:

- Postfix, per sending host and node (anvil): simultaneous connections, and
  connections, messages and recipients per minute. Written to
  POSTFIX_DYNAMIC_DIR/rate_limits, applied by system/libexec/postfix-apply
  (crassostrea-postfix-reload.path; configure.sh keeps them).
- rspamd, counted in Valkey for all nodes of a cluster: messages per sending
  IP, per recipient and bounces (empty sender) per recipient, per minute, hour
  or day. Written to inbound_limits.map; data/conf/rspamd/lua/rspamd.local.lua
  checks them with inbound_limit.redis.lua and defers mail over a limit (4xx).

The relay networks never have rate limits (their senders have outbound
limits); the exempt networks neither (rate_limit_exempt.map for rspamd,
rate_limit_exempt.cidr for Postfix's smtpd_client_event_limit_exceptions).
"""
import time

from ..models import LIMIT_PERIODS, get_setting
from . import store

HITS = "sf_irl_hits"
HIT_PREFIX = "sf_irl_hit:"
COUNTER_PREFIX = "sf_irl:"
HEADER = "# Managed by the Crassostrea web UI - manual changes will be overwritten\n"
# Postfix parameters of the settings (anvil counts per minute)
POSTFIX = {"smtp_connection_count_limit": "smtpd_client_connection_count_limit",
           "smtp_connection_rate_limit": "smtpd_client_connection_rate_limit",
           "smtp_message_rate_limit": "smtpd_client_message_rate_limit",
           "smtp_recipient_rate_limit": "smtpd_client_recipient_rate_limit"}
KINDS = {"ip": "messages from one sending IP address", "rcpt": "messages to one recipient",
         "bounce": "bounces to one recipient"}


def build_rspamd_map():
    """inbound_limits.map: "<kind> <limit>:<seconds>" for the limits in use."""
    lines = []
    for kind in KINDS:
        limit = get_setting(f"inbound_{kind}_limit")
        if limit:
            lines.append(f"{kind} {limit}:{LIMIT_PERIODS[get_setting(f'inbound_{kind}_period')]}")
    return HEADER + "".join(f"{line}\n" for line in lines)


def exempt_networks():
    return [line for line in get_setting("rate_limit_exempt").split() if line]


def build_exempt_map():
    """rate_limit_exempt.map (radix) for rspamd."""
    return HEADER + "".join(f"{network}\n" for network in exempt_networks())


def build_postfix_limits():
    """rate_limits for system/libexec/postfix-apply: parameter=value."""
    return "".join(f"{parameter}={get_setting(key)}\n" for key, parameter in POSTFIX.items())


def build_postfix_exempt():
    """rate_limit_exempt.cidr for smtpd_client_event_limit_exceptions."""
    return HEADER + "".join(f"{network}\tOK\n" for network in exempt_networks())


def hits(limit=50):
    """Senders and recipients deferred in the last 7 days, newest first:
    [{kind, key, count, at, limit, seconds}]."""
    r = store.get_redis()
    result = []
    for member in r.zrevrange(HITS, 0, limit - 1):
        data = r.hgetall(HIT_PREFIX + member)
        if not data:
            continue
        kind, _, key = member.partition(":")
        result.append({"kind": kind, "key": key, "count": int(data.get("count", 0)), "at": int(data.get("at", 0)),
                       "limit": int(data.get("limit", 0)), "seconds": int(data.get("seconds", 0))})
    return result


def reset(kind, key):
    """Clear the counters and the record of one sender IP or recipient: its
    mail is accepted again at once."""
    if kind not in KINDS or not key or len(key) > 320:
        return 0
    r = store.get_redis()
    removed = 0
    for counter in r.scan_iter(f"{COUNTER_PREFIX}{kind}:*:{_escape(key)}:*", count=500):
        removed += r.delete(counter)
    r.delete(HIT_PREFIX + f"{kind}:{key}")
    r.zrem(HITS, f"{kind}:{key}")
    return removed


def _escape(value):
    """A literal for SCAN's glob pattern."""
    return "".join(f"\\{c}" if c in "*?[]\\" else c for c in value)


def period_name(seconds):
    return {60: "minute", 3600: "hour", 86400: "day"}.get(seconds, f"{seconds} s")


def now():
    return int(time.time())
