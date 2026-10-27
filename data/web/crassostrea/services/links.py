"""Link protection: the links of inbound mail for domains with link
protection point to the gateway (https://<hostname>/l/<id>) and are checked
when they are clicked, not only when the message arrived.

rspamd (data/conf/rspamd/lua/rspamd.local.lua, link_protection.json)
rewrites the links and stores each URL in Valkey as sf_link:<id> (id: the
start of its SHA-256), kept link_protection_days. A click looks the URL up,
checks its host against the administrators' block list and the domain block
lists Spamhaus DBL (DQS with the key of Settings), SURBL and URIBL, and
redirects, or shows a warning (with a way on if link_protection_allow_continue).
Verdicts are cached for CACHE_SECONDS; clicks are kept in sf_link_clicks.
Unknown ids get an error page: the gateway is no open redirector.
"""
import ipaddress
import json
import re
import time
from urllib.parse import urlsplit

from flask import current_app

from ..models import Domain, get_setting
from . import netcheck, store

ID_RE = re.compile(r"^[0-9a-f]{24}$")
LINK_PREFIX = "sf_link:"
VERDICT_PREFIX = "sf_link_verdict:"
CLICKS = "sf_link_clicks"
CLICKS_KEPT = 1000
CACHE_SECONDS = 600
MIB = 1024 * 1024


def build_json():
    """link_protection.json for rspamd."""
    hostname = current_app.config["HOSTNAME"]
    domains = [d.name for d in Domain.query.filter_by(active=True, link_protection=True).order_by(Domain.name)]
    return json.dumps({
        "base": f"https://{hostname}/l/",
        "domains": domains,
        "exempt": sorted(set(get_setting("link_protection_exempt_hosts").split()) | {hostname}),
        "ttl": get_setting("link_protection_days") * 86400,
        "max_size": get_setting("max_message_size_mb") * MIB,
    }, indent=1) + "\n"


def lookup(link_id):
    """The URL of a link id, or None. Raises redis.RedisError."""
    if not isinstance(link_id, str) or not ID_RE.match(link_id):
        return None
    return store.get_redis().get(LINK_PREFIX + link_id)


def _matches(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def registered(host):
    """example.com of www.example.com, example.co.uk of a.example.co.uk."""
    labels = host.split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _blocklists():
    key = get_setting("spamhaus_dqs_key")
    dbl = f"{key}.dbl.dq.spamhaus.net" if re.match(r"^[A-Za-z0-9]+$", key) else "dbl.spamhaus.org"
    return [
        # 127.0.1.2-99: spam, phishing, malware, botnet; 100-199: abused legitimate sites;
        # 127.255.255.x: errors (e.g. queries through a public resolver)
        ("Spamhaus DBL", dbl, lambda a: a.startswith("127.0.1.") and 2 <= int(a.rsplit(".", 1)[1]) < 200),
        # bits: 8 phishing, 16 malware, 64 abused, 128 cracked sites
        ("SURBL", "multi.surbl.org", lambda a: a.startswith("127.0.0.") and int(a.rsplit(".", 1)[1]) & 0xD8),
        # 2: black (grey and red are too broad to block a click)
        ("URIBL", "multi.uribl.com", lambda a: a.startswith("127.0.0.") and int(a.rsplit(".", 1)[1]) & 2),
    ]


def _listed(name):
    """The block lists that list ``name``."""
    found = []
    for label, zone, listed in _blocklists():
        try:
            answers = netcheck.lookup(f"{name}.{zone}", "A")
        except (netcheck.NoRecords, netcheck.LookupFailed):
            continue
        if any(listed(answer) for answer in answers):
            found.append(label)
    return found


def check(url):
    """{"blocked": bool, "reason": text or None, "host": host} for a URL."""
    try:
        host = (urlsplit(url).hostname or "").rstrip(".").lower()
    except ValueError:
        host = ""
    if not host:
        return {"blocked": True, "reason": "The link is malformed.", "host": ""}
    if _matches(host, get_setting("link_protection_block_domains").split()):
        return {"blocked": True, "reason": "The administrators blocked this site.", "host": host}
    try:
        ipaddress.ip_address(host.strip("[]"))
        return {"blocked": False, "reason": None, "host": host}
    except ValueError:
        pass
    r = store.get_redis()
    cached = r.get(VERDICT_PREFIX + host)
    if cached:
        return json.loads(cached)
    lists = []
    for name in dict.fromkeys((host, registered(host))):
        lists += [label for label in _listed(name) if label not in lists]
    verdict = {"blocked": bool(lists), "host": host,
               "reason": f"The site is listed as dangerous by {', '.join(lists)}." if lists else None}
    r.set(VERDICT_PREFIX + host, json.dumps(verdict), ex=CACHE_SECONDS)
    return verdict


def record_click(link_id, url, verdict, ip):
    r = store.get_redis()
    r.lpush(CLICKS, json.dumps({"id": link_id, "url": url[:2000], "host": verdict["host"], "at": int(time.time()),
                                "blocked": verdict["blocked"], "reason": verdict["reason"], "ip": ip}))
    r.ltrim(CLICKS, 0, CLICKS_KEPT - 1)


def clicks(limit=200, blocked_only=False):
    """The latest clicks, newest first. Raises redis.RedisError."""
    entries = [json.loads(e) for e in store.get_redis().lrange(CLICKS, 0, CLICKS_KEPT - 1)]
    if blocked_only:
        entries = [e for e in entries if e.get("blocked")]
    return entries[:limit]
