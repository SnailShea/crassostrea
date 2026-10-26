"""Hash lookups of attachments: rspamd (data/conf/rspamd/lua/rspamd.local.lua,
attachment_analysis.json) looks up the hash of every attachment of a
message in

* the Malware Hash Registry of Team Cymru (DNS, MD5; free, no key): known
  malware if at least hashcheck_mhr_percent of the antivirus engines Team
  Cymru runs detect it,
* MalwareBazaar of abuse.ch (an Auth-Key, free): known malware samples,
* VirusTotal (an API key; the free one allows 4 requests a minute and 500 a
  day): at least hashcheck_vt_engines engines detect it,

each adding its score (at the reject threshold: rejected and quarantined).
Only hashes are sent, never files: a file nobody has seen before passes, so
this complements ClamAV. The keys are copied to Valkey (sf_hashcheck_keys)
instead of a map file, which every local user could read. Detections are in
sf_hash_hits.
"""
import json
import re

import requests

from ..models import get_setting
from . import netcheck, store
from .errors import ServiceError

SOURCES = {"mhr": "Team Cymru MHR", "mb": "MalwareBazaar", "vt": "VirusTotal"}
HITS = "sf_hash_hits"
KEYS = "sf_hashcheck_keys"
MIB = 1024 * 1024
TIMEOUT = 10
_HASH_RE = re.compile(r"^([0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$")


def build_json():
    """attachment_analysis.json for rspamd (no keys)."""
    return json.dumps({
        "mhr": {"enabled": bool(get_setting("hashcheck_mhr")), "min_percent": get_setting("hashcheck_mhr_percent"),
                "score": get_setting("hashcheck_mhr_score")},
        "mb": {"enabled": bool(get_setting("hashcheck_mb_key")), "score": get_setting("hashcheck_mb_score")},
        "vt": {"enabled": bool(get_setting("hashcheck_vt_key")), "score": get_setting("hashcheck_vt_score"),
               "min_engines": get_setting("hashcheck_vt_engines"),
               "per_minute": get_setting("hashcheck_vt_per_minute")},
        "cache": 86400,
        "max_size": get_setting("max_message_size_mb") * MIB,
    }, indent=1) + "\n"


def sync_redis(r):
    wanted = {"malwarebazaar": get_setting("hashcheck_mb_key"), "virustotal": get_setting("hashcheck_vt_key")}
    current = r.hgetall(KEYS)
    for field, value in wanted.items():
        if value and current.get(field) != value:
            r.hset(KEYS, field, value)
        elif not value and field in current:
            r.hdel(KEYS, field)


def hits(limit=100):
    """The latest detections, newest first. Raises redis.RedisError."""
    return [json.loads(e) for e in store.get_redis().lrange(HITS, 0, limit - 1)]


def _mhr(digest):
    if len(digest) != 32 and len(digest) != 40:
        return None, "needs the MD5 or SHA-1"
    try:
        answers = netcheck.lookup(f"{digest}.malware.hash.cymru.com", "TXT")
    except netcheck.NoRecords:
        return False, "not known"
    except netcheck.LookupFailed as exc:
        return None, str(exc)
    match = re.match(r"^\d+\s+(\d+)", answers[0] if answers else "")
    if not match:
        return None, "unexpected answer"
    percent = int(match.group(1))
    return percent >= get_setting("hashcheck_mhr_percent"), f"{percent}% of antivirus engines"


def _mb(digest, key):
    response = requests.post("https://mb-api.abuse.ch/api/v1/", data={"query": "get_info", "hash": digest},
                             headers={"Auth-Key": key}, timeout=TIMEOUT)
    body = response.json() if response.status_code == 200 else {}
    status = body.get("query_status")
    if status == "ok":
        return True, (body.get("data") or [{}])[0].get("signature") or "known malware"
    if status == "hash_not_found":
        return False, "not known"
    return None, status or f"HTTP {response.status_code}"


def _vt(digest, key):
    response = requests.get(f"https://www.virustotal.com/api/v3/files/{digest}", headers={"x-apikey": key},
                            timeout=TIMEOUT)
    if response.status_code == 404:
        return False, "not known"
    if response.status_code != 200:
        return None, f"HTTP {response.status_code}"
    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = int(stats.get("malicious") or 0)
    return malicious >= get_setting("hashcheck_vt_engines"), f"{malicious} engines"


def check(digest):
    """Look up a hash with every enabled source: {source: {"malicious": bool
    or None (no answer), "detail": text}}."""
    digest = (digest or "").strip().lower()
    if not _HASH_RE.match(digest):
        raise ServiceError("Enter an MD5, SHA-1 or SHA-256 hash in hex", "hash")
    results = {}
    lookups = [("mhr", lambda: _mhr(digest), get_setting("hashcheck_mhr")),
               ("mb", lambda: _mb(digest, get_setting("hashcheck_mb_key")), get_setting("hashcheck_mb_key")),
               ("vt", lambda: _vt(digest, get_setting("hashcheck_vt_key")), get_setting("hashcheck_vt_key"))]
    for source, lookup, enabled in lookups:
        if not enabled:
            continue
        try:
            malicious, detail = lookup()
        except (requests.RequestException, ValueError) as exc:
            malicious, detail = None, str(exc)
        results[source] = {"malicious": malicious, "detail": detail}
    return results
