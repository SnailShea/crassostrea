"""Redis access: Postfix logs, fail2ban integration (netfilter), login throttling and job locks."""
import json
from contextlib import contextmanager

import redis
from flask import current_app, g

# netfilter-crassostrea reads its ban rules from this key on every log message
# (services/netfilter/main.py writes the same rules when the key is missing).
F2B_REGEX = {
    "1": r"Crassostrea UI: Invalid password for .+ by ([0-9a-f\.:]+)",
    "2": r"warning: non-SMTP command from .*\[([0-9a-f\.:]+)]:.+",
    "3": r"NOQUEUE: reject: RCPT from \[([0-9a-f\.:]+)].+Protocol error.+",
    "4": r"Crassostrea API: Invalid API key by ([0-9a-f\.:]+)",
}


def get_redis():
    if "redis" not in g:
        cfg = current_app.config
        g.redis = redis.Redis(host=cfg["REDIS_HOST"], port=cfg["REDIS_PORT"],
                              password=cfg["REDIS_PASSWORD"], decode_responses=True,
                              socket_timeout=5, socket_connect_timeout=5)
    return g.redis


def ping():
    try:
        return bool(get_redis().ping())
    except redis.RedisError:
        return False


def seed_f2b_regex():
    r = get_redis()
    current = r.get("F2B_REGEX")
    # custom rules (without the web UI's rule) are left alone
    managed = current is None or "Crassostrea UI" in current
    if managed and current != json.dumps(F2B_REGEX):
        r.set("F2B_REGEX", json.dumps(F2B_REGEX))


def _failure_limits(ip, account=None):
    """{redis key: limit}. Failures count per client IP and, for logins, per
    account as well, so guessing one password from many addresses is limited
    too (at the price that an attacker can lock an account for the window)."""
    cfg = current_app.config
    limits = {f"WEB_LOGIN_FAILURES:{ip}": cfg["LOGIN_MAX_FAILURES"]}
    if account:
        limits[f"WEB_LOGIN_FAILURES_ACCOUNT:{account.strip().lower()}"] = cfg["LOGIN_MAX_ACCOUNT_FAILURES"]
    return limits


def report_failed_login(username, ip):
    report_auth_failure(f"Crassostrea UI: Invalid password for {username} by {ip}", ip, account=username)


def report_auth_failure(message, ip, account=None):
    """Publish an authentication failure for netfilter and count it for throttling."""
    r = get_redis()
    try:
        r.publish("F2B_CHANNEL", message)
        for key in _failure_limits(ip, account):
            count = r.incr(key)
            if count == 1:
                r.expire(key, current_app.config["LOGIN_FAILURE_WINDOW"])
    except redis.RedisError as exc:
        current_app.logger.warning("cannot record authentication failure: %s", exc)


def login_blocked(ip, account=None):
    limits = _failure_limits(ip, account)
    try:
        counts = get_redis().mget(list(limits))
    except redis.RedisError:
        return False
    return any(count is not None and int(count) >= limit for count, limit in zip(counts, limits.values()))


def clear_failed_logins(ip, account=None):
    try:
        get_redis().delete(*_failure_limits(ip, account))
    except redis.RedisError:
        pass


def clear_all_failed_logins():
    r = get_redis()
    for key in r.scan_iter("WEB_LOGIN_FAILURES*"):
        r.delete(key)


@contextmanager
def job_lock(name, timeout=3600, wait=0):
    """Run a job on one node at a time (the nodes of a cluster share redis).

    Yields True while holding the lock, False if another node holds it for
    longer than ``wait`` seconds. Without redis a single gateway runs the job
    anyway; a cluster does not, as the job might run on two nodes at once.
    """
    try:
        lock = get_redis().lock(f"SF_JOB_LOCK:{name}", timeout=timeout)
        acquired = lock.acquire(blocking=wait > 0, blocking_timeout=wait or None)
    except redis.RedisError as exc:
        if current_app.config["CLUSTER_NODES"]:
            raise
        current_app.logger.warning("cannot lock job %s, running it anyway: %s", name, exc)
        yield True
        return
    if not acquired:
        yield False
        return
    try:
        yield True
    finally:
        try:
            lock.release()
        except redis.RedisError:
            pass  # the lock expired or redis is gone: it times out anyway


def postfix_log(limit=500):
    entries = []
    for raw in get_redis().lrange("POSTFIX_MAILLOG", 0, limit - 1):
        try:
            entries.append(json.loads(raw))
        except ValueError:
            continue
    return entries


def trim_logs(lines):
    get_redis().ltrim("POSTFIX_MAILLOG", 0, max(lines, 1) - 1)


def banned_networks():
    """Active and permanent bans of netfilter-crassostrea."""
    r = get_redis()
    active = r.hgetall("F2B_ACTIVE_BANS")
    permanent = r.hgetall("F2B_PERM_BANS")
    queued = r.hgetall("F2B_QUEUE_UNBAN")
    bans = [{"network": net, "until": int(float(ts)), "permanent": False, "unban_queued": net in queued}
            for net, ts in active.items()]
    bans += [{"network": net, "until": None, "permanent": True, "unban_queued": net in queued}
             for net in permanent]
    return sorted(bans, key=lambda b: b["network"])


def queue_unban(network):
    get_redis().hset("F2B_QUEUE_UNBAN", network, 1)
