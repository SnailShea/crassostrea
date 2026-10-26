"""Monitoring: metrics for Prometheus (/metrics) and alert mail.

/metrics answers with a bearer token (``create_token``; only its SHA-256 is
stored) in the Prometheus text format: whether the database, Valkey, rspamd
and the services run, the mail queue, the quarantine and mail log, the
messages of the last hour and day, the certificate's expiry, the last
backup and the directory synchronisations.

``check`` evaluates the alert conditions (deferred mail piling up or
waiting long, the certificate expiring, no recent backup, a failing
directory synchronisation, a stopped service; in a cluster the queue and
services of every node and the cluster's problems, services/cluster.py).
``run_alerts`` (flask
check-alerts, crassostrea-job-alerts.timer, every 5 minutes) mails
alert_recipients when a condition starts failing, every 24 hours while it
fails and when it recovers; the state is kept in Valkey (sf_alert_state).
"""
import hashlib
import hmac
import json
import re
import secrets
import time
from datetime import timedelta
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid

import redis
from flask import current_app

from ..extensions import db
from ..models import Directory, MailLogEntry, QuarantineItem, StatBucket, get_setting, set_setting, utcnow
from . import backups, certificates, cluster, mailer, postfix_control, store, sysconf, system
from .rspamd import RspamdError, client

ALERT_STATE = "sf_alert_state"
# The failing checks as the last run saw them, for the sidebar of the web UI:
# {name: message}; expires when the alert job stops running
PROBLEMS = "sf_problems"
PROBLEMS_SECONDS = 900
REMIND_SECONDS = 24 * 3600
QUEUES = ("maildrop", "incoming", "active", "deferred", "hold")


# ---------------------------------------------------------------------------
# Token
# ---------------------------------------------------------------------------

def _hash(token):
    return hashlib.sha256(token.encode()).hexdigest()


def create_token():
    """A new /metrics token (shown once); replaces the old one."""
    token = "sfm_" + secrets.token_urlsafe(32)
    set_setting("metrics_token_hash", _hash(token))
    return token


def revoke_token():
    set_setting("metrics_token_hash", "")


def has_token():
    return bool(get_setting("metrics_token_hash"))


def token_valid(token):
    stored = get_setting("metrics_token_hash")
    return bool(stored and token) and hmac.compare_digest(stored, _hash(token))


# ---------------------------------------------------------------------------
# Collection
# ---------------------------------------------------------------------------

def _try(func, default=None):
    try:
        return func()
    except Exception as exc:  # a broken part must not hide the other metrics
        current_app.logger.info("monitoring: %s failed: %s", getattr(func, "__name__", "check"), exc)
        return default


def queue_state():
    """{queue: messages} and the age of the oldest deferred message, or None."""
    items = postfix_control.mail_queue()
    counts = {name: 0 for name in QUEUES}
    oldest = None
    for item in items:
        name = item.get("queue_name", "")
        counts[name] = counts.get(name, 0) + 1
        if name == "deferred" and item.get("arrival_time"):
            oldest = min(oldest or item["arrival_time"], item["arrival_time"])
    return counts, (time.time() - oldest) if oldest else 0


def _db_ok():
    db.session.execute(db.text("SELECT 1"))
    return True


def _rspamd_ok():
    try:
        client().stat()
        return True
    except RspamdError:
        return False


def _last_backup():
    found = backups.backups()
    status = backups.status() or {}
    return (found[0]["created_at"].timestamp() if found else None), status.get("state")


def collect():
    """The metrics: [(name, help, type, [(labels, value)])]."""
    now = utcnow()
    metrics = []

    def add(name, help_text, kind, samples):
        metrics.append((name, help_text, kind, [(labels, float(value)) for labels, value in samples
                                                if value is not None]))

    up = {"database": _try(_db_ok, False), "valkey": store.ping(), "rspamd": _try(_rspamd_ok, False)}
    add("sf_up", "Whether a component answers", "gauge", [({"component": k}, int(v)) for k, v in up.items()])
    units = _try(system.units, []) or []
    add("sf_service_active", "Whether a systemd unit of the gateway is active", "gauge",
        [({"unit": u["unit"]}, int(u["state"] == "active")) for u in units])
    queue = _try(queue_state)
    if queue:
        counts, oldest = queue
        add("sf_queue_messages", "Messages in the Postfix queue", "gauge",
            [({"queue": name}, count) for name, count in sorted(counts.items())])
        add("sf_queue_deferred_oldest_seconds", "Age of the oldest deferred message", "gauge", [({}, oldest)])
    if up["database"]:
        add("sf_quarantine_messages", "Quarantined messages (one per recipient)", "gauge",
            [({}, QuarantineItem.query.count())])
        add("sf_mail_log_messages", "Messages in the mail log", "gauge", [({}, MailLogEntry.query.count())])
        for window, label in ((timedelta(hours=1), "1h"), (timedelta(hours=24), "24h")):
            since = now.replace(minute=0, second=0, microsecond=0) - window + timedelta(hours=1)
            rows = (db.session.query(StatBucket.direction, StatBucket.category, db.func.sum(StatBucket.messages))
                    .filter(StatBucket.hour >= since).group_by(StatBucket.direction, StatBucket.category).all())
            add(f"sf_messages_{label}", f"Messages scanned in the current hour and the {label} before it"
                if label == "1h" else "Messages scanned in the last 24 hours (whole hours)", "gauge",
                [({"direction": d, "outcome": c}, int(n or 0)) for d, c, n in rows])
        for directory in Directory.query.all():
            add("sf_directory_sync_ok", "Whether the last synchronisation of a directory worked", "gauge",
                [({"directory": directory.name}, int(bool(directory.synced_at) and not directory.sync_error))])
    cert = _try(certificates.current_certificate)
    if cert:
        add("sf_certificate_expiry_seconds", "Seconds until the gateway's certificate expires", "gauge",
            [({}, (cert["not_after"] - certificates._now()).total_seconds())])
    last, state = _try(_last_backup, (None, None))
    add("sf_backup_last_timestamp_seconds", "Unix time of the newest backup", "gauge", [({}, last)])
    add("sf_backup_last_failed", "Whether the last backup failed", "gauge", [({}, int(state == "failed"))])
    if cluster.enabled():
        _cluster_metrics(add)
    return metrics


def _cluster_metrics(add):
    st = _try(cluster.state)
    if not st:
        return
    members = st["members"]
    add("sf_cluster_votes", "Votes of the cluster: all, needed for a majority, in the database cluster", "gauge",
        [({"kind": kind}, value) for kind, value in sorted(st["votes"].items())])
    add("sf_cluster_problems", "Problems of the cluster (Cluster page)", "gauge",
        [({"level": level}, sum(1 for p in st["problems"] if p["level"] == level))
         for level in ("critical", "warning")])
    add("sf_cluster_member_reporting", "Whether a node reported in the last minute", "gauge",
        [({"member": m["name"]}, int(m["reporting"])) for m in members])
    add("sf_cluster_member_report_age_seconds", "Seconds since a node last reported", "gauge",
        [({"member": m["name"]}, m["age"]) for m in members])
    fresh = [m for m in members if m["reporting"]]
    add("sf_cluster_member_maintenance", "Whether a node is in maintenance", "gauge",
        [({"member": m["name"]}, int(m["maintenance"])) for m in members])
    add("sf_cluster_member_database_synced", "Whether a node's database is synced in the primary component",
        "gauge", [({"member": m["name"]}, int((m["galera"] or {}).get("state") == "Synced"
                                              and (m["galera"] or {}).get("status") == "Primary")) for m in fresh])
    add("sf_cluster_member_valkey_master", "Whether a node is the Valkey master", "gauge",
        [({"member": m["name"]}, int((m["valkey"] or {}).get("role") == "master")) for m in fresh if m["probing"]])
    add("sf_cluster_member_valkey_lag_bytes", "Replication bytes a Valkey replica is behind the master", "gauge",
        [({"member": m["name"]}, (m["valkey"] or {}).get("lag_bytes")) for m in fresh if m["probing"]])
    add("sf_cluster_member_queue_messages", "Messages in a node's Postfix queue", "gauge",
        [({"member": m["name"], "queue": name}, count) for m in fresh if m["queue"]
         for name, count in sorted(m["queue"]["counts"].items())])
    if st["witness"]:
        add("sf_cluster_witness_up", "Whether the witness's Sentinel answers and its arbitrator is counted", "gauge",
            [({"component": c}, None if st["witness"][c] is None else int(st["witness"][c]))
             for c in ("sentinel", "arbitrator")])


def _escape(value):
    return str(value).replace("\\", "\\\\").replace("\n", "\\n").replace('"', '\\"')


def render(metrics):
    """The Prometheus text exposition format."""
    lines = []
    for name, help_text, kind, samples in metrics:
        lines.append(f"# HELP {name} {help_text}")
        lines.append(f"# TYPE {name} {kind}")
        for labels, value in samples:
            label_text = ",".join(f'{k}="{_escape(v)}"' for k, v in sorted(labels.items()))
            number = int(value) if value.is_integer() else value
            lines.append(f"{name}{{{label_text}}} {number}" if label_text else f"{name} {number}")
    return "\n".join(lines) + "\n"


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

def _queue_checks(results, queue, suffix=""):
    if queue is None:
        results["queue" + suffix] = {"ok": False,
                                     "message": "The mail queue cannot be read (Postfix control service)"}
        return
    counts, oldest = queue
    limit, hours = get_setting("alert_deferred_count"), get_setting("alert_deferred_hours")
    results["queue" + suffix] = {"ok": counts.get("deferred", 0) < limit,
                                 "message": f"{counts.get('deferred', 0)} deferred message(s) (alert from {limit})"}
    results["queue_age" + suffix] = {"ok": oldest < hours * 3600,
                                     "message": f"The oldest deferred message waits {oldest / 3600:.1f} h "
                                                f"(alert from {hours} h)" if oldest else "No deferred message"}


def _services_check(units):
    stopped = [u["unit"] for u in units if u["state"] != "active"]
    return {"ok": not stopped, "message": f"Not running: {', '.join(stopped)}" if stopped else "Every service runs"}


# What a cluster check says while it is fine (the recovery mail)
CLUSTER_OK = {"node": "Reports again", "database": "In sync", "probe": "The cluster service reports",
              "valkey": "Valkey replicates", "sentinel": "Sentinel reaches a majority", "disk": "Enough disk space",
              "maintenance": "Maintenance as requested", "witness": "The witness takes part",
              "vip": "The floating address is on one node", "versions": "Every node runs the same version",
              "mail": "Nodes accept mail"}


def _cluster_checks(results):
    """Per node: the queue and services from its report, and the cluster's
    problems under stable names (problem@node), so that they recover. A
    node that does not report only has node@: its other checks keep their
    state until it reports again."""
    st = _try(cluster.state)
    if st is None:
        results["database"] = {"ok": False, "message": "The cluster's state cannot be read from the database"}
        return
    names = ["database", "valkey", "mail", "versions"]
    names += ["witness"] if st["witness"] else []
    names += ["vip"] if st["vip"] else []
    for m in st["members"]:
        names.append(f"node@{m['name']}")
        if not m["reporting"]:
            continue
        names += [f"{kind}@{m['name']}" for kind in ("database", "probe", "valkey", "sentinel", "disk", "maintenance")]
        queue = m["queue"]
        _queue_checks(results, (queue["counts"], queue["oldest_deferred"]) if queue else None, f"@{m['name']}")
        if m["services"] is not None:
            results[f"services@{m['name']}"] = _services_check(m["services"])
    for name in names:
        results[name] = {"ok": True, "message": CLUSTER_OK[name.partition("@")[0]]}
    for p in st["problems"]:
        results[p["key"]] = {"ok": False, "message": p["message"]}


def check():
    """The alert conditions: {name: {"ok": bool, "message": text}}; in a
    cluster per node as name@node."""
    results = {}
    if cluster.enabled():
        _cluster_checks(results)
    else:
        _queue_checks(results, _try(queue_state))
    cert = _try(certificates.current_certificate)
    days = get_setting("alert_cert_days")
    results["certificate"] = ({"ok": False, "message": "No certificate is installed"} if not cert else
                              {"ok": cert["days_left"] >= days,
                               "message": f"The certificate expires in {cert['days_left']} day(s) "
                                          f"(alert from {days})"})
    last, state = _try(_last_backup, (None, None))
    hours = get_setting("alert_backup_hours")
    if state == "failed":
        results["backup"] = {"ok": False, "message": "The last backup failed (Backups page)"}
    else:
        age = (time.time() - last) / 3600 if last else None
        results["backup"] = {"ok": age is not None and age < hours,
                             "message": f"The newest backup is {age:.0f} h old (alert from {hours} h)"
                             if age is not None else "There is no backup"}
    failing = [d.name for d in _try(lambda: Directory.query.filter(Directory.sync_error != "").all(), []) or []]
    results["directories"] = {"ok": not failing,
                              "message": f"Not synchronised: {', '.join(failing)}" if failing
                              else "Every directory synchronises"}
    if not cluster.enabled():
        units = _try(system.units)
        if units is not None:
            results["services"] = _services_check(units)
    return results


LABELS = {"queue": "Deferred mail", "queue_age": "Mail waiting", "certificate": "Certificate", "backup": "Backup",
          "directories": "Directories", "services": "Services", "node": "Cluster node", "database": "Database cluster",
          "probe": "Cluster service", "valkey": "Valkey", "sentinel": "Sentinel", "disk": "Disk space",
          "maintenance": "Maintenance", "witness": "Witness", "vip": "Floating address", "versions": "Versions",
          "mail": "Mail acceptance"}


def label(name):
    """A check's name for people: "Deferred mail (mx2.example.com)"."""
    base, _, node = name.partition("@")
    text = LABELS.get(base, base)
    return f"{text} ({node})" if node else text


def _message(recipients, failing, recovered):
    hostname = current_app.config["HOSTNAME"]
    msg = EmailMessage()
    msg["From"] = formataddr(("Mail gateway", f"alerts@{hostname}"))
    msg["To"] = ", ".join(recipients)
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain=hostname)
    parts = []
    if failing:
        parts.append(f"{len(failing)} problem(s)")
    if recovered:
        parts.append(f"{len(recovered)} solved")
    msg["Subject"] = f"[{hostname}] {', '.join(parts)}"
    body = [f"The mail gateway {hostname} found:", ""]
    body += [f"PROBLEM  {label(n)}: {m}" for n, m in failing]
    body += [f"SOLVED   {label(n)}: {m}" for n, m in recovered]
    body += ["", f"https://{hostname}/monitoring/"]
    if cluster.enabled():
        body.append(f"https://{hostname}/cluster/")
    msg.set_content("\n".join(body) + "\n")
    return msg


def _send(recipients, failing, recovered):
    message = _message(recipients, failing, recovered).as_bytes()
    for recipient in recipients:
        mailer.reinject(f"alerts@{current_app.config['HOSTNAME']}", recipient, message)


def send_test():
    """A test alert to alert_recipients. Returns them; raises mailer.ReleaseError."""
    recipients = get_setting("alert_recipients").split()
    if recipients:
        _send(recipients, [("test", "This is a test of the alert mail")], [])
    return recipients


def run_alerts(results=None, now=None):
    """Mail the changes since the last run. Returns (failing, recovered) sent.
    Raises mailer.ReleaseError if the mail cannot be sent (the next run tries
    again)."""
    results = results if results is not None else check()
    record_problems(results)
    recipients = get_setting("alert_recipients").split()
    if not recipients:
        return [], []
    now = now or time.time()
    r = store.get_redis()
    state = {k: json.loads(v) for k, v in r.hgetall(ALERT_STATE).items()}
    failing, recovered = [], []
    for name, result in results.items():
        previous = state.get(name)
        if not result["ok"]:
            if previous is None or now - previous.get("sent", 0) >= REMIND_SECONDS:
                failing.append((name, result["message"]))
                state[name] = {"since": (previous or {}).get("since", now), "sent": now}
        elif previous is not None:
            recovered.append((name, result["message"]))
            state.pop(name)
    if failing or recovered:
        _send(recipients, failing, recovered)
    pipe = r.pipeline()
    pipe.delete(ALERT_STATE)
    if state:
        pipe.hset(ALERT_STATE, mapping={k: json.dumps(v) for k, v in state.items()})
    pipe.execute()
    return failing, recovered


RELEASE_RE = re.compile(r"^v\d+\.\d+\.\d+$")
UPDATE_CHANNELS = {"release": "the newest release", "main": "the newest commit of the branch"}


def deployed():
    """The deployed version for the Monitoring page: {version, deployed_at,
    release_url (a release exactly, else None), channel (update.sh)}."""
    name, deployed_at = cluster.version()
    channel = sysconf.read(("UPDATE_CHANNEL",)).get("UPDATE_CHANNEL") or "release"
    url = f"{current_app.config['PROJECT_URL']}/releases/tag/{name}" if RELEASE_RE.match(name) else None
    return {"version": name or "unknown", "deployed_at": deployed_at, "release_url": url,
            "channel": UPDATE_CHANNELS.get(channel, channel)}


def record_problems(results):
    """Keep the failing checks for the sidebar (``problems``)."""
    failing = {name: result["message"] for name, result in results.items() if not result["ok"]}
    try:
        pipe = store.get_redis().pipeline()
        pipe.delete(PROBLEMS)
        if failing:
            pipe.hset(PROBLEMS, mapping=failing)
            pipe.expire(PROBLEMS, PROBLEMS_SECONDS)
        pipe.execute()
    except redis.RedisError:
        pass


def problems():
    """The failing checks recorded by the last run (alert job every 5
    minutes, or the Monitoring page): {name: message}."""
    try:
        return store.get_redis().hgetall(PROBLEMS)
    except redis.RedisError:
        return {}


def alert_state():
    """The conditions failing now, as recorded by the last run: {name: since}."""
    return {k: json.loads(v).get("since") for k, v in store.get_redis().hgetall(ALERT_STATE).items()}
