"""Cluster management and monitoring (Cluster page, /api/v1/cluster).

Every full node runs ``flask cluster-report`` (crassostrea-cluster-report.service):
every REPORT_SECONDS it writes what it knows about itself into its row of
cluster_reports (``collect``: database, Valkey and Sentinel, the floating
address, mail queue, services, load, disk, version) and carries out what the
administrators want of it (cluster_control: maintenance, becoming the Valkey
master) by writing CLUSTER_REQUEST for the root service
system/libexec/cluster-node. That service applies it and probes what needs
the cluster certificate (Valkey and Sentinel over TLS, the floating address)
into CLUSTER_PROBE, which the report includes.

``state`` combines the reports of all nodes into the cluster's state and its
problems, for the page, the alert mail and /metrics. The witness runs no web
UI: it is seen through the nodes (its Sentinel answers them, the arbitrator
counts in the database cluster's size).

Building the cluster in the web UI, like Proxmox: a single gateway creates a
cluster of one node (``request_create``, system/libexec/cluster-setup runs
setup.sh --ha); a member hands out a one-time join information
(``join_information``); another single gateway joins with it
(``request_join``): its cluster-setup asks the member (``join``, POST
/cluster/join, pinned to the member's certificate), which adds it to the
membership (cluster_membership) and returns its join bundle once the member
has applied the membership, then runs setup.sh --join. Every member applies a
changed membership itself (``reconcile``, cluster-node).
"""
import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import time
from datetime import timedelta, timezone

from flask import current_app

from ..extensions import db
from ..models import ClusterControl, ClusterJoinToken, ClusterMembership, ClusterReport, hash_token, utcnow
from . import sysconf
from .errors import ServiceError

REPORT_SECONDS = 10
# A report (or probe) older than this counts as missing
STALE_SECONDS = 60
# A request is written again if the node has not carried it out by then
RETRY_SECONDS = 60
# A request to become the Valkey master that waited longer is dropped
PROMOTE_SECONDS = 300
# Different versions are normal while the nodes are updated one by one
VERSION_GRACE_SECONDS = 3600
DISK_WARN_PERCENT = 90
# Filesystems whose use is reported (each one once)
DISK_PATHS = ("/", "/var", "/var/lib/mysql", "/var/spool/postfix")
# A join information works once, for this long
JOIN_SECONDS = 3600
JOIN_PREFIX = "sfjoin1."
# A bundle request the member did not answer is written again after this
BUNDLE_RETRY_SECONDS = 120
HOSTNAME_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")
GALERA_STATUS = ("wsrep_local_state_comment", "wsrep_cluster_status", "wsrep_cluster_size", "wsrep_ready",
                 "wsrep_local_recv_queue_avg", "wsrep_flow_control_paused")


def enabled():
    return bool(current_app.config["CLUSTER_NODES"])


def parse_members(text):
    """[(hostname, address)] of HA_NODES-style text (hostname=address,...)."""
    return [tuple(part.strip().lower() for part in entry.split("=", 1))
            for entry in (text or "").split(",") if "=" in entry]


def format_members(pairs):
    return ",".join(f"{name}={address}" for name, address in pairs)


def membership():
    """The membership row (None before the cluster wrote it)."""
    return db.session.get(ClusterMembership, 1)


def nodes():
    """The full nodes: the cluster's membership, else this member's
    configuration (HA_NODES at the start of the process)."""
    row = _try(membership)
    return parse_members(row.nodes) if row and row.nodes else list(current_app.config["CLUSTER_NODES"])


def witness():
    row = _try(membership)
    if row and row.nodes:
        found = parse_members(row.witness)
        return found[0] if found else None
    return current_app.config["CLUSTER_WITNESS"]


def votes():
    total = len(nodes()) + (1 if witness() else 0)
    return total, total // 2 + 1


def _try(func, default=None):
    try:
        return func()
    except Exception as exc:  # a broken part must not hide the others
        current_app.logger.info("cluster report: %s failed: %s", getattr(func, "__name__", "part"), exc)
        db.session.rollback()
        return default


# ---------------------------------------------------------------------------
# This node's report
# ---------------------------------------------------------------------------

def _galera():
    rows = db.session.execute(db.text(
        "SHOW GLOBAL STATUS WHERE Variable_name IN ("
        + ", ".join(f"'{name}'" for name in GALERA_STATUS) + ")")).all()
    values = {name.lower(): value for name, value in rows}
    if not values:
        return None

    def number(key, kind=int):
        try:
            return kind(values.get(key) or 0)
        except ValueError:
            return 0
    return {"state": values.get("wsrep_local_state_comment", ""), "status": values.get("wsrep_cluster_status", ""),
            "size": number("wsrep_cluster_size"), "ready": values.get("wsrep_ready", "").upper() == "ON",
            "recv_queue": number("wsrep_local_recv_queue_avg", float),
            "flow_paused": number("wsrep_flow_control_paused", float)}


def probe():
    """What system/libexec/cluster-node last found (None if it does not run)."""
    try:
        with open(current_app.config["CLUSTER_PROBE"], encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def version():
    """(version, unix time it was deployed) from system/configure.sh."""
    try:
        with open(current_app.config["VERSION_FILE"], encoding="utf-8") as fh:
            lines = fh.read().split("\n")
    except OSError:
        return "", 0
    try:
        deployed = int(lines[1]) if len(lines) > 1 else 0
    except ValueError:
        deployed = 0
    return lines[0].strip()[:64], deployed


def _memory():
    info = {}
    with open("/proc/meminfo", encoding="ascii") as fh:
        for line in fh:
            key, _, value = line.partition(":")
            info[key] = int(value.split()[0])
    total = info.get("MemTotal") or 0
    return round(100.0 * (total - info.get("MemAvailable", 0)) / total, 1) if total else None


def _disk():
    seen, result = set(), []
    for path in DISK_PATHS:
        try:
            st = os.statvfs(path)
        except OSError:
            continue
        if st.f_fsid in seen or not st.f_blocks:
            continue
        seen.add(st.f_fsid)
        used = 100.0 * (st.f_blocks - st.f_bfree) / (st.f_blocks - st.f_bfree + st.f_bavail)
        result.append({"path": path, "used_percent": round(used, 1), "free_bytes": st.f_bavail * st.f_frsize})
    return result


def _uptime():
    with open("/proc/uptime", encoding="ascii") as fh:
        return int(float(fh.read().split()[0]))


def _queue():
    from . import monitoring
    counts, oldest = monitoring.queue_state()
    return {"counts": counts, "oldest_deferred": int(oldest)}


def _services():
    from . import system
    return [{"unit": u["unit"], "state": u["state"]} for u in system.units()]


def _scanned():
    from .rspamd import client
    return client().stat().get("scanned", 0)


def collect():
    """This node's report (stored as JSON in cluster_reports)."""
    name, deployed = version()
    return {
        "version": name, "deployed_at": deployed,
        "galera": _try(_galera),
        "probe": probe(),
        "queue": _try(_queue),
        "services": _try(_services),
        "scanned": _try(_scanned),
        "load": _try(lambda: [round(x, 2) for x in os.getloadavg()]),
        "cpus": os.cpu_count(),
        "memory_percent": _try(_memory),
        "disk": _try(_disk, []),
        "uptime": _try(_uptime),
    }


def publish(data):
    hostname = current_app.config["HOSTNAME"]
    row = db.session.get(ClusterReport, hostname)
    if row is None:
        row = ClusterReport(hostname=hostname)
        db.session.add(row)
    row.data = json.dumps(data, separators=(",", ":"))
    row.updated_at = utcnow()
    db.session.commit()


# The request last written and when (one cluster-report process per node)
_last_request = {}


def reconcile(found):
    """Write CLUSTER_REQUEST if this node is not what cluster_control asks
    for. Returns the request written, or None."""
    hostname = current_app.config["HOSTNAME"]
    control = db.session.get(ClusterControl, hostname)
    found = found or {}
    wanted = {}
    if bool(control and control.maintenance) != bool(found.get("maintenance")):
        wanted["maintenance"] = "on" if control and control.maintenance else "off"
    if (control and control.promote_token and control.promote_at
            and utcnow() - control.promote_at < timedelta(seconds=PROMOTE_SECONDS)
            and (found.get("promote") or {}).get("token") != control.promote_token):
        wanted["promote"] = control.promote_token
    # the cluster's membership, if this member's configuration differs
    row = membership()
    if row is not None and row.nodes:
        conf = sysconf.read(("HA_NODES", "HA_WITNESS"))
        if (parse_members(row.nodes) != parse_members(conf.get("HA_NODES"))
                or parse_members(row.witness) != parse_members(conf.get("HA_WITNESS"))):
            wanted["members"] = row.nodes
            wanted["witness"] = row.witness
    if not wanted:
        _last_request.clear()
        return None
    if _last_request.get("wanted") == wanted and time.time() - _last_request["at"] < RETRY_SECONDS:
        return None
    path = current_app.config["CLUSTER_REQUEST"]
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="ascii") as fh:
        fh.write("".join(f"{key}={value}\n" for key, value in sorted(wanted.items())))
    os.replace(tmp, path)
    _last_request.update(wanted=wanted, at=time.time())
    return wanted


def seed_membership():
    """The membership from this member's configuration, the first time."""
    if membership() is not None:
        return
    conf = sysconf.read(("HA_NODES", "HA_WITNESS"))
    if not parse_members(conf.get("HA_NODES")):
        return
    db.session.add(ClusterMembership(id=1, nodes=format_members(parse_members(conf["HA_NODES"])),
                                     witness=format_members(parse_members(conf.get("HA_WITNESS"))),
                                     changed_by="configuration"))
    db.session.commit()


def report_once():
    data = collect()
    publish(data)
    seed_membership()
    return reconcile(data["probe"])


# ---------------------------------------------------------------------------
# The cluster's state
# ---------------------------------------------------------------------------

def duration(seconds):
    seconds = int(seconds)
    if seconds < 120:
        return f"{seconds} s"
    if seconds < 7200:
        return f"{seconds // 60} min"
    if seconds < 172800:
        return f"{seconds // 3600} h"
    return f"{seconds // 86400} days"


def _node_state(name, address, report, control, now):
    data = {}
    if report is not None:
        try:
            data = json.loads(report.data or "{}")
        except ValueError:
            data = {}
    age = (now - report.updated_at).total_seconds() if report is not None else None
    found = data.get("probe") or {}
    probe_age = time.time() - found["at"] if isinstance(found.get("at"), (int, float)) else None
    promote = control.promote_token if control and control.promote_token and control.promote_at and \
        now - control.promote_at < timedelta(seconds=PROMOTE_SECONDS) else ""
    services = data.get("services")
    return {
        "name": name, "address": address, "role": "node", "self": name == current_app.config["HOSTNAME"],
        "reported_at": report.updated_at if report is not None else None, "age": age,
        "reporting": age is not None and age < STALE_SECONDS,
        "probing": probe_age is not None and probe_age < STALE_SECONDS,
        "maintenance": bool(control and control.maintenance),
        "maintenance_applied": bool(found.get("maintenance")),
        "maintenance_since": control.changed_at if control and control.maintenance else None,
        "changed_by": control.changed_by if control else "",
        "promoting": bool(promote) and (found.get("promote") or {}).get("token") != promote,
        "last_action": found.get("last_action") or None,
        "galera": data.get("galera"),
        "valkey": found.get("valkey") or None,
        "sentinel": found.get("sentinel") or None,
        "vip": found.get("vip"),
        "queue": data.get("queue"),
        "services": services,
        "services_down": [s["unit"] for s in services or [] if s.get("state") != "active"],
        "scanned": data.get("scanned"),
        "load": data.get("load"), "cpus": data.get("cpus"), "memory_percent": data.get("memory_percent"),
        "disk": data.get("disk") or [], "uptime": data.get("uptime"),
        "version": data.get("version", ""), "deployed_at": data.get("deployed_at") or 0,
    }


def state(now=None):
    """The cluster as the reports show it (None for a single gateway)."""
    if not enabled():
        return None
    cfg = current_app.config
    now = now or utcnow()
    reports = {r.hostname: r for r in ClusterReport.query.all()}
    controls = {c.hostname: c for c in ClusterControl.query.all()}
    members = [_node_state(name, address, reports.get(name), controls.get(name), now) for name, address in nodes()]
    fresh = [m for m in members if m["reporting"]]
    problems, notices = [], []

    def problem(key, level, message):
        problems.append({"key": key, "level": level, "message": message})

    for m in members:
        if not m["reporting"]:
            problem(f"node@{m['name']}", "critical", f"{m['name']} has not reported for {duration(m['age'])}"
                    if m["age"] is not None else f"{m['name']} has never reported (crassostrea-cluster-report)")
            continue
        galera = m["galera"]
        if not galera:
            problem(f"database@{m['name']}", "warning", f"{m['name']}: its database state cannot be read")
        elif galera["status"] != "Primary" or galera["state"] not in ("Synced", "Donor/Desynced"):
            level = "critical" if galera["status"] != "Primary" else "warning"
            problem(f"database@{m['name']}", level, f"{m['name']}: database {galera['status'] or 'unknown'}, "
                                                    f"{galera['state'] or 'unknown'}")
        if not m["probing"]:
            problem(f"probe@{m['name']}", "warning",
                    f"{m['name']}: the cluster service does not report (crassostrea-cluster.service)")
        elif m["valkey"] and m["valkey"].get("role") == "slave" and m["valkey"].get("link") != "up":
            problem(f"valkey@{m['name']}", "warning", f"{m['name']}: its Valkey replica is not connected to "
                                                      "the master")
        elif m["valkey"] is not None and not m["valkey"].get("role"):
            problem(f"valkey@{m['name']}", "warning", f"{m['name']}: Valkey does not answer")
        sentinel = m["sentinel"]
        if m["probing"] and sentinel is not None and not sentinel.get("quorum"):
            problem(f"sentinel@{m['name']}", "warning",
                    f"{m['name']}: Sentinel cannot reach a majority ({sentinel.get('message') or 'no answer'})")
        for disk in m["disk"]:
            if disk.get("used_percent", 0) >= DISK_WARN_PERCENT:
                problem(f"disk@{m['name']}", "warning",
                        f"{m['name']}: {disk['path']} is {disk['used_percent']:.0f}% full")
                break
        if m["maintenance"]:
            if not m["maintenance_applied"] and m["maintenance_since"] and \
                    (now - m["maintenance_since"]).total_seconds() > RETRY_SECONDS:
                problem(f"maintenance@{m['name']}", "warning",
                        f"{m['name']}: maintenance was requested but is not in effect")
            notices.append(f"{m['name']} is in maintenance since {m['maintenance_since']:%Y-%m-%d %H:%M} UTC"
                           + (f" ({m['changed_by']})" if m["changed_by"] else ""))

    total, quorum = votes()
    primaries = [m for m in fresh if (m["galera"] or {}).get("status") == "Primary"]
    present = max((m["galera"]["size"] for m in primaries), default=0)
    if fresh and not primaries:
        problem("database", "critical", "No node reports a primary database component")
    elif primaries and present < quorum:
        problem("database", "critical", f"{present} of {total} votes in the database cluster: no majority")
    elif primaries and present < total:
        problem("database", "warning", f"{present} of {total} votes in the database cluster")

    probed = [m for m in fresh if m["probing"] and m["valkey"] is not None]
    masters = [m["name"] for m in probed if m["valkey"].get("role") == "master"]
    master_offset = next((m["valkey"].get("offset", 0) for m in probed if m["valkey"].get("role") == "master"), None)
    for m in probed:
        if m["valkey"].get("role") == "slave" and master_offset is not None:
            m["valkey"]["lag_bytes"] = max(0, master_offset - (m["valkey"].get("offset") or 0))
    if probed and not masters:
        problem("valkey", "critical", "No node is the Valkey master")
    elif len(masters) > 1:
        problem("valkey", "critical", f"Several nodes are Valkey masters: {', '.join(masters)}")

    witness_state = None
    if witness():
        name, address = witness()
        answers = [m["sentinel"].get("witness") for m in fresh if m["probing"] and m["sentinel"]]
        answers = [a for a in answers if a is not None]
        nodes_in = sum(1 for m in primaries if m["galera"]["size"] == present)
        witness_state = {"name": name, "address": address, "role": "witness",
                         "sentinel": any(answers) if answers else None,
                         "arbitrator": (present > nodes_in) if primaries else None}
        missing = []
        if witness_state["sentinel"] is False:
            missing.append("its Sentinel does not answer")
        if witness_state["arbitrator"] is False:
            missing.append("the arbitrator is not in the database cluster")
        if missing:
            problem("witness", "warning", f"Witness {name}: {' and '.join(missing)}")

    vip = None
    if cfg["CLUSTER_VIP"]:
        holders = [m["name"] for m in fresh if m["probing"] and m["vip"]]
        vip = {"address": cfg["CLUSTER_VIP"], "holders": holders}
        if len(holders) > 1:
            problem("vip", "critical", f"The floating address {cfg['CLUSTER_VIP']} is on several nodes: "
                                       f"{', '.join(holders)}")
        elif not holders and any(m["probing"] for m in fresh):
            problem("vip", "warning", f"The floating address {cfg['CLUSTER_VIP']} is on no node")

    versions = {m["version"] for m in fresh if m["version"]}
    if len(versions) > 1 and time.time() - max(m["deployed_at"] for m in fresh) > VERSION_GRACE_SECONDS:
        problem("versions", "warning", "The nodes run different versions: "
                + ", ".join(f"{m['name']} {m['version'] or 'unknown'}" for m in fresh))

    accepting = [m for m in fresh if not m["maintenance"] and (m["galera"] or {}).get("state") == "Synced"]
    if fresh and not accepting:
        problem("mail", "critical", "No node accepts mail: every node is in maintenance or out of sync")

    levels = {p["level"] for p in problems}
    return {
        "self": cfg["HOSTNAME"], "members": members, "witness": witness_state, "vip": vip,
        "votes": {"total": total, "quorum": quorum, "present": present},
        "valkey_master": masters[0] if len(masters) == 1 else None,
        "problems": problems, "notices": notices,
        "level": "critical" if "critical" in levels else "warning" if levels else "ok",
    }


# ---------------------------------------------------------------------------
# Changes
# ---------------------------------------------------------------------------

def _member(name):
    name = (name or "").strip().lower()
    if name not in dict(nodes()):
        raise ServiceError(f"{name or 'The name'} is not a node of this cluster", field="node", status=404)
    return name


def _control(name):
    row = db.session.get(ClusterControl, name)
    if row is None:
        row = ClusterControl(hostname=name, maintenance=False, changed_by="", promote_token="")
        db.session.add(row)
    return row


def set_maintenance(name, on, actor, force=False):
    """Put a node into maintenance or take it out (the caller commits).

    A node in maintenance answers new SMTP connections with 421, so senders
    use the other MX records, hands over the Valkey master and the floating
    address, and keeps delivering its queue. Refused if no other node would
    accept mail, unless ``force``."""
    if not enabled():
        raise ServiceError("This gateway is not part of a cluster", status=409)
    name = _member(name)
    if on:
        current = state()
        others = [m for m in current["members"] if m["name"] != name and m["reporting"] and not m["maintenance"]
                  and (m["galera"] or {}).get("state") == "Synced"]
        if not others and not force:
            raise ServiceError(f"No other node is reporting, in sync and out of maintenance: {name} is needed to "
                               "accept mail", status=409)
    row = _control(name)
    if row.maintenance != bool(on):
        row.maintenance = bool(on)
        row.changed_by = (actor or "")[:64]
        row.changed_at = utcnow()
    if on:
        row.promote_token = ""
    return row


def request_valkey_master(name, actor):
    """Make a node the Valkey master (Sentinel hands it over within about
    30 seconds; the caller commits)."""
    if not enabled():
        raise ServiceError("This gateway is not part of a cluster", status=409)
    name = _member(name)
    member = next(m for m in state()["members"] if m["name"] == name)
    if not member["reporting"] or not member["probing"]:
        raise ServiceError(f"{name} is not reporting", status=409)
    if member["maintenance"]:
        raise ServiceError(f"{name} is in maintenance: take it out first", status=409)
    valkey = member["valkey"] or {}
    if valkey.get("role") == "master":
        raise ServiceError(f"{name} already is the Valkey master", status=409)
    if valkey.get("role") != "slave" or valkey.get("link") != "up":
        raise ServiceError(f"The Valkey replica of {name} is not connected to the master", status=409)
    row = _control(name)
    row.promote_token = secrets.token_hex(8)
    row.promote_at = utcnow()
    current_app.logger.info("cluster: %s asked to make %s the Valkey master", actor, name)
    return row


# ---------------------------------------------------------------------------
# Building the cluster
# ---------------------------------------------------------------------------

def _write_json(path, data):
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="utf-8") as handle:
        json.dump(data, handle)
    os.replace(tmp, path)


def _valid_address(address, field="address"):
    try:
        ip = ipaddress.IPv4Address((address or "").strip())
    except ValueError:
        raise ServiceError("The cluster address must be an IPv4 address", field) from None
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local:
        raise ServiceError(f"{ip} cannot be a cluster address", field)
    return str(ip)


def certificate_fingerprint():
    """SHA-256 of this node's HTTPS certificate (DER), as the joining node pins it."""
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    with open(current_app.config["SSL_CERT"], "rb") as handle:
        cert = x509.load_pem_x509_certificates(handle.read())[0]
    return hashlib.sha256(cert.public_bytes(Encoding.DER)).hexdigest()


def join_information(actor):
    """A one-time join information (JOIN_SECONDS) for another gateway:
    this member's name, cluster address, HTTPS port and certificate, and a
    secret (only its hash is stored)."""
    if not enabled():
        raise ServiceError("This gateway is not part of a cluster", status=409)
    hostname = current_app.config["HOSTNAME"]
    address = dict(nodes()).get(hostname)
    if not address:
        raise ServiceError(f"{hostname} is not a node of the cluster", status=409)
    try:
        fingerprint = certificate_fingerprint()
    except (OSError, ValueError, IndexError) as exc:
        raise ServiceError(f"Cannot read this node's certificate: {exc}", status=503) from exc
    token = secrets.token_urlsafe(32)
    db.session.add(ClusterJoinToken(token_hash=hash_token(token), created_by=(actor or "")[:64],
                                    expires_at=utcnow() + timedelta(seconds=JOIN_SECONDS)))
    info = {"host": hostname, "address": address, "port": current_app.config["HTTPS_PORT"],
            "fingerprint": fingerprint, "token": token}
    encoded = base64.urlsafe_b64encode(json.dumps(info, separators=(",", ":")).encode()).decode().rstrip("=")
    return {"information": JOIN_PREFIX + encoded, "expires_in": JOIN_SECONDS, **{k: info[k] for k in
                                                                               ("host", "address", "fingerprint")}}


def decode_join_information(text):
    """The fields of a join information; raises ServiceError."""
    text = re.sub(r"\s+", "", text or "")
    if not text.startswith(JOIN_PREFIX):
        raise ServiceError("This is no join information (it starts with sfjoin1.)", "information")
    try:
        raw = text[len(JOIN_PREFIX):]
        info = json.loads(base64.urlsafe_b64decode(raw + "=" * (-len(raw) % 4)))
    except ValueError:
        raise ServiceError("The join information is damaged: copy it again", "information") from None
    if not isinstance(info, dict):
        raise ServiceError("The join information is damaged: copy it again", "information")
    host, port = str(info.get("host", "")).lower(), info.get("port")
    if not HOSTNAME_RE.match(host) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise ServiceError("The join information is damaged: copy it again", "information")
    if not re.fullmatch(r"[0-9a-f]{64}", str(info.get("fingerprint", ""))) \
            or not re.fullmatch(r"[A-Za-z0-9_-]{20,100}", str(info.get("token", ""))):
        raise ServiceError("The join information is damaged: copy it again", "information")
    return {"host": host, "address": _valid_address(info.get("address"), "information"), "port": port,
            "fingerprint": info["fingerprint"], "token": info["token"]}


def _bundle_path(host):
    return os.path.join(current_app.config["CLUSTER_BUNDLE_DIR"], f"{host}.tar")


def _request_bundle(row, host):
    """Ask this member's cluster-node to apply the membership and write the
    join bundle of host."""
    path = current_app.config["CLUSTER_BUNDLE_REQUEST"]
    tmp = f"{path}.tmp"
    with open(tmp, "w", encoding="ascii") as handle:
        handle.write(f"members={row.nodes}\nwitness={row.witness}\nhost={host}\n")
    os.replace(tmp, path)


def join(token, hostname, address):
    """A gateway joins (POST /cluster/join, by its cluster-setup): the first
    call adds it to the membership and asks for its bundle; later calls
    return (202, None) until the bundle is there, then (200, bytes) once."""
    hostname = (hostname or "").strip().lower()
    row = db.session.get(ClusterJoinToken, hash_token(token or "")) if token else None
    now = utcnow()
    if row is None or row.expires_at < now or (row.used_by and row.used_by != hostname):
        raise ServiceError("The join information is invalid, used or expired: create a new one", status=403)
    if not row.used_by:
        if not HOSTNAME_RE.match(hostname) or len(hostname) > 253:
            raise ServiceError("Invalid hostname", "hostname")
        address = _valid_address(address)
        current = nodes()
        taken = dict(current)
        if hostname in taken or (witness() and witness()[0] == hostname):
            raise ServiceError(f"{hostname} is already a member of the cluster", status=409)
        if address in taken.values() or (witness() and witness()[1] == address):
            raise ServiceError(f"The address {address} is already used by a member", status=409)
        members = membership()
        if members is None:
            members = ClusterMembership(id=1, nodes=format_members(current),
                                        witness=format_members([witness()] if witness() else []))
            db.session.add(members)
        members.nodes = format_members(current + [(hostname, address)])
        members.changed_by = f"join:{hostname}"[:64]
        members.changed_at = now
        row.used_by, row.used_at = hostname, now
        db.session.commit()
        _request_bundle(members, hostname)
        current_app.logger.info("cluster: %s (%s) joins", hostname, address)
        return 202, None
    path = _bundle_path(hostname)
    if os.path.exists(path) and os.path.getmtime(path) >= row.used_at.replace(tzinfo=timezone.utc).timestamp() - 5:
        with open(path, "rb") as handle:
            bundle = handle.read()
        os.remove(path)
        row.expires_at = now  # delivered: the information is spent
        db.session.commit()
        return 200, bundle
    if (not os.path.exists(current_app.config["CLUSTER_BUNDLE_REQUEST"])
            and (now - row.used_at).total_seconds() > BUNDLE_RETRY_SECONDS):
        _request_bundle(membership(), hostname)
    return 202, None


def remove_node(name, actor):
    """Remove a full node that is switched off (it does not report), like
    pvecm delnode; the others apply it. The caller commits."""
    name = _member(name)
    if name == current_app.config["HOSTNAME"]:
        raise ServiceError("A node cannot remove itself: remove it on another node", status=409)
    member = next(m for m in state()["members"] if m["name"] == name)
    if member["reporting"]:
        raise ServiceError(f"{name} is running: switch it off first (it must not run again with this cluster's "
                           "data, reinstall it to use it again)", status=409)
    remaining = [n for n in nodes() if n[0] != name]
    row = membership() or ClusterMembership(id=1, witness=format_members([witness()] if witness() else []))
    row.nodes = format_members(remaining)
    row.changed_by, row.changed_at = (actor or "")[:64], utcnow()
    db.session.merge(row)
    ClusterReport.query.filter_by(hostname=name).delete()
    ClusterControl.query.filter_by(hostname=name).delete()
    return remaining


def remove_witness(actor):
    """Remove the witness from the membership (the caller commits)."""
    if not witness():
        raise ServiceError("The cluster has no witness", status=404)
    row = membership() or ClusterMembership(id=1, nodes=format_members(nodes()))
    row.witness = ""
    row.changed_by, row.changed_at = (actor or "")[:64], utcnow()
    db.session.merge(row)


# A single gateway creating or joining a cluster (system/libexec/cluster-setup)

def setup_status():
    """The outcome of the last create or join, or None."""
    try:
        with open(current_app.config["CLUSTER_SETUP_STATUS"], encoding="utf-8") as handle:
            entry = json.load(handle)
    except (OSError, ValueError):
        return None
    return entry if isinstance(entry, dict) else None


def setup_busy():
    return (os.path.exists(current_app.config["CLUSTER_SETUP_REQUEST"])
            or (setup_status() or {}).get("state") == "running")


def local_addresses():
    """IPv4 addresses of this server's interfaces, for the cluster address."""
    from . import ipconfig
    try:
        return [a.split("/")[0] for i in ipconfig.interfaces() for a in i["live4"]]
    except Exception:
        return []


def _setup_request(data):
    if setup_busy():
        raise ServiceError("A cluster setup is already running; wait for its result", status=409)
    try:
        _write_json(current_app.config["CLUSTER_SETUP_REQUEST"], data)
    except OSError as exc:
        raise ServiceError(f"Cannot start the setup ({exc}); is crassostrea-cluster-setup.path installed?",
                           status=503) from exc


def _single_gateway():
    if enabled():
        raise ServiceError("This gateway already is a cluster member", status=409)


def request_create(address, vip=""):
    """Turn this single gateway into the first node of a cluster."""
    _single_gateway()
    address = _valid_address(address)
    vip = (vip or "").strip()
    if vip:
        match = re.fullmatch(r"([0-9.]+)/(\d{1,2})", vip)
        if not match or int(match.group(2)) > 32:
            raise ServiceError("The floating address needs a prefix length, e.g. 192.0.2.10/24", "vip")
        _valid_address(match.group(1), "vip")
    if address not in local_addresses():
        raise ServiceError(f"{address} is not an address of this server", "address")
    _setup_request({"action": "create", "address": address, "vip": vip})
    return {"address": address, "vip": vip}


def request_join(information, address):
    """Join a cluster with a join information from one of its members."""
    _single_gateway()
    info = decode_join_information(information)
    address = _valid_address(address)
    if address not in local_addresses():
        raise ServiceError(f"{address} is not an address of this server", "address")
    if info["host"] == current_app.config["HOSTNAME"]:
        raise ServiceError("This gateway has the member's name: it cannot join itself", "information")
    _setup_request({"action": "join", "address": address, "member_address": info["address"],
                    **{key: info[key] for key in ("host", "port", "fingerprint", "token")}})
    return {"host": info["host"], "address": address}
