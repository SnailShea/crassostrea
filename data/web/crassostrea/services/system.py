"""State of the gateway's systemd units, its use of the host (CPU, memory,
storage) and its cluster, shown on the dashboard.

``systemctl show`` only reads unit properties, which every user may do; the
host's use comes from /proc and statvfs.
"""
import os
import subprocess
import time

import redis
from flask import current_app

from ..extensions import db
from . import store

PROPERTIES = ("Id", "Description", "LoadState", "ActiveState", "SubState", "ActiveEnterTimestamp")
# Filesystems whose use is reported (each one once)
DISK_PATHS = ("/", "/var", "/var/lib/mysql", "/var/spool/postfix")
# The CPU counters this process read last: (monotonic time, busy, total)
_cpu_last = []


class SystemStatusError(Exception):
    pass


def parse_show(text):
    """``systemctl show`` output for several units: blocks separated by blank lines."""
    units, current = [], {}
    for line in text.splitlines() + [""]:
        if not line.strip():
            if current:
                units.append(current)
                current = {}
            continue
        key, _, value = line.partition("=")
        current[key] = value
    return units


def units():
    names = current_app.config["SERVICE_UNITS"]
    if not names:
        return []
    try:
        result = subprocess.run(["systemctl", "show", "--no-pager", "--property=" + ",".join(PROPERTIES),
                                 "--", *names], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise SystemStatusError(f"Cannot read the service status: {exc}") from exc
    if result.returncode != 0:
        raise SystemStatusError(f"Cannot read the service status: {result.stderr.strip() or result.returncode}")
    return [{
        "unit": u.get("Id", ""),
        "description": u.get("Description", ""),
        "state": u.get("ActiveState", "unknown") if u.get("LoadState") == "loaded" else u.get("LoadState", "unknown"),
        "sub_state": u.get("SubState", ""),
        "since": u.get("ActiveEnterTimestamp", ""),
    } for u in parse_show(result.stdout)]


def _cpu_counters():
    """(busy, total) jiffies of all CPUs since boot; guest time is already in user."""
    with open("/proc/stat", encoding="ascii") as fh:
        values = [int(v) for v in fh.readline().split()[1:9]]
    idle = values[3] + (values[4] if len(values) > 4 else 0)  # idle, iowait
    return sum(values) - idle, sum(values)


def cpu_percent(sample=0.25):
    """The CPU use since this process last read it (the dashboard refreshes
    every 30 s), or over ``sample`` seconds when that was long ago."""
    now = time.monotonic()
    if not _cpu_last or not 1 <= now - _cpu_last[0] <= 600:
        _cpu_last[:] = [now, *_cpu_counters()]
        time.sleep(sample)
        now = time.monotonic()
    busy, total = _cpu_counters()
    previous_busy, previous_total = _cpu_last[1:]
    _cpu_last[:] = [now, busy, total]
    return round(100.0 * (busy - previous_busy) / (total - previous_total), 1) if total > previous_total else 0.0


def memory():
    """{total_bytes, used_bytes, percent}: used is what is not available."""
    info = {}
    with open("/proc/meminfo", encoding="ascii") as fh:
        for line in fh:
            key, _, value = line.partition(":")
            info[key] = int(value.split()[0]) * 1024
    total = info.get("MemTotal") or 0
    used = total - info.get("MemAvailable", 0)
    return {"total_bytes": total, "used_bytes": used, "percent": round(100.0 * used / total, 1) if total else None}


def disks():
    """[{path, used_percent, free_bytes, total_bytes}] of DISK_PATHS, each filesystem once."""
    seen, result = set(), []
    for path in DISK_PATHS:
        try:
            st = os.statvfs(path)
        except OSError:
            continue
        if st.f_fsid in seen or not st.f_blocks:
            continue
        seen.add(st.f_fsid)
        # what root reserves counts as neither used nor available, as in df
        usable = st.f_blocks - st.f_bfree + st.f_bavail
        result.append({"path": path, "used_percent": round(100.0 * (st.f_blocks - st.f_bfree) / usable, 1),
                       "free_bytes": st.f_bavail * st.f_frsize, "total_bytes": usable * st.f_frsize})
    return result


def resources():
    """This node's use of the host: {cpu_percent, load, cpus, memory, disks};
    a part that cannot be read is None (disks: [])."""
    def read(func, default=None):
        try:
            return func()
        except (OSError, ValueError, IndexError, ZeroDivisionError) as exc:
            current_app.logger.info("system: %s failed: %s", func.__name__, exc)
            return default
    return {"cpu_percent": read(cpu_percent), "load": read(lambda: [round(x, 2) for x in os.getloadavg()]),
            "cpus": os.cpu_count(), "memory": read(memory), "disks": read(disks, [])}


def cluster_status():
    """The cluster as seen from this node (None for a single gateway).

    Galera's view of the database cluster, and valkey's replication as
    reported by the master (redis is reached through haproxy, which always
    forwards to the master). Errors are returned in ``errors``.
    """
    if not current_app.config["CLUSTER_NODES"]:
        return None
    from . import cluster
    # the cluster's membership: it can change while this process runs
    nodes, witness = cluster.nodes(), cluster.witness()
    status = {
        "node": current_app.config["HOSTNAME"],
        "members": len(nodes) + (1 if witness else 0),
        "database": None,
        "valkey": None,
        "errors": [],
    }
    try:
        rows = db.session.execute(db.text(
            "SHOW GLOBAL STATUS WHERE Variable_name IN "
            "('wsrep_cluster_size', 'wsrep_cluster_status', 'wsrep_local_state_comment')")).all()
        values = {name: value for name, value in rows}
        status["database"] = {
            "size": int(values.get("wsrep_cluster_size") or 0),
            "status": values.get("wsrep_cluster_status", "unknown"),
            "state": values.get("wsrep_local_state_comment", "unknown"),
        }
    except Exception as exc:  # shown on the dashboard
        status["errors"].append(f"Cannot read the database cluster state: {exc}")
    try:
        info = store.get_redis().info("replication")
        replicas = [v for k, v in info.items() if k.startswith("slave") and isinstance(v, dict)]
        replica_ips = {r.get("ip") for r in replicas}
        # the master is the node that is not a replica
        others = [name for name, address in nodes if address not in replica_ips]
        status["valkey"] = {
            "master": others[0] if len(others) == 1 else None,
            "in_sync": sum(1 for r in replicas if r.get("state") == "online"),
            "expected": len(nodes) - 1,
        }
    except redis.RedisError as exc:
        status["errors"].append(f"Cannot read the valkey replication state: {exc}")
    return status
