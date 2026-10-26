"""State of the gateway's systemd units and of its cluster, shown on the dashboard.

``systemctl show`` only reads unit properties, which every user may do.
"""
import subprocess

import redis
from flask import current_app

from ..extensions import db
from . import store

PROPERTIES = ("Id", "Description", "LoadState", "ActiveState", "SubState", "ActiveEnterTimestamp")


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
