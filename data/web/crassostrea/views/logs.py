import ipaddress

import redis
from flask import flash, redirect, request, url_for

from ..services import logs, store
from . import protected_blueprint, render_live

bp = protected_blueprint("logs", __name__)


@bp.get("/logs")
def index():
    """Logs (Monitoring): the Postfix log of all nodes, or the journal of a
    service of this node (?service=, services/logs.py)."""
    available = logs.sources()
    source = request.args.get("service", "postfix")
    source = source if source in {key for key, _, _ in available} else "postfix"
    needle = request.args.get("q", "").strip().lower()
    priority = request.args.get("priority", "")
    priority = priority if priority in {key for key, _ in logs.PRIORITIES} else ""
    entries, error = [], None
    if source == "postfix":
        try:
            entries = store.postfix_log(limit=2000)
        except redis.RedisError as exc:
            error = f"Cannot read logs from redis: {exc}"
        if needle:
            entries = [e for e in entries if needle in str(e.get("message", "")).lower()]
    else:
        try:
            entries = logs.journal(source, lines=2000 if needle else 500, priority=priority)
        except logs.LogReaderError as exc:
            error = str(exc)
        if needle:
            entries = [e for e in entries if needle in e["message"].lower() or needle in e["unit"].lower()]
    return render_live("logs.html", "_logs_live.html", entries=entries[:500], error=error, sources=available,
                       source=source, label=next(label for key, label, _ in available if key == source),
                       description=next(text for key, _, text in available if key == source), q=needle,
                       priority=priority, priorities=logs.PRIORITIES, priority_names=logs.PRIORITY_NAMES)


@bp.get("/bans")
def bans():
    error, banned = None, []
    try:
        banned = store.banned_networks()
    except redis.RedisError as exc:
        error = f"Cannot read bans from redis: {exc}"
    return render_live("bans.html", "_bans_live.html", bans=banned, error=error)


@bp.post("/bans/unban")
def unban():
    network = request.form.get("network", "")
    try:
        ipaddress.ip_network(network, strict=False)
    except ValueError:
        flash("Invalid network.", "danger")
        return redirect(url_for("logs.bans"))
    try:
        store.queue_unban(network)
        flash(f"{network} will be unbanned within a few seconds.", "success")
    except redis.RedisError as exc:
        flash(f"Cannot queue unban: {exc}", "danger")
    return redirect(url_for("logs.bans"))
