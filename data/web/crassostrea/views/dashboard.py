"""Dashboard: the statistics of the scanned mail and how long scanning and
delivery took (services/stats.py), hourly for the last 24 hours or daily for
the last 30 days, the quarantine, and for full administrators the health of
the gateway, its mail queue by direction, its use of CPU, memory and storage
and its cluster. Domain administrators see their domains only."""
from datetime import timedelta

from flask import render_template, request
from flask_login import current_user

from ..extensions import db
from ..models import Domain, QuarantineItem, utcnow
from ..services import cluster as cluster_service, monitoring, postfix_control, stats, store, system
from ..services.rspamd import RspamdError, client
from . import in_scope, protected_blueprint, scope

bp = protected_blueprint("dashboard", __name__, domain_admins=True)
# The rows of the mail queue card: Postfix's queues (mail passes incoming and
# maildrop in moments)
QUEUE_ROWS = {"Being delivered": ("maildrop", "incoming", "active"), "Deferred": ("deferred",),
              "On hold": ("hold",)}
# The graph's views: (range of services/stats.py, label)
VIEWS = {"hourly": ("24h", "Hourly, last 24 hours"), "daily": ("30d", "Daily, last 30 days")}


@bp.get("/")
def index():
    view = request.args.get("view", "hourly")
    view = view if view in VIEWS else "hourly"
    allowed = scope()
    data = stats.series(VIEWS[view][0], domains=allowed)

    since = utcnow() - timedelta(hours=24)
    quarantined = QuarantineItem.query
    if allowed is not None:
        quarantined = quarantined.filter(QuarantineItem.domain.in_(sorted(allowed) or [""]))
    quarantine = {"total": quarantined.count(),
                  "last_24h": quarantined.filter(QuarantineItem.created_at >= since).count()}
    scoped = [d for d in Domain.query.order_by(Domain.name) if in_scope(d.name)]

    errors, health, cluster, learned, queue, queue_error, resources = [], None, None, None, None, None, None
    if current_user.is_full_admin:
        stat = None
        try:
            stat = client().stat()
            learned = stat.get("learned", 0)
        except RspamdError as exc:
            errors.append(str(exc))
        health = {"Database": _db_ok(), "Valkey": store.ping(), "Rspamd": stat is not None}
        try:
            queue = monitoring.queue_directions()
            queue["rows"] = [(label, *(sum(queue[d].get(n, 0) for n in names) for d in ("inbound", "outbound")))
                             for label, names in QUEUE_ROWS.items()]
        except postfix_control.PostfixControlError as exc:
            queue_error = str(exc)
        resources = system.resources()
        cluster = system.cluster_status()
        if cluster:
            errors.extend(cluster["errors"])
            try:
                cluster["problems"] = len(cluster_service.state()["problems"])
            except Exception:  # shown on the Cluster page
                db.session.rollback()
                cluster["problems"] = None

    return render_template("dashboard.html", data=data, chart=stats.chart(data),
                           scan_chart=stats.latency_chart(data, "scan_ms"),
                           delivery_chart=stats.latency_chart(data, "delivery_s"),
                           categories=stats.CATEGORIES, views=VIEWS, view=view, quarantine=quarantine,
                           health=health, cluster=cluster, learned=learned, queue=queue, queue_error=queue_error,
                           resources=resources,
                           domain_counts={"active": sum(1 for d in scoped if d.active), "total": len(scoped)},
                           errors=errors)


def _db_ok():
    try:
        db.session.execute(db.text("SELECT 1"))
        return True
    except Exception:
        return False
