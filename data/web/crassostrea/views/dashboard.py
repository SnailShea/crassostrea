"""Dashboard: the statistics of the scanned mail (services/stats.py), the
quarantine and recent mail, and for full administrators the health of the
gateway and its cluster. Domain administrators see their domains only."""
from datetime import timedelta

from flask import request
from flask_login import current_user

from ..extensions import db
from ..models import Domain, MailLogEntry, QuarantineItem, utcnow
from ..services import cluster as cluster_service, maillog, stats, store, system
from ..services.rspamd import RspamdError, client
from . import in_scope, protected_blueprint, render_live, scope

bp = protected_blueprint("dashboard", __name__, domain_admins=True)


def filters():
    """Period, direction and domain of the statistics (query string)."""
    range_key = request.args.get("range", "7d")
    direction = request.args.get("direction", "")
    domain = request.args.get("domain", "").strip().lower()
    return (range_key if range_key in stats.RANGES else "7d",
            direction if direction in ("inbound", "outbound") else "",
            domain if domain and in_scope(domain) else "")


@bp.get("/")
def index():
    range_key, direction, domain = filters()
    allowed = scope()
    data = stats.series(range_key, domain, direction, domains=allowed)

    since = utcnow() - timedelta(hours=24)
    quarantined = QuarantineItem.query
    if allowed is not None:
        quarantined = quarantined.filter(QuarantineItem.domain.in_(sorted(allowed) or [""]))
    if domain:
        quarantined = quarantined.filter(QuarantineItem.domain == domain)
    quarantine = {"total": quarantined.count(),
                  "last_24h": quarantined.filter(QuarantineItem.created_at >= since).count()}
    # mail that arrived: refused recipients (no message) only crowd it out
    recent = (maillog.filtered(direction=direction, domain=domain, domains=allowed)
              .filter(MailLogEntry.reject_reason == "").limit(10).all())
    scoped = [d for d in Domain.query.order_by(Domain.name) if in_scope(d.name)]
    domains = [d.name for d in scoped]

    errors, health, cluster, learned = [], None, None, None
    if current_user.is_full_admin:
        stat = None
        try:
            stat = client().stat()
            learned = stat.get("learned", 0)
        except RspamdError as exc:
            errors.append(str(exc))
        health = {"Database": _db_ok(), "Valkey": store.ping(), "Rspamd": stat is not None}
        cluster = system.cluster_status()
        if cluster:
            errors.extend(cluster["errors"])
            try:
                cluster["problems"] = len(cluster_service.state()["problems"])
            except Exception:  # shown on the Cluster page
                db.session.rollback()
                cluster["problems"] = None

    return render_live("dashboard.html", "_dashboard_live.html", data=data, chart=stats.chart(data),
                       categories=stats.CATEGORIES, ranges=stats.RANGES, range_key=range_key, direction=direction,
                       domain=domain, domains=domains, quarantine=quarantine, recent=recent, health=health,
                       cluster=cluster, learned=learned,
                       domain_counts={"active": sum(1 for d in scoped if d.active), "total": len(scoped)},
                       errors=errors)


def _db_ok():
    try:
        db.session.execute(db.text("SELECT 1"))
        return True
    except Exception:
        return False
