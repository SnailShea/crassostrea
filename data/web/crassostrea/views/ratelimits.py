"""Rate limits page: inbound limits per sending host (Postfix), per sending IP
and recipient (rspamd, Valkey) and the exempt networks (services/ratelimits.py)."""
import redis
from flask import flash, redirect, request, url_for

from ..extensions import db
from ..forms import RateLimitsForm
from ..services import filters, outbound, ratelimits
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint, render_live

bp = protected_blueprint("ratelimits", __name__, url_prefix="/rate-limits")


def _render(form=None, code=200):
    values = filters.get_settings()
    form = form or RateLimitsForm(formdata=None, data={key: values[key] for key in filters.RATE_LIMIT_SETTINGS})
    try:
        hits, valkey_error = ratelimits.hits(), None
    except redis.RedisError as exc:
        hits, valkey_error = [], str(outbound.valkey_error(exc))
    return render_live("ratelimits.html", "_ratelimits_live.html", form=form, hits=hits, valkey_error=valkey_error,
                       kinds=ratelimits.KINDS, period_name=ratelimits.period_name), code


@bp.get("/")
def index():
    return _render()


@bp.post("/")
def save():
    form = RateLimitsForm()
    if not form.validate_on_submit():
        return _render(form, 400)
    try:
        filters.update_settings(**{key: getattr(form, key).data if getattr(form, key).data is not None else ""
                                   for key in filters.RATE_LIMIT_SETTINGS})
    except ServiceError as exc:
        db.session.rollback()
        field = getattr(form, exc.field or "", None)
        if field is not None:
            field.errors = [*field.errors, str(exc)]
        else:
            flash(str(exc), "danger")
        return _render(form, 400)
    db.session.commit()
    if not sync_all():
        flash("Saved, but the filter maps could not be written. See the web UI log (journalctl -u crassostrea-web).",
              "warning")
    flash("Rate limits saved. Rspamd applies them within a minute, Postfix within seconds.", "success")
    return redirect(url_for("ratelimits.index"))


@bp.post("/reset")
def reset():
    kind, key = request.form.get("kind", ""), request.form.get("key", "")
    try:
        ratelimits.reset(kind, key)
    except redis.RedisError as exc:
        flash(f"Cannot reset: {outbound.valkey_error(exc)}", "danger")
    else:
        flash(f"{key} may send again." if kind == "ip" else f"Mail to {key} is accepted again.", "success")
    return redirect(url_for("ratelimits.index"))
