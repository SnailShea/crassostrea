import redis
from flask import flash, redirect, request, url_for

from ..extensions import db
from ..forms import OutboundDefaultForm, OutboundLimitForm
from ..models import OutboundLimit
from ..services import filters, outbound
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint, render_live

bp = protected_blueprint("outbound", __name__, url_prefix="/outbound")

MAPS_FAILED = "Saved, but the filter maps could not be written. See the web UI log (journalctl -u crassostrea-web)."


def _render(default_form=None, limit_form=None, code=200):
    count, period = outbound.default()
    try:
        usage, hits, valkey_error = outbound.usage(), outbound.hits(), None
    except redis.RedisError as exc:
        usage, hits, valkey_error = [], [], str(outbound.valkey_error(exc))
    return render_live("outbound.html", "_outbound_live.html",
                       default_form=default_form or OutboundDefaultForm(
                           formdata=None, data={"outbound_limit": count, "outbound_limit_period": period}),
                       limit_form=limit_form or OutboundLimitForm(formdata=None), limits=outbound.limits(),
                       usage=usage, hits=hits, valkey_error=valkey_error), code


def _saved(message):
    db.session.commit()
    if not sync_all():
        flash(MAPS_FAILED, "warning")
    flash(message, "success")


@bp.get("/")
def index():
    return _render()


@bp.post("/default")
def save_default():
    form = OutboundDefaultForm()
    if not form.validate_on_submit():
        return _render(default_form=form, code=400)
    filters.update_settings(outbound_limit=form.outbound_limit.data,
                            outbound_limit_period=form.outbound_limit_period.data)
    _saved(f"Every sender may now send to {form.outbound_limit.data} recipients per "
           f"{form.outbound_limit_period.data}." if form.outbound_limit.data else
           "Senders without their own limit are no longer limited.")
    return redirect(url_for("outbound.index"))


@bp.post("/limits")
def set_limit():
    """Adds a limit, or changes the one of the same sender."""
    form = OutboundLimitForm()
    if not form.validate_on_submit():
        return _render(limit_form=form, code=400)
    try:
        sender = outbound.normalize_sender(form.sender.data)
        existing = OutboundLimit.query.filter_by(sender=sender).first()
        if existing:
            outbound.update_limit(existing, max_recipients=form.max_recipients.data, period=form.period.data,
                                  comment=form.comment.data or "")
        else:
            outbound.add_limit(sender, form.max_recipients.data, form.period.data, form.comment.data or "")
    except ServiceError as exc:
        db.session.rollback()
        form.sender.errors = [*form.sender.errors, str(exc)]
        return _render(limit_form=form, code=400)
    _saved(f"Limit for {sender} {'changed' if existing else 'added'}.")
    return redirect(url_for("outbound.index"))


@bp.post("/limits/<int:limit_id>/delete")
def delete_limit(limit_id):
    limit = db.get_or_404(OutboundLimit, limit_id)
    outbound.delete_limit(limit)
    _saved(f"Limit for {limit.sender} removed.")
    return redirect(url_for("outbound.index"))


@bp.post("/reset")
def reset():
    sender = request.form.get("sender", "")
    try:
        found = outbound.reset(sender)
    except ServiceError as exc:
        flash(str(exc), "danger")
    except redis.RedisError as exc:
        flash(str(outbound.valkey_error(exc)), "danger")
    else:
        flash(f"{sender} can send again." if found else f"{sender} had no count.", "success" if found else "info")
    return redirect(url_for("outbound.index"))
