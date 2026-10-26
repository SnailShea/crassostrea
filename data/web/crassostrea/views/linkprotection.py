import redis
from flask import flash, redirect, request, url_for

from ..extensions import db
from ..forms import LinkCheckForm, LinkProtectionForm
from ..models import Domain
from ..services import filters, links
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint, render_live

bp = protected_blueprint("linkprotection", __name__, url_prefix="/link-protection")


def _render(form=None, check_form=None, result=None, code=200):
    if form is None:
        values = filters.get_settings()
        form = LinkProtectionForm(formdata=None, data={key: values[key] for key in filters.LINK_SETTINGS})
    blocked_only = request.args.get("blocked") == "1"
    try:
        clicks, error = links.clicks(blocked_only=blocked_only), None
    except redis.RedisError as exc:
        clicks, error = [], f"Valkey cannot be reached ({exc})"
    return render_live("linkprotection.html", "_linkprotection_live.html", form=form,
                       check_form=check_form or LinkCheckForm(formdata=None, prefix="check"), result=result,
                       domains=Domain.query.order_by(Domain.name).all(), clicks=clicks, clicks_error=error,
                       blocked_only=blocked_only), code


@bp.get("/")
def index():
    return _render()


@bp.post("/")
def save():
    form = LinkProtectionForm()
    if not form.validate_on_submit():
        return _render(form, code=400)
    try:
        filters.update_settings(
            link_protection_exempt_hosts=form.link_protection_exempt_hosts.data or "",
            link_protection_block_domains=form.link_protection_block_domains.data or "",
            link_protection_allow_continue=form.link_protection_allow_continue.data,
            link_protection_days=form.link_protection_days.data)
    except ServiceError as exc:
        db.session.rollback()
        field = getattr(form, exc.field or "", None)
        if field is not None:
            field.errors = [*field.errors, str(exc)]
        else:
            flash(str(exc), "danger")
        return _render(form, code=400)
    db.session.commit()
    if not sync_all():
        flash("Saved, but the filter maps could not be written. See the web UI log (journalctl -u crassostrea-web).",
              "warning")
    flash("Link protection saved.", "success")
    return redirect(url_for("linkprotection.index"))


@bp.post("/check")
def check():
    form = LinkCheckForm(prefix="check")
    if not form.validate_on_submit():
        return _render(check_form=form, code=400)
    url = form.url.data.strip()
    if "://" not in url:
        url = "http://" + url
    try:
        result = links.check(url)
    except redis.RedisError as exc:
        flash(f"Valkey cannot be reached ({exc})", "danger")
        return _render(check_form=form, code=503)
    return _render(check_form=form, result=result)
