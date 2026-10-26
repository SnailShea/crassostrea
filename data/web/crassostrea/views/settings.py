import os

from flask import current_app, flash, redirect, render_template, request, url_for

from ..extensions import db
from ..forms import BrandingForm, GlobalSettingsForm, HostnameForm, RelayNetworkForm
from ..models import Domain, RelayNetwork, set_setting
from ..services import adminaccess, branding, digest, filters, hostname, timezone
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint

bp = protected_blueprint("settings", __name__, url_prefix="/settings")


def _branding_form():
    brand = branding.get_branding()
    return BrandingForm(formdata=None, prefix="brand", data={
        "brand_name": brand["name"], "brand_accent": brand["accent"] or "#2557d6",
        "default_accent": not brand["accent"], "brand_footer": brand["footer"], "brand_theme": brand["theme"]})


def _render(form):
    overrides = Domain.query.filter(db.or_(Domain.reject_score.isnot(None), Domain.add_header_score.isnot(None),
                                           Domain.greylist_score.isnot(None))).count()
    return render_template("settings.html", form=form, overrides=overrides, digest_sender=digest.sender_address(),
                           clamav_installed=_clamav_installed(), client_ip=request.remote_addr,
                           system_zone=timezone.system_zone(), zone_status=timezone.status())


def _clamav_installed():
    """configure.sh turns the antivirus module off with SKIP_CLAMD."""
    path = os.path.join(os.path.dirname(current_app.config["RSPAMD_MAP_DIR"].rstrip("/")), "override.d",
                        "antivirus.conf")
    try:
        with open(path, encoding="utf-8") as handle:
            return "enabled = false" not in handle.read()
    except OSError:
        return True


def hostname_context(form=None):
    """The hostname card, shown on the IP addressing page (views/ipconfig.py)."""
    return {"hostname_form": form or HostnameForm(prefix="host", formdata=None), "hostname": hostname.current(),
            "hostname_pending": hostname.pending(), "in_cluster": hostname.in_cluster()}


@bp.get("/")
def index():
    return _render(GlobalSettingsForm(data=filters.get_settings()))


@bp.post("/")
def save():
    form = GlobalSettingsForm()
    if not form.validate_on_submit():
        return _render(form), 400
    try:
        values = {key: getattr(form, key).data for key in filters.SETTINGS}
        stored = filters.update_settings(**values)
        adminaccess.check_own_address(stored["admin_allowed_networks"], request.remote_addr)
    except ServiceError as exc:
        db.session.rollback()
        field = getattr(form, exc.field, None)
        if field is not None:
            field.errors = [*field.errors, str(exc)]
        else:
            flash(str(exc), "danger")
        return _render(form), 400
    db.session.commit()
    # size limits are files for Postfix and Rspamd
    sync_all()
    flash("Settings saved. Rspamd applies new thresholds and limits within a minute.", "success")
    if values["timezone"] and values["timezone"] != timezone.system_zone():
        flash(f"The servers switch to the time zone {values['timezone']} and restart their services: this node "
              "now, the other nodes of a cluster at their next sync.", "info")
    return redirect(url_for("settings.index"))


@bp.post("/hostname")
def change_hostname():
    form = HostnameForm(prefix="host")
    if form.validate_on_submit():
        try:
            warnings = hostname.request_change(form.hostname.data)
        except ServiceError as exc:
            form.hostname.errors = [*form.hostname.errors, str(exc)]
        else:
            new = hostname.normalize(form.hostname.data)
            flash(f"The gateway is switching to {new}: Postfix uses the new name within seconds, the web UI "
                  "restarts (reload the page if it does not answer for a moment), and a certificate for the new "
                  "name is requested.", "success")
            for warning in warnings:
                flash(warning, "warning")
            return redirect(url_for("ipconfig.index") + "#hostname")
    from .ipconfig import render_page
    return render_page(hostname_form=form, code=400)


@bp.get("/networks")
def networks():
    return render_template("relay_networks.html", network_form=RelayNetworkForm(prefix="net"),
                           networks=RelayNetwork.query.order_by(RelayNetwork.cidr).all())


@bp.post("/networks")
def add_network():
    form = RelayNetworkForm(prefix="net")
    if form.validate_on_submit():
        try:
            filters.add_relay_network(form.cidr.data, form.comment.data)
        except ServiceError as exc:
            db.session.rollback()
            if exc.status == 409:
                flash(f"{exc}.", "info")
            else:
                flash(str(exc), "danger")
        else:
            db.session.commit()
            if sync_all():
                flash(f"{form.cidr.data} may now relay mail through the gateway.", "success")
            else:
                flash("Saved, but Postfix/Rspamd could not be updated. See the web UI log (journalctl -u crassostrea-web).", "warning")
    else:
        for errors in form.errors.values():
            for error in errors:
                flash(error, "danger")
    return redirect(url_for("settings.networks"))


@bp.post("/networks/<int:network_id>/delete")
def delete_network(network_id):
    network = db.get_or_404(RelayNetwork, network_id)
    filters.delete_relay_network(network)
    db.session.commit()
    sync_all()
    flash(f"{network.cidr} removed.", "success")
    return redirect(url_for("settings.networks"))


@bp.post("/digests/send")
def send_digests():
    sent, failed = digest.send_due_digests()
    if sent:
        flash(f"{len(sent)} digest(s) sent.", "success")
    elif not failed:
        flash("No digests are due right now.", "info")
    for address, error in list(failed.items())[:10]:
        flash(f"Digest for {address} failed: {error}", "danger")
    return redirect(url_for("settings.index", _anchor="quarantine"))


@bp.get("/branding")
def branding_page(form=None, code=200):
    return render_template("branding.html", branding_form=form or _branding_form()), code


@bp.post("/branding")
def save_branding():
    form = BrandingForm(prefix="brand")
    if not form.validate_on_submit():
        return branding_page(form, 400)
    try:
        for kind in ("logo", "favicon"):
            upload = getattr(form, kind).data
            if getattr(form, f"remove_{kind}").data:
                branding.delete_asset(kind)
            elif upload and getattr(upload, "filename", ""):
                branding.save_asset(kind, upload.read())
    except branding.BrandingError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(url_for("settings.branding_page"))
    set_setting("brand_name", form.brand_name.data.strip())
    set_setting("brand_accent", "" if form.default_accent.data else form.brand_accent.data.lower())
    set_setting("brand_footer", (form.brand_footer.data or "").strip())
    set_setting("brand_theme", form.brand_theme.data)
    branding.bump_version()
    db.session.commit()
    flash("Branding saved.", "success")
    return redirect(url_for("settings.branding_page"))
