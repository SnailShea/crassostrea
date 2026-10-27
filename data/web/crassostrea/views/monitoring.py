import redis
from flask import flash, redirect, render_template, session, url_for

from ..extensions import db
from ..forms import AlertForm, SiemForm, UpdateChannelForm, WatchdogForm
from ..services import filters, mailer, monitoring, serverconf, siem, store, system
from ..services.errors import ServiceError
from . import protected_blueprint, render_live

bp = protected_blueprint("monitoring", __name__, url_prefix="/monitoring")

SIEM_FIELDS = ("siem_host", "siem_port", "siem_protocol", "siem_format", "siem_verify_tls", "siem_mail_log",
               "siem_audit")
ALERT_FIELDS = ("alert_recipients", "alert_deferred_count", "alert_deferred_hours", "alert_cert_days",
                "alert_backup_hours")


def _render(update_form=None, code=200):
    """The Monitoring page: the version, the checks and the services (live)."""
    try:
        state = monitoring.alert_state()
    except redis.RedisError:
        state = {}
    checks = monitoring.check()
    monitoring.record_problems(checks)
    services, services_error = [], None
    try:
        services = system.units()
    except system.SystemStatusError as exc:
        services_error = str(exc)
    deployed = monitoring.deployed()
    update_form = update_form or UpdateChannelForm(formdata=None, prefix="update", data={
        "update_channel": deployed["channel"], "update_branch": deployed["branch"]})
    response = render_live("monitoring.html", "_monitoring_live.html", services=services,
                           services_error=services_error, checks=checks,
                           labels={name: monitoring.label(name) for name in checks}, failing_since=state,
                           deployed=deployed, update_form=update_form)
    response.status_code = code
    return response


def _render_settings(siem_form=None, alert_form=None, watchdog_form=None, code=200):
    """Settings → Alerts & export: Prometheus, SIEM, alert mail, the watchdog's notices."""
    values = filters.get_settings()
    siem_form = siem_form or SiemForm(formdata=None, prefix="siem", data={k: values[k] for k in SIEM_FIELDS})
    alert_form = alert_form or AlertForm(formdata=None, prefix="alert", data={k: values[k] for k in ALERT_FIELDS})
    watchdog_form = watchdog_form or WatchdogForm(formdata=None, prefix="watchdog",
                                                  data={k: values[k] for k in filters.WATCHDOG_SETTINGS})
    try:
        queued = store.get_redis().llen(siem.QUEUE)
    except redis.RedisError:
        queued = None
    return render_template("monitoring_settings.html", siem_form=siem_form, alert_form=alert_form,
                           watchdog_form=watchdog_form,
                           has_token=monitoring.has_token(), new_token=session.pop("new_metrics_token", None),
                           queued=queued), code


def _save(form, fields, message, anchor, endpoint="monitoring.settings_page", sync=False):
    try:
        filters.update_settings(**{key: getattr(form, key).data if getattr(form, key).data is not None else ""
                                   for key in fields})
    except ServiceError as exc:
        db.session.rollback()
        field = getattr(form, exc.field or "", None)
        if field is not None:
            field.errors = [*field.errors, str(exc)]
        else:
            flash(str(exc), "danger")
        return None
    db.session.commit()
    if sync:
        serverconf.sync()
    flash(message, "success")
    return redirect(url_for(endpoint) + anchor)


@bp.get("/")
def index():
    return _render()


@bp.get("/settings")
def settings_page():
    return _render_settings()


@bp.post("/token")
def create_token():
    session["new_metrics_token"] = monitoring.create_token()
    db.session.commit()
    flash("New metrics token created: copy it now, it is not shown again. The previous token no longer works.",
          "success")
    return redirect(url_for("monitoring.settings_page") + "#metrics")


@bp.post("/token/revoke")
def revoke_token():
    monitoring.revoke_token()
    db.session.commit()
    flash("The metrics token was revoked: /metrics answers no one.", "success")
    return redirect(url_for("monitoring.settings_page") + "#metrics")


@bp.post("/siem")
def save_siem():
    form = SiemForm(prefix="siem")
    if form.validate_on_submit():
        response = _save(form, SIEM_FIELDS, "SIEM settings saved.", "#siem")
        if response:
            return response
    return _render_settings(siem_form=form, code=400)


@bp.post("/siem/test")
def test_siem():
    if not filters.get_settings()["siem_host"]:
        flash("Enter the SIEM's host first.", "warning")
    else:
        try:
            siem.send_test()
        except OSError as exc:
            flash(f"The test event could not be sent: {exc}", "danger")
        else:
            flash("A test event was sent.", "success")
    return redirect(url_for("monitoring.settings_page") + "#siem")


@bp.post("/alerts")
def save_alerts():
    form = AlertForm(prefix="alert")
    if form.validate_on_submit():
        response = _save(form, ALERT_FIELDS, "Alert settings saved.", "#alerts")
        if response:
            return response
    return _render_settings(alert_form=form, code=400)


@bp.post("/alerts/test")
def test_alerts():
    try:
        recipients = monitoring.send_test()
    except mailer.ReleaseError as exc:
        flash(f"The test mail could not be sent: {exc}", "danger")
    else:
        if recipients:
            flash(f"A test alert was sent to {', '.join(recipients)}.", "success")
        else:
            flash("Enter the recipients first.", "warning")
    return redirect(url_for("monitoring.settings_page") + "#alerts")


@bp.post("/watchdog")
def save_watchdog():
    form = WatchdogForm(prefix="watchdog")
    if form.validate_on_submit():
        response = _save(form, filters.WATCHDOG_SETTINGS, "Watchdog notices saved; the watchdog uses them from its "
                         "next notice.", "#watchdog", sync=True)
        if response:
            return response
    return _render_settings(watchdog_form=form, code=400)


@bp.post("/update-channel")
def save_update_channel():
    form = UpdateChannelForm(prefix="update")
    if form.validate_on_submit():
        response = _save(form, filters.UPDATE_SETTINGS, "Saved: update.sh follows this from its next run.",
                         "#version", endpoint="monitoring.index")
        if response:
            return response
    return _render(update_form=form, code=400)
