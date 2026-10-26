import redis
from flask import flash, redirect, render_template, session, url_for

from ..extensions import db
from ..forms import AlertForm, SiemForm
from ..services import filters, mailer, monitoring, siem, store, system
from ..services.errors import ServiceError
from . import protected_blueprint, render_live

bp = protected_blueprint("monitoring", __name__, url_prefix="/monitoring")

SIEM_FIELDS = ("siem_host", "siem_port", "siem_protocol", "siem_format", "siem_verify_tls", "siem_mail_log",
               "siem_audit")
ALERT_FIELDS = ("alert_recipients", "alert_deferred_count", "alert_deferred_hours", "alert_cert_days",
                "alert_backup_hours")


def _render():
    """The Monitoring page: the checks and the services (live)."""
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
    return render_live("monitoring.html", "_monitoring_live.html", services=services, services_error=services_error,
                       checks=checks, labels={name: monitoring.label(name) for name in checks},
                       failing_since=state, deployed=monitoring.deployed())


def _render_settings(siem_form=None, alert_form=None, code=200):
    """Settings → Alerts & export: Prometheus, SIEM, alert mail."""
    values = filters.get_settings()
    siem_form = siem_form or SiemForm(formdata=None, prefix="siem", data={k: values[k] for k in SIEM_FIELDS})
    alert_form = alert_form or AlertForm(formdata=None, prefix="alert", data={k: values[k] for k in ALERT_FIELDS})
    try:
        queued = store.get_redis().llen(siem.QUEUE)
    except redis.RedisError:
        queued = None
    return render_template("monitoring_settings.html", siem_form=siem_form, alert_form=alert_form,
                           has_token=monitoring.has_token(), new_token=session.pop("new_metrics_token", None),
                           queued=queued), code


def _save(form, fields, message, anchor):
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
    flash(message, "success")
    return redirect(url_for("monitoring.settings_page") + anchor)


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
