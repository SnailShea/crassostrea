from flask import flash, redirect, render_template, request, url_for

from ..extensions import db
from ..forms import ReportSettingsForm
from ..models import Domain
from ..services import filters, reports
from ..services.errors import ServiceError
from . import in_scope, protected_blueprint, require_full_admin

bp = protected_blueprint("reports", __name__, url_prefix="/reports", domain_admins=True)

PERIODS = (7, 30, 90)


def _render(form=None, code=200):
    days = request.args.get("days", 30, type=int)
    days = days if days in PERIODS else 30
    names = [d.name for d in Domain.query.order_by(Domain.name) if in_scope(d.name)]
    summary = {name: values for name, values in reports.summary(days).items()
               if in_scope(name) or any(name.endswith("." + n) for n in names)}
    domain = request.args.get("domain") or ""
    if domain and domain not in summary and domain not in names:
        domain = ""
    detail = None
    if domain:
        dmarc, tls = reports.recent(domain)
        detail = {"failing": reports.failing_sources(domain, days), "passing": reports.passing_sources(domain, days),
                  "tls_failures": reports.tls_failures(domain, days), "dmarc": dmarc, "tls": tls,
                  "dns": reports.dns_records(domain) if domain in names else []}
    if form is None:
        values = filters.get_settings()
        form = ReportSettingsForm(formdata=None, data={key: values[key] for key in filters.REPORT_SETTINGS})
    return render_template("reports.html", summary=summary, domains=names, domain=domain, detail=detail, days=days,
                           periods=PERIODS, address=reports.address(), form=form), code


@bp.get("/")
def index():
    return _render()


@bp.post("/settings")
def save_settings():
    require_full_admin()
    form = ReportSettingsForm()
    if not form.validate_on_submit():
        return _render(form, 400)
    try:
        filters.update_settings(report_retention_days=form.report_retention_days.data,
                                dmarc_send_reports=form.dmarc_send_reports.data)
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return _render(form, 400)
    db.session.commit()
    flash("Report settings saved.", "success")
    return redirect(url_for("reports.index"))
