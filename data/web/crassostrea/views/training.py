from flask import flash, redirect, render_template, url_for

from ..extensions import db
from ..forms import LearnForm, UserReportSettingsForm
from ..services import filters, user_reports
from ..services.errors import ServiceError
from ..services.maps import sync_all
from ..services.rspamd import RspamdError, train
from . import protected_blueprint

bp = protected_blueprint("training", __name__, url_prefix="/training")


@bp.route("/", methods=["GET", "POST"])
def index():
    form = LearnForm()
    if form.validate_on_submit():
        message = b""
        if form.message_file.data:
            message = form.message_file.data.read()
        elif form.message_text.data:
            message = form.message_text.data.replace("\r\n", "\n").encode("utf-8")
        if not message.strip():
            flash("Please upload or paste a message.", "danger")
        elif b":" not in message.split(b"\n", 1)[0]:
            flash("This does not look like a raw e-mail message (headers are missing).", "danger")
        else:
            try:
                notes = train(message, spam=form.kind.data == "spam")
                flash("Message " + ", ".join(notes) + ".", "success")
                return redirect(url_for("training.index"))
            except RspamdError as exc:
                flash(str(exc), "danger")
    return _render(form)


def _render(form=None, reports_form=None, code=200):
    values = filters.get_settings()
    return render_template("training.html", form=form or LearnForm(formdata=None),
                           reports_form=reports_form or UserReportSettingsForm(
                               formdata=None, prefix="reports",
                               data={key: values[key] for key in filters.USER_REPORT_SETTINGS}),
                           addresses=user_reports.addresses(), recent=user_reports.recent(), kinds=user_reports.KINDS,
                           enabled=values["user_reports_enabled"]), code


@bp.post("/reports")
def save_reports():
    form = UserReportSettingsForm(prefix="reports")
    if not form.validate_on_submit():
        return _render(reports_form=form, code=400)
    try:
        filters.update_settings(user_reports_enabled=form.user_reports_enabled.data,
                                user_reports_confirm=form.user_reports_confirm.data,
                                user_reports_per_hour=form.user_reports_per_hour.data)
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return _render(reports_form=form, code=400)
    db.session.commit()
    if not sync_all():
        flash("Saved, but the filter maps could not be written. See the web UI log (journalctl -u crassostrea-web).",
              "warning")
    flash("Reporting saved. Rspamd applies it within a minute.", "success")
    return redirect(url_for("training.index") + "#reports")
