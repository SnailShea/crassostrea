import redis
from flask import flash, redirect, render_template, url_for

from ..extensions import db
from ..forms import JournalForm
from ..services import filters, journal, mailer
from ..services.errors import ServiceError
from . import protected_blueprint, render_live

bp = protected_blueprint("journal", __name__, url_prefix="/journal")


def _render(form=None, code=200):
    if form is None:
        values = filters.get_settings()
        form = JournalForm(formdata=None, data={key: values[key] for key in filters.JOURNAL_SETTINGS})
    try:
        state, error = journal.status(), None
    except redis.RedisError as exc:
        state, error = None, f"Valkey cannot be reached ({exc})"
    return render_live("journal.html", "_journal_live.html", form=form, state=state, state_error=error,
                       sender=journal.sender()), code


@bp.get("/")
def index():
    return _render()


@bp.post("/")
def save():
    form = JournalForm()
    if not form.validate_on_submit():
        return _render(form, 400)
    try:
        filters.update_settings(journal_address=form.journal_address.data or "",
                                journal_inbound=form.journal_inbound.data, journal_outbound=form.journal_outbound.data,
                                journal_rejected=form.journal_rejected.data, journal_format=form.journal_format.data)
    except ServiceError as exc:
        db.session.rollback()
        form.journal_address.errors = [str(exc)]
        return _render(form, 400)
    db.session.commit()
    flash("Journaling saved." if form.journal_address.data else "Journaling is off.", "success")
    return redirect(url_for("journal.index"))


@bp.post("/test")
def test():
    if not filters.get_settings()["journal_address"]:
        flash("Enter the archive address first.", "warning")
        return redirect(url_for("journal.index"))
    try:
        journal.send_test()
    except mailer.ReleaseError as exc:
        flash(f"The test could not be sent: {exc}", "danger")
    else:
        flash("A test journal report was sent.", "success")
    return redirect(url_for("journal.index"))
