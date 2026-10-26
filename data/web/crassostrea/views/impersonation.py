from flask import flash, redirect, render_template, url_for

from ..extensions import db
from ..forms import ImpersonationSettingsForm, ImpersonationTestForm, ProtectedPersonForm
from ..models import ProtectedPerson, get_setting
from ..services import filters, impersonation
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint

bp = protected_blueprint("impersonation", __name__, url_prefix="/impersonation")

MAPS_FAILED = "Saved, but the filter maps could not be written. See the web UI log (journalctl -u crassostrea-web)."


def _render(settings_form=None, person_form=None, test_form=None, result=None, code=200):
    if settings_form is None:
        values = filters.get_settings()
        settings_form = ImpersonationSettingsForm(formdata=None, data={key: values[key]
                                                                       for key in filters.IMPERSONATION_SETTINGS})
    return render_template("impersonation.html", settings_form=settings_form,
                           person_form=person_form or ProtectedPersonForm(formdata=None, prefix="person"),
                           test_form=test_form or ImpersonationTestForm(formdata=None, prefix="test"),
                           result=result, people=impersonation.people(),
                           domains=impersonation.protected_domains(),
                           reject_score=get_setting("reject_score")), code


def _field_error(form, exc):
    db.session.rollback()
    field = getattr(form, exc.field or "", None)
    if field is not None:
        field.errors = [*field.errors, str(exc)]
    else:
        flash(str(exc), "danger")


def _saved(message):
    db.session.commit()
    if not sync_all():
        flash(MAPS_FAILED, "warning")
    flash(message, "success")


@bp.get("/")
def index():
    return _render()


@bp.post("/settings")
def save_settings():
    form = ImpersonationSettingsForm()
    if not form.validate_on_submit():
        return _render(settings_form=form, code=400)
    try:
        filters.update_settings(
            impersonation_name_score=form.impersonation_name_score.data,
            impersonation_lookalike_score=form.impersonation_lookalike_score.data,
            impersonation_spoof_score=form.impersonation_spoof_score.data,
            impersonation_extra_domains=form.impersonation_extra_domains.data or "",
            impersonation_exempt_domains=form.impersonation_exempt_domains.data or "")
    except ServiceError as exc:
        _field_error(form, exc)
        return _render(settings_form=form, code=400)
    _saved("Impersonation checks saved. Rspamd applies them within a minute.")
    return redirect(url_for("impersonation.index"))


@bp.post("/people")
def add_person():
    form = ProtectedPersonForm(prefix="person")
    if not form.validate_on_submit():
        return _render(person_form=form, code=400)
    try:
        person = impersonation.add_person(form.name.data, form.addresses.data or "")
    except ServiceError as exc:
        _field_error(form, exc)
        return _render(person_form=form, code=400)
    _saved(f"{person.name} is protected.")
    return redirect(url_for("impersonation.index") + "#people")


@bp.post("/people/<int:person_id>/delete")
def delete_person(person_id):
    person = db.get_or_404(ProtectedPerson, person_id)
    impersonation.delete_person(person)
    _saved(f"{person.name} is no longer protected.")
    return redirect(url_for("impersonation.index") + "#people")


@bp.post("/test")
def test():
    form = ImpersonationTestForm(prefix="test")
    if not form.validate_on_submit():
        return _render(test_form=form, code=400)
    try:
        result = impersonation.test(form.display_name.data or "", form.address.data)
    except ServiceError as exc:
        form.address.errors = [str(exc)]
        return _render(test_form=form, code=400)
    return _render(test_form=form, result=result)
