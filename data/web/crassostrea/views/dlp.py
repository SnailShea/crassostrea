from flask import flash, redirect, render_template, url_for

from ..extensions import db
from ..forms import DlpRuleForm, DlpTestForm
from ..models import DlpRule
from ..services import dlp
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint

bp = protected_blueprint("dlp", __name__, url_prefix="/dlp")

FIELDS = ("name", "detector", "pattern", "min_matches", "sender", "action", "active", "comment")
MAPS_FAILED = "Saved, but the filter maps could not be written. See the web UI log (journalctl -u crassostrea-web)."


def _index(test_form=None, results=None, code=200):
    return render_template("dlp/index.html", rules=dlp.rules(), test_form=test_form or DlpTestForm(formdata=None),
                           results=results, detectors=dlp.DETECTORS, actions=dlp.ACTIONS), code


def _saved(message):
    db.session.commit()
    if not sync_all():
        flash(MAPS_FAILED, "warning")
    flash(message, "success")


def _save(form, rule=None):
    """Validate and store the form; returns the rule or None (errors on the form)."""
    if not form.validate_on_submit():
        return None
    data = {key: getattr(form, key).data for key in FIELDS}
    data["pattern"], data["sender"], data["comment"] = (data["pattern"] or "", data["sender"] or "",
                                                         data["comment"] or "")
    try:
        rule = dlp.update_rule(rule, **data) if rule else dlp.add_rule(**data)
    except ServiceError as exc:
        db.session.rollback()
        field = getattr(form, exc.field or "", None)
        if field is not None:
            field.errors = [*field.errors, str(exc)]
        else:
            flash(str(exc), "danger")
        return None
    return rule


@bp.get("/")
def index():
    return _index()


@bp.route("/new", methods=["GET", "POST"])
def create():
    form = DlpRuleForm()
    rule = _save(form)
    if rule:
        _saved(f"Rule {rule.name} added.")
        return redirect(url_for("dlp.index"))
    return render_template("dlp/form.html", form=form, rule=None), 400 if form.is_submitted() else 200


@bp.route("/<int:rule_id>", methods=["GET", "POST"])
def edit(rule_id):
    rule = db.get_or_404(DlpRule, rule_id)
    form = DlpRuleForm(obj=rule)
    if form.is_submitted():
        if _save(form, rule):
            _saved(f"Rule {rule.name} saved.")
            return redirect(url_for("dlp.index"))
        return render_template("dlp/form.html", form=form, rule=rule), 400
    return render_template("dlp/form.html", form=form, rule=rule)


@bp.post("/<int:rule_id>/delete")
def delete(rule_id):
    rule = db.get_or_404(DlpRule, rule_id)
    dlp.delete_rule(rule)
    _saved(f"Rule {rule.name} deleted.")
    return redirect(url_for("dlp.index"))


@bp.post("/test")
def test():
    form = DlpTestForm()
    if not form.validate_on_submit():
        return _index(form, code=400)
    try:
        results = dlp.test(form.text.data, form.sender.data or "")
    except ServiceError as exc:
        getattr(form, exc.field, form.text).errors = [str(exc)]
        return _index(form, code=400)
    return _index(form, results)
