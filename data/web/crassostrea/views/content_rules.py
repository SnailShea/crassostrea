import re

from flask import flash, redirect, render_template, url_for

from ..extensions import db
from ..forms import ContentRuleForm, ContentTestForm
from ..models import ContentRule
from ..services import content_rules
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint

bp = protected_blueprint("content_rules", __name__, url_prefix="/content-rules")

MAPS_FAILED = "Saved, but the filter maps could not be written. See the web UI log (journalctl -u crassostrea-web)."


def _index(test_form=None, results=None, code=200):
    return render_template("content_rules/index.html", rules=content_rules.rules(), results=results,
                           test_form=test_form or ContentTestForm(formdata=None),
                           fields=content_rules.FIELDS, matches=content_rules.MATCHES,
                           actions=content_rules.ACTIONS, directions=content_rules.DIRECTIONS), code


def _saved(message):
    db.session.commit()
    if not sync_all():
        flash(MAPS_FAILED, "warning")
    flash(message, "success")


def _save(form, rule=None):
    if not form.validate_on_submit():
        return None
    data = {key: getattr(form, key).data for key in content_rules.COLUMNS}
    data.update(header=data["header"] or "", message=data["message"] or "", comment=data["comment"] or "",
                score=data["score"] or 0.0)
    try:
        return content_rules.update_rule(rule, **data) if rule else content_rules.add_rule(**data)
    except ServiceError as exc:
        db.session.rollback()
        field = getattr(form, exc.field or "", None)
        if field is not None:
            field.errors = [*field.errors, str(exc)]
        else:
            flash(str(exc), "danger")
        return None


@bp.get("/")
def index():
    return _index()


@bp.route("/new", methods=["GET", "POST"])
def create():
    form = ContentRuleForm()
    rule = _save(form)
    if rule:
        _saved(f"Rule {rule.name} added.")
        return redirect(url_for("content_rules.index"))
    return render_template("content_rules/form.html", form=form, rule=None), 400 if form.is_submitted() else 200


@bp.route("/<int:rule_id>", methods=["GET", "POST"])
def edit(rule_id):
    rule = db.get_or_404(ContentRule, rule_id)
    form = ContentRuleForm(obj=rule)
    if form.is_submitted():
        if _save(form, rule):
            _saved(f"Rule {rule.name} saved.")
            return redirect(url_for("content_rules.index"))
        return render_template("content_rules/form.html", form=form, rule=rule), 400
    return render_template("content_rules/form.html", form=form, rule=rule)


@bp.post("/<int:rule_id>/delete")
def delete(rule_id):
    rule = db.get_or_404(ContentRule, rule_id)
    content_rules.delete_rule(rule)
    _saved(f"Rule {rule.name} deleted.")
    return redirect(url_for("content_rules.index"))


@bp.post("/test")
def test():
    form = ContentTestForm()
    if not form.validate_on_submit():
        return _index(form, code=400)
    try:
        values = content_rules.message_values(form.source.data, form.envelope_from.data or "",
                                              re.split(r"[\s,;]+", form.recipients.data or ""))
        results = content_rules.test(values, form.direction.data)
    except ServiceError as exc:
        form.source.errors = [str(exc)]
        return _index(form, code=400)
    return _index(form, results)
