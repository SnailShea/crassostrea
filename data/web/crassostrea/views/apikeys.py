"""API key management. A key is only shown once, right after it was created."""
from flask import abort, flash, redirect, render_template, url_for
from flask_wtf import FlaskForm
from wtforms import BooleanField, StringField
from wtforms.validators import InputRequired, Length, Optional, ValidationError

from ..extensions import db
from ..models import ApiKey
from ..validators import ValidationError as InvalidValue, normalize_network
from . import protected_blueprint

bp = protected_blueprint("apikeys", __name__, url_prefix="/api-keys")


class ApiKeyForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired(), Length(max=64)])
    read_only = BooleanField("Read-only (GET requests only)")
    allow_from = StringField("Allowed source networks", validators=[Optional(), Length(max=1024)])

    def validate_allow_from(self, field):
        networks = []
        for part in (field.data or "").replace(" ", ",").split(","):
            if part.strip():
                try:
                    networks.append(normalize_network(part))
                except InvalidValue as exc:
                    raise ValidationError(str(exc))
        field.data = ",".join(networks)


def _render(form, new_key=None):
    keys = ApiKey.query.order_by(ApiKey.created_at.desc()).all()
    return render_template("apikeys.html", form=form, keys=keys, new_key=new_key)


@bp.get("/")
def index():
    return _render(ApiKeyForm())


@bp.post("/")
def create():
    form = ApiKeyForm()
    if not form.validate_on_submit():
        return _render(form), 400
    api_key, token = ApiKey.create(form.name.data, form.read_only.data, form.allow_from.data or "")
    db.session.add(api_key)
    db.session.commit()
    # Rendered directly (no redirect + flash): the key must not end up in the session cookie
    return _render(ApiKeyForm(formdata=None), new_key={"name": api_key.name, "token": token})


@bp.post("/<int:key_id>/delete")
def delete(key_id):
    api_key = db.session.get(ApiKey, key_id)
    if api_key is None:
        abort(404)
    db.session.delete(api_key)
    db.session.commit()
    flash(f"API key {api_key.name} revoked.", "success")
    return redirect(url_for("apikeys.index"))
