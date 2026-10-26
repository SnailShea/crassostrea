from flask import abort, flash, redirect, send_file, url_for

from ..extensions import db
from ..forms import BackupSettingsForm
from ..services import audit, backups, filters
from ..services.errors import ServiceError
from . import protected_blueprint, render_live

bp = protected_blueprint("backups", __name__, url_prefix="/backups")


def _render(form=None, code=200):
    settings = filters.get_settings()
    form = form or BackupSettingsForm(formdata=None, data={key: settings[key] for key in filters.BACKUP_SETTINGS})
    return render_live("backups.html", "_backups_live.html", form=form, backups=backups.backups(),
                       status=backups.status(), busy=backups.busy(), backup_dir=backups._dir()), code


@bp.get("/")
def index():
    return _render()


@bp.post("/create")
def create():
    try:
        backups.request_create()
    except ServiceError as exc:
        flash(str(exc), "danger")
    else:
        flash("Making a backup; it appears in the list when it is done.", "success")
    return redirect(url_for("backups.index"))


@bp.post("/<name>/delete")
def delete(name):
    try:
        backups.request_delete(name)
    except ServiceError as exc:
        flash(str(exc), "danger")
    else:
        flash(f"Deleting {name}.", "success")
    return redirect(url_for("backups.index"))


@bp.get("/<name>/download")
def download(name):
    try:
        path = backups.path_for(name)
    except ServiceError:
        abort(404)
    # it holds every password and private key of the gateway
    audit.event("backups.download", name, f"Downloaded {name}")
    return send_file(path, mimetype="application/gzip", as_attachment=True, download_name=name)


@bp.post("/settings")
def save_settings():
    form = BackupSettingsForm()
    if not form.validate_on_submit():
        return _render(form, 400)
    try:
        filters.update_settings(**{key: getattr(form, key).data for key in filters.BACKUP_SETTINGS})
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return _render(form, 400)
    db.session.commit()
    flash("Backup settings saved.", "success")
    return redirect(url_for("backups.index") + "#settings")
