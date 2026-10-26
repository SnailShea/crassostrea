from flask import flash, redirect, render_template, request, url_for

from ..extensions import db
from ..forms import DirectoryForm
from ..models import Directory
from ..services import directory as directory_service
from ..services.errors import ServiceError
from ..services.store import job_lock
from . import protected_blueprint

bp = protected_blueprint("directories", __name__, url_prefix="/directories")


def _data(form, directory=None):
    data = {key: getattr(form, key).data for key in directory_service.FIELDS}
    for key, value in data.items():
        if isinstance(value, str):
            data[key] = value.strip()
    # an empty password field keeps the stored secret
    for key in directory_service.SECRETS:
        if directory is not None and not data[key]:
            del data[key]
    return data


def _save(form, directory=None):
    if not form.validate_on_submit():
        return None
    try:
        data = _data(form, directory)
        if directory is None:
            return directory_service.create_directory(**data)
        return directory_service.update_directory(directory, **data)
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
    return render_template("directories/index.html", directories=directory_service.directories(),
                           kinds=directory_service.KINDS)


@bp.route("/new", methods=["GET", "POST"])
def create():
    form = DirectoryForm()
    directory = _save(form)
    if directory:
        db.session.commit()
        flash(f"Directory {directory.name} added. Test it, then choose it for domains (recipient validation).",
              "success")
        return redirect(url_for("directories.edit", directory_id=directory.id))
    return render_template("directories/form.html", form=form, directory=None,
                           defaults=directory_service), 400 if form.is_submitted() else 200


@bp.route("/<int:directory_id>", methods=["GET", "POST"])
def edit(directory_id):
    directory = db.get_or_404(Directory, directory_id)
    form = DirectoryForm(obj=directory)
    if form.is_submitted():
        if _save(form, directory):
            db.session.commit()
            flash(f"Directory {directory.name} saved.", "success")
            return redirect(url_for("directories.edit", directory_id=directory.id))
        directory = db.get_or_404(Directory, directory_id)
        return render_template("directories/form.html", form=form, directory=directory,
                               defaults=directory_service), 400
    # secrets are never sent to the browser
    form.bind_password.data = form.client_secret.data = ""
    return render_template("directories/form.html", form=form, directory=directory, defaults=directory_service)


@bp.post("/<int:directory_id>/test")
def test(directory_id):
    directory = db.get_or_404(Directory, directory_id)
    try:
        found = directory_service.preview(directory)
    except directory_service.DirectoryError as exc:
        flash(f"The test failed: {exc}", "danger")
    else:
        counts = ", ".join(f"{name}: {count}" for name, count in found["domains"].items()) or "no domain uses it yet"
        flash(f"{found['total']} addresses found ({counts}).", "success")
        if found["sample"]:
            flash("For example: " + ", ".join(found["sample"][:10]), "info")
    return redirect(url_for("directories.edit", directory_id=directory.id))


@bp.post("/<int:directory_id>/sync")
def sync(directory_id):
    directory = db.get_or_404(Directory, directory_id)
    force = request.form.get("force") == "1"
    with job_lock("sync-directories", timeout=600, wait=30) as acquired:
        if not acquired:
            flash("A synchronisation is running; try again in a minute.", "warning")
            return redirect(url_for("directories.edit", directory_id=directory.id))
        try:
            results = directory_service.sync(directory, force=force)
        except directory_service.DirectoryError as exc:
            flash(f"Not synchronised: {exc}", "danger")
        else:
            if not results:
                flash("No domain uses this directory for recipient validation yet.", "info")
            for name, result in results.items():
                flash(f"{name}: {result['total']} recipients ({result['added']} added, {result['removed']} "
                      "removed).", "success")
    return redirect(url_for("directories.edit", directory_id=directory.id))


@bp.post("/<int:directory_id>/delete")
def delete(directory_id):
    directory = db.get_or_404(Directory, directory_id)
    try:
        directory_service.delete_directory(directory)
    except ServiceError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("directories.edit", directory_id=directory.id))
    db.session.commit()
    flash(f"Directory {directory.name} deleted.", "success")
    return redirect(url_for("directories.index"))
