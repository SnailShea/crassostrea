from flask import abort, flash, redirect, render_template, url_for
from flask_login import current_user

from ..extensions import db
from ..forms import AdminAccessForm, AdminForm
from ..models import Admin
from ..services import accounts, twofactor
from . import protected_blueprint, render_live

bp = protected_blueprint("users", __name__, url_prefix="/admins")


@bp.route("/", methods=["GET", "POST"])
def index():
    form = AdminForm()
    if form.validate_on_submit():
        try:
            admin = accounts.create_admin(form.username.data, form.password.data, role=form.role.data,
                                          domains=form.domains.data if form.role.data == "domain" else [])
        except accounts.AccountError as exc:
            db.session.rollback()
            (form.domains if exc.field == "domains" else form.username).errors.append(str(exc))
        else:
            db.session.commit()
            flash(f"Administrator {admin.username} created.", "success")
            return redirect(url_for("users.index"))
    admins = Admin.query.order_by(Admin.username).all()
    return render_live("users.html", "_users_live.html", form=form, admins=admins)


def _get(admin_id):
    admin = db.session.get(Admin, admin_id)
    if admin is None:
        abort(404)
    return admin


@bp.route("/<int:admin_id>", methods=["GET", "POST"])
def access(admin_id):
    """Role and domains of an administrator."""
    admin = _get(admin_id)
    form = AdminAccessForm(data={"role": admin.role, "domains": [d.name for d in admin.domains]})
    if form.validate_on_submit():
        try:
            accounts.update_admin(admin, acting=current_user, role=form.role.data,
                                  domains=form.domains.data if form.role.data == "domain" else [])
        except accounts.AccountError as exc:
            db.session.rollback()
            admin = _get(admin_id)
            (form.domains if exc.field == "domains" else form.role).errors.append(str(exc))
        else:
            db.session.commit()
            flash(f"Access of {admin.username} saved.", "success")
            return redirect(url_for("users.index"))
    return render_template("users_access.html", admin=admin, form=form), 400 if form.errors else 200


@bp.post("/<int:admin_id>/toggle")
def toggle(admin_id):
    admin = _get(admin_id)
    try:
        accounts.update_admin(admin, acting=current_user, active=not admin.active)
    except accounts.AccountError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        db.session.commit()
        flash(f"Administrator {admin.username} {'enabled' if admin.active else 'disabled'}.", "success")
    return redirect(url_for("users.index"))


@bp.post("/<int:admin_id>/delete")
def delete(admin_id):
    admin = _get(admin_id)
    try:
        accounts.delete_admin(admin, acting=current_user)
    except accounts.AccountError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        db.session.commit()
        flash(f"Administrator {admin.username} deleted.", "success")
    return redirect(url_for("users.index"))


@bp.post("/<int:admin_id>/reset-2fa")
def reset_two_factor(admin_id):
    """For an administrator who lost their phone and recovery codes."""
    admin = _get(admin_id)
    if admin.id == current_user.id:
        flash("Turn your own two-factor login off on your account page.", "danger")
    else:
        twofactor.disable(admin)
        db.session.commit()
        flash(f"Two-factor login of {admin.username} was reset.", "success")
    return redirect(url_for("users.index"))
