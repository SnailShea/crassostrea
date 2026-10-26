"""Self-service quarantine for mailbox users.

A mailbox user only ever sees inbound messages addressed to their own
address. Releasing viruses and training the filter are left to administrators.
"""
from flask import abort, flash, redirect, render_template, request, url_for
from flask_login import current_user

from ..extensions import db
from ..models import QuarantineItem
from ..services.quarantine import owned_by, parse_message, self_service_release
from . import back, mailbox_blueprint, mailbox_settings

bp = mailbox_blueprint("portal", __name__, url_prefix="/my")

PER_PAGE = 50


def _own_items():
    return QuarantineItem.query.filter(owned_by(current_user.email))


def _get_own_item(item_id):
    item = _own_items().filter(QuarantineItem.id == item_id).first()
    if item is None:
        abort(404)
    return item


@bp.get("/")
def index():
    query = _own_items()
    search = request.args.get("q", "").strip()
    if search:
        like = f"%{search}%"
        query = query.filter(db.or_(QuarantineItem.subject.ilike(like), QuarantineItem.sender.ilike(like)))
    page = request.args.get("page", 1, type=int)
    pagination = (query.order_by(QuarantineItem.created_at.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    return render_template("portal/index.html", pagination=pagination)


@bp.get("/<int:item_id>")
def show(item_id):
    item = _get_own_item(item_id)
    return render_template("portal/show.html", item=item, **parse_message(item.message))


def _release_own(item):
    return self_service_release(item, current_user.email)


@bp.post("/<int:item_id>/action")
def action(item_id):
    item = _get_own_item(item_id)
    act = request.form.get("action")
    if act in ("release_allow", "block_delete") and not (act == "release_allow" and item.is_virus):
        return mailbox_settings.personal_list_action(item, act, current_user.email, "portal.show", "portal.index")
    if act == "release":
        error = _release_own(item)
        if error:
            flash(error, "danger")
        else:
            flash("The message has been delivered to your mailbox.", "success")
        return redirect(url_for("portal.show", item_id=item.id))
    if act == "delete":
        db.session.delete(item)
        db.session.commit()
        flash("Message deleted.", "success")
        return redirect(url_for("portal.index"))
    abort(400)


@bp.post("/bulk")
def bulk():
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    act = request.form.get("action")
    if act not in ("release", "delete"):
        abort(400)
    items = _own_items().filter(QuarantineItem.id.in_(ids)).all() if ids else []
    if not items:
        flash("No messages selected.", "info")
        return redirect(back("portal.index"))
    done, errors = 0, []
    for item in items:
        if act == "delete":
            db.session.delete(item)
            db.session.commit()
            done += 1
            continue
        error = _release_own(item)
        if error:
            errors.append(f"“{item.subject or '(no subject)'}”: {error}")
        else:
            done += 1
    if done:
        flash(f"{done} message(s) {'released' if act == 'release' else 'deleted'}.", "success")
    for error in errors[:10]:
        flash(error, "danger")
    return redirect(back("portal.index"))


@bp.get("/settings")
def settings():
    return render_template("portal/settings.html", **_settings_context())


def _settings_context():
    ctx = mailbox_settings.context(current_user, limited=True)
    ctx.update(settings_url=url_for("portal.save_settings"), entry_url=url_for("portal.add_entry"),
               entry_delete_endpoint="portal.delete_entry", entry_delete_args={})
    return ctx


@bp.post("/settings")
def save_settings():
    mailbox_settings.save(current_user, limited=True)
    return redirect(url_for("portal.settings"))


@bp.post("/settings/entries")
def add_entry():
    mailbox_settings.add_entry(current_user)
    return redirect(url_for("portal.settings", _anchor="lists"))


@bp.post("/settings/entries/<int:entry_id>/delete")
def delete_entry(entry_id):
    mailbox_settings.delete_entry(current_user, entry_id)
    return redirect(url_for("portal.settings", _anchor="lists"))
