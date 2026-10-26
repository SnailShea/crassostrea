"""Quarantine access through the token link of a digest mail.

No login: the token in the URL grants access to the inbound quarantine of one
address until it expires. GET requests never change anything (mail scanners
prefetch links), releasing and deleting require a POST from the page.
"""
from flask import Blueprint, abort, flash, g, redirect, render_template, request, url_for

from ..extensions import db
from ..models import QuarantineItem, utcnow
from ..services.digest import resolve_token
from ..services.quarantine import owned_by, parse_message, self_service_release, sender_mailbox
from . import mailbox_settings, safe_next

bp = Blueprint("token", __name__, url_prefix="/q/<token>")

PER_PAGE = 50


@bp.url_value_preprocessor
def load_token(endpoint, values):
    g.token = values.pop("token", None)


@bp.url_defaults
def add_token(endpoint, values):
    values.setdefault("token", getattr(g, "token", None))


@bp.before_request
def require_token():
    row = resolve_token(g.token)
    if row is None:
        return render_template("token/invalid.html"), 404
    row.last_used_at = utcnow()
    db.session.commit()
    g.digest_address = row.rcpt


@bp.after_request
def no_leaks(response):
    # The token is part of the URL: never send it to other sites, never cache
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response


def _items():
    return QuarantineItem.query.filter(owned_by(g.digest_address))


def _get(item_id):
    item = _items().filter(QuarantineItem.id == item_id).first()
    if item is None:
        abort(404)
    return item


@bp.get("/")
def index():
    page = request.args.get("page", 1, type=int)
    pagination = (_items().order_by(QuarantineItem.created_at.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    return render_template("token/index.html", pagination=pagination, address=g.digest_address)


@bp.get("/<int:item_id>")
def show(item_id):
    item = _get(item_id)
    return render_template("token/show.html", item=item, address=g.digest_address,
                           personal_lists=sender_mailbox(item) is not None and bool(item.sender),
                           **parse_message(item.message))


def _released_by():
    return f"digest link ({g.digest_address})"


@bp.post("/<int:item_id>/action")
def action(item_id):
    item = _get(item_id)
    act = request.form.get("action")
    if act in ("release_allow", "block_delete") and not (act == "release_allow" and item.is_virus):
        return mailbox_settings.personal_list_action(item, act, _released_by(), "token.show", "token.index")
    if act == "release":
        error = self_service_release(item, _released_by())
        flash(error or "The message has been delivered to your mailbox.", "danger" if error else "success")
        return redirect(url_for("token.show", item_id=item.id))
    if act == "delete":
        db.session.delete(item)
        db.session.commit()
        flash("Message deleted.", "success")
        return redirect(url_for("token.index"))
    abort(400)


@bp.post("/bulk")
def bulk():
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    act = request.form.get("action")
    if act not in ("release", "delete"):
        abort(400)
    items = _items().filter(QuarantineItem.id.in_(ids)).all() if ids else []
    done, errors = 0, []
    for item in items:
        if act == "delete":
            db.session.delete(item)
            db.session.commit()
            done += 1
            continue
        error = self_service_release(item, _released_by())
        if error:
            errors.append(f"“{item.subject or '(no subject)'}”: {error}")
        else:
            done += 1
    if done:
        flash(f"{done} message(s) {'released' if act == 'release' else 'deleted'}.", "success")
    for error in errors[:10]:
        flash(error, "danger")
    if not items:
        flash("No messages selected.", "info")
    return redirect(safe_next(request.form.get("next"), url_for("token.index")))
