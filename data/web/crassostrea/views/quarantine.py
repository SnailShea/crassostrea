import io

from flask import abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user

from ..extensions import db
from ..models import DIRECTIONS, Domain, MailboxUser, QuarantineItem
from ..services import html_preview as html_preview_service, mailer
from ..services.errors import ServiceError
from ..services.maps import sync_all
from ..services.quarantine import (SENDER_SCOPES, base_address, learn_spam_and_delete, list_sender, owned_by,
                                   parse_message, release, sender_mailbox)
from ..services.rspamd import RspamdError
from . import back, html_preview, protected_blueprint, render_live, require_scope, scope

bp = protected_blueprint("quarantine", __name__, url_prefix="/quarantine", domain_admins=True)

PER_PAGE = 50


def _scoped(query):
    allowed = scope()
    return query if allowed is None else query.filter(QuarantineItem.domain.in_(sorted(allowed) or [""]))


def _domains():
    allowed = scope()
    return [d.name for d in Domain.query.order_by(Domain.name) if allowed is None or d.name in allowed]


def _filtered_query():
    query = _scoped(QuarantineItem.query)
    domain = request.args.get("domain", "").strip().lower()
    search = request.args.get("q", "").strip()
    status = request.args.get("status", "")
    direction = request.args.get("direction", "")
    owner = _owner()
    if owner:
        # one mailbox's inbound mail, with its sub-addresses (alice+tag@)
        query = query.filter(owned_by(owner))
    if direction in DIRECTIONS:
        query = query.filter(QuarantineItem.direction == direction)
    if domain:
        query = query.filter(QuarantineItem.domain == domain)
    if search:
        like = f"%{search}%"
        query = query.filter(db.or_(QuarantineItem.subject.ilike(like), QuarantineItem.sender.ilike(like),
                                    QuarantineItem.rcpt.ilike(like), QuarantineItem.qid == search))
    if status == "released":
        query = query.filter(QuarantineItem.released_at.isnot(None))
    elif status == "pending":
        query = query.filter(QuarantineItem.released_at.is_(None))
    return query


def _owner():
    """?user=: the mailbox (base address) whose quarantine is shown."""
    value = request.args.get("user", "").strip().lower()
    if "@" not in value or len(value) > 320:
        return ""
    return base_address(value)


@bp.get("/")
def index():
    page = request.args.get("page", 1, type=int)
    pagination = (_filtered_query().order_by(QuarantineItem.created_at.desc())
                  .paginate(page=page, per_page=PER_PAGE, error_out=False))
    domains = _domains()
    owner = _owner()
    mailbox = MailboxUser.query.filter_by(email=owner).first() if owner else None
    return render_live("quarantine/index.html", "quarantine/_live.html", pagination=pagination, domains=domains,
                       directions=DIRECTIONS, owner=owner, mailbox=mailbox)


def _get_item(item_id):
    item = db.session.get(QuarantineItem, item_id)
    if item is None:
        abort(404)
    require_scope(item.domain)
    return item


@bp.get("/<int:item_id>")
def show(item_id):
    item = _get_item(item_id)
    return render_template("quarantine/show.html", item=item, sender_scopes=_sender_scopes(item),
                           html_url=url_for("quarantine.html", item_id=item.id)
                           if html_preview_service.has_html(item.message) else None,
                           **parse_message(item.message))


@bp.get("/<int:item_id>/html")
def html(item_id):
    return html_preview(_get_item(item_id).message)


@bp.get("/<int:item_id>/raw")
def raw(item_id):
    item = _get_item(item_id)
    return send_file(io.BytesIO(item.message), mimetype="message/rfc822", as_attachment=True,
                     download_name=f"quarantine-{item.id}.eml")


def _sender_scopes(item):
    """The lists the sender of ``item`` can go on: {scope: label}."""
    if item.direction != "inbound" or not item.sender:
        return {}
    scopes = dict(SENDER_SCOPES)
    if sender_mailbox(item) is None:
        scopes.pop("mailbox")
    if scope() is not None:  # domain administrators: their domains only
        scopes.pop("global")
    return scopes


@bp.post("/<int:item_id>/action")
def action(item_id):
    item = _get_item(item_id)
    act = request.form.get("action")
    if act in ("release_allow", "block_delete"):
        return _list_sender_action(item, act)
    try:
        if act in ("release", "release_ham"):
            if item.is_virus and request.form.get("confirm_virus") != "yes":
                flash("This message contains a virus. Confirm the release explicitly.", "danger")
                return redirect(url_for("quarantine.show", item_id=item.id))
            notes = release(item, current_user.username, learn_ham=act == "release_ham")
            db.session.commit()
            flash(f"Message released to {item.rcpt}. " + "; ".join(notes), "success")
            return redirect(url_for("quarantine.show", item_id=item.id))
        if act == "learn_spam":
            notes = learn_spam_and_delete(item)
            db.session.commit()
            flash("Message " + ", ".join(notes) + " and deleted.", "success")
        elif act == "delete":
            db.session.delete(item)
            db.session.commit()
            flash("Message deleted.", "success")
        else:
            abort(400)
    except (mailer.ReleaseError, RspamdError) as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(url_for("quarantine.show", item_id=item_id))
    return redirect(url_for("quarantine.index"))


def _list_sender_action(item, act):
    """Release & allow sender, or block sender & delete."""
    list_scope = request.form.get("scope", "")
    if list_scope not in _sender_scopes(item):
        flash("Choose where the sender is listed.", "danger")
        return redirect(url_for("quarantine.show", item_id=item.id))
    if act == "release_allow" and item.is_virus and request.form.get("confirm_virus") != "yes":
        flash("This message contains a virus. Confirm the release explicitly.", "danger")
        return redirect(url_for("quarantine.show", item_id=item.id))
    try:
        listed = list_sender(item, "allow" if act == "release_allow" else "block", list_scope)
        if act == "release_allow":
            notes = release(item, current_user.username)
            db.session.commit()
            sync_all()
            flash(f"Message released to {item.rcpt}. {listed} " + "; ".join(notes), "success")
            return redirect(url_for("quarantine.show", item_id=item.id))
        db.session.delete(item)
        db.session.commit()
        sync_all()
        flash(f"{listed} Message deleted.", "success")
        return redirect(url_for("quarantine.index"))
    except (ServiceError, mailer.ReleaseError) as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(url_for("quarantine.show", item_id=item.id))


@bp.post("/bulk")
def bulk():
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    act = request.form.get("action")
    items = _scoped(QuarantineItem.query).filter(QuarantineItem.id.in_(ids)).all() if ids else []
    if not items:
        flash("No messages selected.", "info")
        return redirect(back("quarantine.index"))

    done, failed = 0, []
    for item in items:
        try:
            if act == "release":
                if item.is_virus:
                    failed.append(f"#{item.id}: contains a virus, release it individually")
                    continue
                if item.released_at is not None:
                    continue
                release(item, current_user.username)
            elif act == "learn_spam":
                learn_spam_and_delete(item)
            elif act == "delete":
                db.session.delete(item)
            else:
                abort(400)
            db.session.commit()
            done += 1
        except (mailer.ReleaseError, RspamdError) as exc:
            db.session.rollback()
            failed.append(f"#{item.id}: {exc}")
    if done:
        flash(f"{done} message(s) processed.", "success")
    for message in failed[:10]:
        flash(message, "danger")
    return redirect(back("quarantine.index"))
