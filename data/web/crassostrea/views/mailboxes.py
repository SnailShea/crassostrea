"""Administration of mailbox users (self-service quarantine accounts)."""
from flask import abort, flash, redirect, render_template, request, url_for

from .. import passwords
from ..extensions import db
from ..forms import MailboxUserForm, SetPasswordForm
from ..models import Domain, MailboxUser, QuarantineItem, get_setting
from ..services import accounts, invites
from ..services.quarantine import base_address, owned_by
from . import back, in_scope, mailbox_settings, protected_blueprint, render_live, require_scope, scope

bp = protected_blueprint("mailboxes", __name__, url_prefix="/mailboxes", domain_admins=True)


def _get(user_id):
    user = db.session.get(MailboxUser, user_id)
    if user is None:
        abort(404)
    require_scope(user.domain.name)
    return user


def _pending_counts():
    """{base address: inbound quarantined messages not released}"""
    counts = {}
    rows = (db.session.query(QuarantineItem.rcpt, db.func.count(QuarantineItem.id))
            .filter(QuarantineItem.direction == "inbound", QuarantineItem.released_at.is_(None))
            .group_by(QuarantineItem.rcpt))
    for rcpt, count in rows:
        address = base_address(rcpt.lower())
        counts[address] = counts.get(address, 0) + count
    return counts


@bp.route("/", methods=["GET", "POST"])
def index():
    form = MailboxUserForm()
    if form.validate_on_submit():
        try:
            if not in_scope(form.email.data.rsplit("@", 1)[-1]):
                raise accounts.AccountError("You can only add users of your own domains.")
            user = accounts.create_mailbox_user(form.email.data, form.password.data)
        except accounts.AccountError as exc:
            db.session.rollback()
            form.email.errors.append(str(exc))
        else:
            db.session.commit()
            flash(f"Mailbox user {user.email} created. They can log in with their address.", "success")
            return redirect(url_for("mailboxes.index"))

    query = MailboxUser.query
    allowed = scope()
    if allowed is not None:
        query = query.join(Domain).filter(Domain.name.in_(sorted(allowed) or [""]))
    domain_filter = request.args.get("domain", "").strip().lower()
    search = request.args.get("q", "").strip().lower()
    if domain_filter:
        query = (query if allowed is not None else query.join(Domain)).filter(Domain.name == domain_filter)
    if search:
        query = query.filter(MailboxUser.email.contains(search))
    users = query.order_by(MailboxUser.email).all()
    domains = [d.name for d in Domain.query.order_by(Domain.name) if in_scope(d.name)]
    return render_live("mailboxes.html", "_mailboxes_live.html", form=form, users=users, domains=domains,
                       pending=_pending_counts())


@bp.get("/<int:user_id>")
def edit(user_id):
    user = _get(user_id)
    ctx = mailbox_settings.context(user, limited=False)
    ctx.update(settings_url=url_for("mailboxes.save_settings", user_id=user.id),
               entry_url=url_for("mailboxes.add_entry", user_id=user.id),
               entry_delete_endpoint="mailboxes.delete_entry", entry_delete_args={"user_id": user.id})
    items = QuarantineItem.query.filter(owned_by(user.email))
    ctx.update(quarantine_recent=items.order_by(QuarantineItem.created_at.desc()).limit(10).all(),
               quarantine_pending=items.filter(QuarantineItem.released_at.is_(None)).count())
    return render_template("mailbox_edit.html", password_form=SetPasswordForm(prefix="pw"),
                           password_format=passwords.scheme(user.password_hash), **ctx)


@bp.post("/<int:user_id>/settings")
def save_settings(user_id):
    mailbox_settings.save(_get(user_id), limited=False)
    return redirect(url_for("mailboxes.edit", user_id=user_id))


@bp.post("/<int:user_id>/entries")
def add_entry(user_id):
    mailbox_settings.add_entry(_get(user_id))
    return redirect(url_for("mailboxes.edit", user_id=user_id, _anchor="lists"))


@bp.post("/<int:user_id>/entries/<int:entry_id>/delete")
def delete_entry(user_id, entry_id):
    mailbox_settings.delete_entry(_get(user_id), entry_id)
    return redirect(url_for("mailboxes.edit", user_id=user_id, _anchor="lists"))


@bp.post("/<int:user_id>/toggle")
def toggle(user_id):
    user = _get(user_id)
    accounts.update_mailbox_user(user, active=not user.active)
    db.session.commit()
    flash(f"{user.email} {'enabled' if user.active else 'disabled'}.", "success")
    if request.form.get("next") == "edit":
        return redirect(url_for("mailboxes.edit", user_id=user.id))
    return redirect(back("mailboxes.index"))


@bp.post("/<int:user_id>/password")
def set_password(user_id):
    user = _get(user_id)
    form = SetPasswordForm(prefix="pw")
    if form.validate_on_submit():
        try:
            accounts.update_mailbox_user(user, password=form.password.data)
        except accounts.AccountError as exc:
            db.session.rollback()
            flash(str(exc), "danger")
        else:
            db.session.commit()
            flash(f"Password of {user.email} changed.", "success")
    else:
        for errors in form.errors.values():
            for error in errors:
                flash(error, "danger")
    return redirect(url_for("mailboxes.edit", user_id=user.id))


@bp.post("/<int:user_id>/password-link")
def send_password_link(user_id):
    user = _get(user_id)
    try:
        invites.send_link(user)
    except invites.InviteError as exc:
        db.session.rollback()
        flash(f"The link could not be sent: {exc}", "danger")
    else:
        db.session.commit()
        flash(f"A link to set a password was sent to {user.email}. It is valid for "
              f"{get_setting('mailbox_invite_days')} day(s); earlier links stop working.", "success")
    return redirect(url_for("mailboxes.edit", user_id=user.id))


@bp.post("/<int:user_id>/delete")
def delete(user_id):
    user = _get(user_id)
    accounts.delete_mailbox_user(user)
    db.session.commit()
    flash(f"Mailbox user {user.email} deleted. Their quarantined mail is kept for administrators.", "success")
    return redirect(back("mailboxes.index"))
