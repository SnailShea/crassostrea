"""Personal filter settings of a mailbox user (thresholds, digest, lists).

Shared by the self-service portal (``limited=True``: threshold range is
restricted) and the administrator's mailbox user page.
"""
from flask import flash, redirect, url_for

from ..extensions import db
from ..forms import MailboxSettingsForm, UserListEntryForm
from ..models import DIGEST_INTERVALS
from ..services import accounts
from ..services.digest import effective_interval
from ..services.errors import ServiceError
from ..services.maps import sync_all
from ..services.quarantine import list_sender, self_service_release


def context(user, limited):
    data = {f: getattr(user, f) for f in accounts.SCORE_FIELDS}
    data["digest_interval"] = user.digest_interval or ""
    form = MailboxSettingsForm(prefix="settings", data=data)
    default_interval = effective_interval(user.domain)
    form.digest_interval.choices = ([("", f"Default ({DIGEST_INTERVALS[default_interval].lower()})")]
                                    + list(DIGEST_INTERVALS.items()))
    return {
        "settings_form": form,
        "entry_form": UserListEntryForm(prefix="entry"),
        "defaults": accounts.domain_scores(user.domain),
        "score_range": accounts.USER_SCORE_RANGE if limited else None,
        "mailbox": user,
        "allow_entries": sorted((e for e in user.list_entries if e.list_type == "allow"), key=lambda e: e.value),
        "block_entries": sorted((e for e in user.list_entries if e.list_type == "block"), key=lambda e: e.value),
    }


def _flash_form_errors(form):
    for errors in form.errors.values():
        for error in errors:
            flash(error, "danger")


def save(user, limited):
    form = MailboxSettingsForm(prefix="settings")
    form.digest_interval.choices = [("", "")] + list(DIGEST_INTERVALS.items())
    if not form.validate_on_submit():
        _flash_form_errors(form)
        return False
    try:
        accounts.update_mailbox_user(user, limited=limited,
                                     digest_interval=form.digest_interval.data or None,
                                     **{f: getattr(form, f).data for f in accounts.SCORE_FIELDS})
    except accounts.AccountError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return False
    db.session.commit()
    flash("Settings saved. New thresholds apply within a minute.", "success")
    return True


def add_entry(user):
    form = UserListEntryForm(prefix="entry")
    if not form.validate_on_submit():
        _flash_form_errors(form)
        return
    try:
        accounts.add_user_list_entry(user, form.list_type.data, form.value.data, form.comment.data)
    except accounts.AccountError as exc:
        db.session.rollback()
        flash(str(exc), "info" if exc.status == 409 else "danger")
        return
    db.session.commit()
    flash(f"{form.value.data} added to the {form.list_type.data} list.", "success")


def delete_entry(user, entry_id):
    try:
        accounts.delete_user_list_entry(user, entry_id)
    except accounts.AccountError:
        return
    db.session.commit()
    flash("Entry removed.", "success")


def personal_list_action(item, act, released_by, show_endpoint, index_endpoint):
    """Release & allow sender / block sender & delete for the recipient's own
    list (portal and digest links). Returns a redirect."""
    try:
        listed = list_sender(item, "allow" if act == "release_allow" else "block", "mailbox")
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return redirect(url_for(show_endpoint, item_id=item.id))
    if act == "block_delete":
        db.session.delete(item)
        db.session.commit()
        sync_all()
        flash(f"{listed} Its mail is no longer delivered to you. Message deleted.", "success")
        return redirect(url_for(index_endpoint))
    item_id = item.id
    error = self_service_release(item, released_by)
    if error:
        db.session.rollback()
        flash(error, "danger")
        return redirect(url_for(show_endpoint, item_id=item_id))
    sync_all()
    flash(f"The message has been delivered to your mailbox. {listed}", "success")
    return redirect(url_for(index_endpoint))
