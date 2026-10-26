import redis
from flask import flash, redirect, render_template, url_for

from ..extensions import db
from ..forms import AttachmentPolicyForm, HashCheckForm, HashLookupForm
from ..models import SETTING_DEFAULTS
from ..services import filters, hashcheck
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint

bp = protected_blueprint("attachments", __name__, url_prefix="/attachments")

HASH_FIELDS = ("hashcheck_mhr", "hashcheck_mhr_percent", "hashcheck_mhr_score", "hashcheck_mb_score",
               "hashcheck_vt_engines", "hashcheck_vt_score", "hashcheck_vt_per_minute")


def _render(form=None, hash_form=None, check_form=None, result=None, code=200):
    settings = filters.get_settings()
    if form is None:
        form = AttachmentPolicyForm(formdata=None, data={key: settings[key] for key in filters.ATTACHMENT_SETTINGS})
        form.attachment_blocked_extensions.data = " ".join(settings["attachment_blocked_extensions"].split())
    if hash_form is None:
        hash_form = HashLookupForm(formdata=None, prefix="hash", data={key: settings[key] for key in HASH_FIELDS})
    try:
        hits, hits_error = hashcheck.hits(), None
    except redis.RedisError as exc:
        hits, hits_error = [], f"Valkey cannot be reached ({exc})"
    return render_template("attachments.html", form=form, hash_form=hash_form,
                           check_form=check_form or HashCheckForm(formdata=None, prefix="check"), result=result,
                           settings=settings, hits=hits, hits_error=hits_error, sources=hashcheck.SOURCES,
                           defaults=SETTING_DEFAULTS["attachment_blocked_extensions"].split()), code


def _field_error(form, exc):
    db.session.rollback()
    field = getattr(form, exc.field or "", None)
    if field is not None:
        field.errors = [*field.errors, str(exc)]
    else:
        flash(str(exc), "danger")


def _saved(message):
    db.session.commit()
    if not sync_all():
        flash("Saved, but the filter maps could not be written. See the web UI log (journalctl -u crassostrea-web).",
              "warning")
    flash(message, "success")


@bp.get("/")
def index():
    return _render()


@bp.post("/")
def save():
    form = AttachmentPolicyForm()
    if not form.validate_on_submit():
        return _render(form, code=400)
    try:
        filters.update_settings(
            attachment_blocked_extensions=form.attachment_blocked_extensions.data or "",
            attachment_scan_archives=form.attachment_scan_archives.data,
            attachment_block_encrypted=form.attachment_block_encrypted.data,
            attachment_outbound=form.attachment_outbound.data,
            attachment_exempt_senders=form.attachment_exempt_senders.data or "")
    except ServiceError as exc:
        _field_error(form, exc)
        return _render(form, code=400)
    _saved("Attachment policy saved. Rspamd applies it within a minute.")
    return redirect(url_for("attachments.index"))


@bp.post("/hashes")
def save_hashes():
    form = HashLookupForm(prefix="hash")
    if not form.validate_on_submit():
        return _render(hash_form=form, code=400)
    changes = {key: getattr(form, key).data for key in HASH_FIELDS}
    # an empty key field keeps the stored key
    for key, remove in (("hashcheck_mb_key", form.hashcheck_mb_remove.data),
                        ("hashcheck_vt_key", form.hashcheck_vt_remove.data)):
        if remove:
            changes[key] = ""
        elif getattr(form, key).data:
            changes[key] = getattr(form, key).data
    try:
        filters.update_settings(**changes)
    except ServiceError as exc:
        _field_error(form, exc)
        return _render(hash_form=form, code=400)
    _saved("Hash lookups saved. Rspamd applies them within a minute.")
    return redirect(url_for("attachments.index") + "#hashes")


@bp.post("/hashes/check")
def check_hash():
    form = HashCheckForm(prefix="check")
    if not form.validate_on_submit():
        return _render(check_form=form, code=400)
    try:
        result = hashcheck.check(form.hash.data)
    except ServiceError as exc:
        form.hash.errors = [str(exc)]
        return _render(check_form=form, code=400)
    return _render(check_form=form, result=result)
