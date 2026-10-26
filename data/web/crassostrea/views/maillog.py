import io

from flask import abort, flash, redirect, render_template, request, send_file, url_for
from flask_login import current_user

from ..extensions import db
from ..models import DIRECTIONS, Domain, MailLogEntry, get_setting
from ..services import deliveries, html_preview as html_preview_service, mailer, maillog
from ..services.errors import ServiceError
from ..services.quarantine import parse_message
from . import html_preview, protected_blueprint, render_live, scope

bp = protected_blueprint("maillog", __name__, url_prefix="/mail-log", domain_admins=True)

PER_PAGE = 50


@bp.get("/")
def index():
    page = request.args.get("page", 1, type=int)
    allowed = scope()
    query = maillog.filtered(request.args.get("direction", ""), request.args.get("action", ""),
                             request.args.get("domain", ""), request.args.get("q", ""), domains=allowed,
                             delivery=request.args.get("delivery", ""))
    pagination = query.paginate(page=page, per_page=PER_PAGE, error_out=False)
    domains = [d.name for d in Domain.query.order_by(Domain.name) if allowed is None or d.name in allowed]
    return render_live("maillog/index.html", "maillog/_live.html", pagination=pagination, domains=domains,
                       directions=DIRECTIONS, actions=maillog.ACTIONS, delivery=deliveries.states(pagination.items),
                       delivery_states=deliveries.STATES,
                       retention_days=get_setting("maillog_retention_days"))


def _get_entry(entry_id):
    entry = db.session.get(MailLogEntry, entry_id)
    if entry is None or not maillog.in_scope(entry, scope()):
        abort(404)
    return entry


@bp.get("/<int:entry_id>")
def show(entry_id):
    entry = _get_entry(entry_id)
    if entry.refused:
        return render_template("maillog/show.html", entry=entry, quarantined=[], html_url=None)
    return render_template("maillog/show.html", entry=entry, quarantined=maillog.quarantined(entry),
                           delivery=deliveries.summary(entry),
                           html_url=url_for("maillog.html", entry_id=entry.id)
                           if html_preview_service.has_html(entry.message) else None,
                           **parse_message(entry.message))


@bp.get("/<int:entry_id>/html")
def html(entry_id):
    entry = _get_entry(entry_id)
    if entry.refused:
        abort(404)
    return html_preview(entry.message)


@bp.get("/<int:entry_id>/raw")
def raw(entry_id):
    entry = _get_entry(entry_id)
    if entry.refused:
        abort(404)
    return send_file(io.BytesIO(entry.message), mimetype="message/rfc822", as_attachment=True,
                     download_name=f"mail-log-{entry.id}.eml")


@bp.post("/<int:entry_id>/requeue")
def requeue(entry_id):
    entry = _get_entry(entry_id)
    rcpts = request.form.getlist("rcpts")
    allowed = scope()
    if allowed is not None and not (entry.direction == "outbound" and entry.sender.rsplit("@", 1)[-1] in allowed):
        # a domain administrator re-delivers to its own recipients only
        chosen = rcpts
        rcpts = [r for r in rcpts if r.rsplit("@", 1)[-1] in allowed]
        if chosen and not rcpts:
            flash("None of the chosen recipients is in your domains.", "danger")
            return redirect(url_for("maillog.show", entry_id=entry_id))
    try:
        notes = maillog.requeue(entry, rcpts, current_user.username,
                                allow_virus=request.form.get("confirm_virus") == "yes")
        db.session.commit()
        flash("Message " + "; ".join(notes) + ".", "success")
    except (ServiceError, mailer.ReleaseError) as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    return redirect(url_for("maillog.show", entry_id=entry_id))
