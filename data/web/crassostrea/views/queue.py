import re

from flask import abort, flash, redirect, render_template, request, url_for

from ..services import postfix_control
from . import protected_blueprint, render_live

bp = protected_blueprint("queue", __name__, url_prefix="/queue")

# Short (hex) and long Postfix queue IDs, checked again by the control service
QUEUE_ID = re.compile(r"^[0-9A-Za-z]{6,32}$")


@bp.get("/")
def index():
    items, error = [], None
    try:
        items = postfix_control.mail_queue()
    except postfix_control.PostfixControlError as exc:
        error = str(exc)
    items.sort(key=lambda i: i.get("arrival_time", 0), reverse=True)
    return render_live("queue/index.html", "queue/_live.html", items=items, error=error)


@bp.get("/<queue_id>")
def show(queue_id):
    if not QUEUE_ID.match(queue_id):
        abort(404)
    try:
        content = postfix_control.queue_message(queue_id)
    except postfix_control.PostfixControlError as exc:
        flash(str(exc), "danger")
        return redirect(url_for("queue.index"))
    return render_template("queue/show.html", queue_id=queue_id, content=content)


@bp.post("/action")
def action():
    task = request.form.get("action")
    ids = [i for i in request.form.getlist("ids") if QUEUE_ID.match(i)]
    labels = {
        "flush": "Queue flushed.",
        "deliver": "Delivery scheduled.",
        "hold": "Messages put on hold.",
        "unhold": "Messages released from hold.",
        "delete": "Messages deleted.",
        "super_delete": "All queued messages deleted.",
    }
    if task not in labels:
        abort(400)
    if task not in ("flush", "super_delete") and not ids:
        flash("No messages selected.", "info")
        return redirect(url_for("queue.index"))
    try:
        postfix_control.queue_action(task, ids)
        flash(labels[task], "success")
    except postfix_control.PostfixControlError as exc:
        flash(str(exc), "danger")
    return redirect(url_for("queue.index"))
