"""Rewritten links of inbound mail (services/links.py): /l/<id>, no login.

The recipient is redirected to the original URL unless it is blocked; then a
warning explains why. GET only: mail scanners prefetch links, and a click
changes nothing but the click log.
"""
import redis
from flask import Blueprint, current_app, redirect, render_template, request

from ..models import get_setting
from ..services import links

bp = Blueprint("links", __name__, url_prefix="/l")


@bp.get("/<link_id>")
def follow(link_id):
    try:
        url = links.lookup(link_id)
        if url is None:
            return render_template("links/unknown.html"), 404
        verdict = links.check(url)
        links.record_click(link_id, url, verdict, request.remote_addr or "")
    except redis.RedisError as exc:
        current_app.logger.warning("link %s could not be checked: %s", link_id, exc)
        return render_template("links/unavailable.html"), 503
    if verdict["blocked"]:
        current_app.logger.info("link %s to %s blocked: %s", link_id, verdict["host"], verdict["reason"])
        return render_template("links/blocked.html", url=url, verdict=verdict,
                               allow_continue=bool(get_setting("link_protection_allow_continue")))
    response = redirect(url, 302)
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Cache-Control"] = "no-store"
    return response
