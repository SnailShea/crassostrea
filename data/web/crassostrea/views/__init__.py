from urllib.parse import urlsplit

from flask import Blueprint, Response, abort, make_response, redirect, render_template, request, url_for
from flask_login import current_user

from ..extensions import login_manager
from ..services import html_preview as html_preview_service

# Sent by static/app.js when it only needs the live region of a page
LIVE_HEADER = "X-Live-Fragment"


def protected_blueprint(name, import_name, url_prefix=None, domain_admins=False):
    """Blueprint whose views all require a logged in administrator. With
    ``domain_admins`` domain administrators may use it too: its views limit
    them to their domains (``scope``, ``require_scope``)."""
    bp = Blueprint(name, import_name, url_prefix=url_prefix)

    @bp.before_request
    def require_admin():
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if not current_user.is_admin:
            if request.method == "GET":
                return redirect(url_for("portal.index"))
            abort(403)
        if not domain_admins and not current_user.is_full_admin:
            if request.method == "GET":
                return redirect(url_for("quarantine.index"))
            abort(403)

    return bp


def scope():
    """The domains the administrator may see (a set of names), None: all."""
    return current_user.domain_scope


def in_scope(domain):
    allowed = scope()
    return allowed is None or (domain or "").lower() in allowed


def require_scope(domain):
    """404 for a domain the administrator does not manage (as if it did not exist)."""
    if not in_scope(domain):
        abort(404)


def require_full_admin():
    if not current_user.is_full_admin:
        abort(403)


def mailbox_blueprint(name, import_name, url_prefix=None):
    """Blueprint for mailbox users (self-service quarantine)."""
    bp = Blueprint(name, import_name, url_prefix=url_prefix)

    @bp.before_request
    def require_mailbox_user():
        if not current_user.is_authenticated:
            return login_manager.unauthorized()
        if current_user.is_admin:
            # Administrators manage every quarantine in the admin area
            if request.method == "GET":
                return redirect(url_for("quarantine.index"))
            abort(403)

    return bp


def safe_next(target, default):
    """Only allow redirects to local paths."""
    if not target or not target.startswith("/") or target.startswith("//") or "\\" in target:
        return default
    parts = urlsplit(target)
    if parts.scheme or parts.netloc:
        return default
    return target


def back(endpoint, **values):
    """Redirect target from the submitted 'next' field, falling back to endpoint."""
    return safe_next(request.form.get("next"), url_for(endpoint, **values))


def render_live(template, fragment, **context):
    """Render a page, or only its live region when the page's script asks for
    it (header X-Live-Fragment: 1, see static/app.js): after an in-page form
    submission (the redirect back to the page keeps the header). ``fragment``
    is the template of the region, which the page includes; it shows the
    flashed messages itself in that case.
    """
    if request.headers.get(LIVE_HEADER) == "1":
        response = make_response(render_template(fragment, live_fragment=True, **context))
        response.headers[LIVE_HEADER] = "1"
        response.headers["Cache-Control"] = "no-store"
    else:
        response = make_response(render_template(template, **context))
    response.vary.add(LIVE_HEADER)
    return response


def html_preview(raw):
    """The HTML view of a stored message: its sanitized HTML body, for the
    sandboxed frame of the message view (services/html_preview.py)."""
    page = html_preview_service.render(raw)
    if page is None:
        abort(404)
    response = Response(page, mimetype="text/html")
    response.headers["Content-Security-Policy"] = html_preview_service.CSP
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["Cache-Control"] = "private, no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response
