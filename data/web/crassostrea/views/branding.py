"""Public branding assets and the light/dark theme switch.

Used by the login page and the digest token pages as well, so nothing here
requires a login.
"""
from flask import Blueprint, Response, abort, current_app, redirect, request, send_from_directory, url_for

from ..extensions import db
from ..models import BrandAsset
from ..services.branding import THEMES, get_branding, theme_css
from . import safe_next

bp = Blueprint("branding", __name__)

THEME_COOKIE = "sf_theme"
LONG_CACHE = "public, max-age=31536000, immutable"


def _cache_headers(response):
    # Asset URLs carry ?v=<brand_version>, a changed asset gets a new URL
    response.headers["Cache-Control"] = LONG_CACHE if request.args.get("v") else "public, max-age=300"
    return response


def _asset(name):
    asset = db.session.get(BrandAsset, name)
    if asset is None:
        return None
    response = Response(asset.data, mimetype=asset.content_type)
    if asset.content_type == "image/svg+xml":
        # Opened directly, an SVG is a document: never let it run or load anything
        response.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'; sandbox"
    return _cache_headers(response)


@bp.get("/branding/logo")
def logo():
    response = _asset("logo")
    if response is None:
        abort(404)
    return response


@bp.get("/branding/favicon")
def favicon():
    response = _asset("favicon")
    if response is None:
        response = _cache_headers(send_from_directory(current_app.static_folder, "favicon.svg"))
    return response


@bp.get("/branding/theme.css")
def stylesheet():
    response = Response(theme_css(get_branding()["accent"]), mimetype="text/css")
    return _cache_headers(response)


@bp.post("/theme")
def set_theme():
    theme = request.form.get("theme", "")
    if theme not in THEMES:
        abort(400)
    response = redirect(safe_next(request.form.get("next"), url_for("auth.login")))
    response.set_cookie(THEME_COOKIE, theme, max_age=365 * 86400, samesite="Lax",
                        secure=current_app.config["SESSION_COOKIE_SECURE"], httponly=False)
    return response


def current_theme():
    """Theme for the <html data-theme> attribute: cookie, else the branding default."""
    theme = request.cookies.get(THEME_COOKIE)
    if theme not in THEMES:
        theme = get_branding()["theme"]
    return theme if theme in ("light", "dark") else None
