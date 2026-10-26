"""Swagger UI for the REST API (administrators only, no external assets)."""
import swagger_ui_bundle
from flask import abort, render_template, send_from_directory

from . import protected_blueprint

bp = protected_blueprint("apidocs", __name__, url_prefix="/api/docs")

ASSETS = {"swagger-ui.css", "swagger-ui-bundle.js", "favicon-32x32.png"}


@bp.get("/")
def index():
    response = render_template("apidocs.html")
    # Swagger UI sets inline styles from JavaScript
    return response, 200, {"Content-Security-Policy": (
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; connect-src 'self'; frame-ancestors 'none'; form-action 'self'")}


@bp.get("/assets/<path:filename>")
def asset(filename):
    if filename not in ASSETS:
        abort(404)
    return send_from_directory(swagger_ui_bundle.swagger_ui_path, filename, max_age=86400)
