"""Crassostrea - web UI and internal API.

``create_app("ui")`` is the admin interface (proxied by nginx),
``create_app("internal")`` serves the endpoints used by rspamd. Both run in
separate systemd services (crassostrea-web, crassostrea-web-internal);
only the UI port is proxied by nginx.
"""
import logging

from flask import Flask
from sqlalchemy import event
from werkzeug.middleware.proxy_fix import ProxyFix

from .config import Config
from .extensions import csrf, db, login_manager


def create_app(role="ui", config=None):
    app = Flask(__name__)
    app.config.from_object(Config)
    if config:
        app.config.update(config)
    app.config["ROLE"] = role

    if not app.config.get("SECRET_KEY"):
        raise RuntimeError("WEB_SECRET_KEY is not set")

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

    db.init_app(app)
    if app.config["SQLALCHEMY_DATABASE_URI"].startswith("sqlite"):
        with app.app_context():
            @event.listens_for(db.engine, "connect")
            def _sqlite_fk(dbapi_connection, _record):
                dbapi_connection.execute("PRAGMA foreign_keys=ON")

    from . import cli
    cli.register(app)

    from .views.health import bp as health_bp
    app.register_blueprint(health_bp)

    if role == "internal":
        app.config["MAX_CONTENT_LENGTH"] = app.config["INTERNAL_MAX_CONTENT_LENGTH"]
        from .internal import bp as internal_bp
        app.register_blueprint(internal_bp)
        return app

    # Admin UI behind nginx
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
    login_manager.init_app(app)
    from .services import exploits
    exploits.init_app(app)
    csrf.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message_category = "info"
    login_manager.session_protection = "strong"

    from .auth import bp as auth_bp
    from . import api
    from .views import (apidocs, apikeys, attachments, audit, backups, branding, cluster, cluster_join, content_rules,
                        dashboard, directories, dlp, domains, impersonation, ipconfig, journal, linkprotection, links,
                        lists, logs, maillog, mailboxes, metrics, monitoring, network, outbound, portal, queue,
                        quarantine, ratelimits, reports, settings, tls, token, training, users)
    app.register_blueprint(auth_bp)
    for module in (api, apidocs, apikeys, attachments, audit, backups, branding, cluster, cluster_join, content_rules,
                   dashboard, directories, dlp, domains, impersonation, ipconfig, journal, linkprotection, links, lists,
                   logs, maillog, mailboxes, metrics, monitoring, network, outbound, portal, queue, quarantine,
                   ratelimits, reports, settings, tls, token, training, users):
        app.register_blueprint(module.bp)
    api.json_error_for_api_paths(app)

    from . import template_helpers
    template_helpers.register(app)

    from .services import audit as audit_log
    audit_log.init_app(app)

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "frame-ancestors 'none'; form-action 'self'")
        return response

    return app
