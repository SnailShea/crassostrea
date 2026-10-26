from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import has_request_context, request, url_for
from flask_login import current_user

from .models import get_setting
from .services.branding import THEMES, get_branding
from .services.symbols import explain as explain_symbol
from .navigation import for_user as navigation
from .services.cluster import duration
from .views.branding import THEME_COOKIE, current_theme


def zone():
    """The time zone times are shown in (Settings -> time zone; UTC without)."""
    try:
        name = get_setting("timezone")
        return ZoneInfo(name) if name else timezone.utc
    except (ZoneInfoNotFoundError, ValueError, RuntimeError):
        return timezone.utc


def _local(value):
    """A stored time (naive UTC, aware, or a Unix timestamp) in the time zone."""
    if isinstance(value, (int, float)):
        value = datetime.fromtimestamp(value, tz=timezone.utc)
    elif value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(zone())


def _datetime(value):
    if value is None or value == "":
        return "–"
    value = _local(value)
    return value.strftime("%Y-%m-%d %H:%M:%S ") + (value.tzname() or "UTC")


def _localtime(value, fmt):
    return "–" if value is None or value == "" else _local(value).strftime(fmt)


def _filesize(value):
    value = float(value or 0)
    for unit in ("B", "KiB", "MiB", "GiB"):
        if value < 1024 or unit == "GiB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GiB"


def _action_class(action):
    return {
        "reject": "bad",
        "soft reject": "warn",
        "add header": "warn",
        "rewrite subject": "warn",
        "greylist": "info",
        "no action": "good",
    }.get((action or "").lower(), "muted")


def _url_with(**changes):
    args = request.args.to_dict()
    args.update({k: v for k, v in changes.items() if v is not None})
    for key, value in changes.items():
        if value is None:
            args.pop(key, None)
    return url_for(request.endpoint, **(request.view_args or {}), **args)


def _problems():
    """Failing monitoring checks for the sidebar of full administrators:
    {label: message} (base.html reads it once a page)."""
    if not has_request_context() or not getattr(current_user, "is_full_admin", False):
        return {}
    from .services import monitoring
    return {monitoring.label(name): message for name, message in sorted(monitoring.problems().items())}


def register(app):
    app.jinja_env.filters["datetime"] = _datetime
    app.jinja_env.filters["localtime"] = _localtime
    app.jinja_env.filters["explain_symbol"] = explain_symbol
    app.jinja_env.filters["filesize"] = _filesize
    app.jinja_env.filters["duration"] = lambda value: "–" if value is None else duration(value)
    app.jinja_env.filters["action_class"] = _action_class
    app.jinja_env.globals["url_with"] = _url_with
    app.jinja_env.globals["navigation"] = navigation
    app.jinja_env.globals["problems"] = _problems

    @app.context_processor
    def inject():
        if not has_request_context():  # e-mails rendered by CLI commands
            return {"hostname": app.config["HOSTNAME"], "brand": get_branding()}
        brand = get_branding()
        chosen = request.cookies.get(THEME_COOKIE)
        return {
            "hostname": app.config["HOSTNAME"],
            "brand": brand,
            "theme": current_theme(),
            "theme_choice": chosen if chosen in THEMES else brand["theme"],
            "themes": THEMES,
        }
