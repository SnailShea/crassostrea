"""The time zone of the gateway (Settings -> time zone).

The web UI stores times in UTC and shows them in the chosen zone
(template_helpers.py). The servers follow too: ``sync`` (every sync of the
maps, on every cluster node) writes the name to TIMEZONE_REQUEST, and
system/libexec/set-timezone (crassostrea-timezone.path, root) sets it with
timedatectl and restarts the services that read it at start. Its outcome is in
TIMEZONE_STATUS. Empty: the servers keep their zone, the web UI shows UTC.
"""
import json
import os

from flask import current_app

from ..models import get_setting


def system_zone():
    """The zone /etc/localtime points to ("UTC" when it cannot tell)."""
    try:
        target = os.readlink(current_app.config["LOCALTIME"])
    except OSError:
        return "UTC"
    marker = "zoneinfo/"
    return target.split(marker, 1)[1] if marker in target else "UTC"


def status():
    """set-timezone's last outcome: {state, timezone, message, at} or None."""
    try:
        with open(current_app.config["TIMEZONE_STATUS"], encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def sync():
    """Write the chosen zone for set-timezone; returns True when it changed.
    Errors are logged (the other maps do not depend on it)."""
    from .maps import _write_if_changed
    name = get_setting("timezone")
    path = current_app.config["TIMEZONE_REQUEST"]
    try:
        if not name:
            if os.path.exists(path):
                os.unlink(path)
            return False
        if _write_if_changed(path, name + "\n"):
            current_app.logger.info("requested the time zone %s", name)
            return True
    except OSError as exc:
        current_app.logger.error("cannot request the time zone %s: %s", name, exc)
    return False
