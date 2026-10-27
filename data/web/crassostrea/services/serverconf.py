"""Settings of the web UI that services outside it apply. The web UI runs
unprivileged, so it hands them over (``sync``, part of maps.sync_all, on
every cluster node):

- files below /var/lib/crassostrea/web, applied by root services started by
  path units, which check the values again: the web server's settings
  (WEB_ACCESS_REQUEST, system/libexec/nginx-apply) and the Spamhaus DQS key
  (SPAMHAUS_REQUEST, system/libexec/spamhaus-apply). system/configure.sh
  reads the same files;
- values in Valkey for logship (POSTFIX_LOG_LINES) and the watchdog's
  notices (WATCHDOG_NOTIFY, read at every notice).
"""
import re

from flask import current_app

from ..models import get_setting
from . import store

WATCHDOG_KEY = "WATCHDOG_NOTIFY"
LOG_LINES_KEY = "POSTFIX_LOG_LINES"
DQS_KEY_RE = re.compile(r"^[A-Za-z0-9]{1,64}$")


def build_web_access():
    """key=value lines for nginx-apply; networks separated by spaces."""
    def networks(key):
        return " ".join(get_setting(key).split())
    return (f"http_redirect={get_setting('http_redirect')}\n"
            f"rspamd_ui_networks={networks('rspamd_ui_networks')}\n"
            f"trusted_proxies={networks('trusted_proxies')}\n")


def build_spamhaus():
    key = get_setting("spamhaus_dqs_key")
    return (key if DQS_KEY_RE.match(key) else "") + "\n"


def runtime_values():
    """{Valkey key: value or mapping} for logship and the watchdog."""
    return {
        LOG_LINES_KEY: str(get_setting("postfix_log_lines")),
        WATCHDOG_KEY: {
            "email": ",".join(get_setting("watchdog_notify_email").split()),
            "webhook": get_setting("watchdog_notify_webhook"),
            "webhook_body": get_setting("watchdog_notify_webhook_body"),
            "subject": get_setting("watchdog_subject"),
            "notify_start": "y" if get_setting("watchdog_notify_start") else "n",
            "notify_ban": "y" if get_setting("watchdog_notify_ban") else "n",
        },
    }


def sync():
    """Write the files and the Valkey values. Returns False on an error
    (logged; the next sync retries)."""
    from .maps import _write_if_changed
    app = current_app
    ok = True
    for name, key, content in (("web server settings", "WEB_ACCESS_REQUEST", build_web_access()),
                               ("Spamhaus DQS key", "SPAMHAUS_REQUEST", build_spamhaus())):
        try:
            if _write_if_changed(app.config[key], content):
                app.logger.info("updated the %s", name)
        except OSError as exc:
            ok = False
            app.logger.error("cannot write the %s to %s: %s", name, app.config[key], exc)
    try:
        pipe = store.get_redis().pipeline()
        for key, value in runtime_values().items():
            if isinstance(value, dict):
                pipe.delete(key)
                pipe.hset(key, mapping=value)
            else:
                pipe.set(key, value)
        pipe.execute()
    except Exception as exc:  # redis errors must not block the other maps
        ok = False
        app.logger.error("cannot update the logship and watchdog settings in redis: %s", exc)
    return ok
