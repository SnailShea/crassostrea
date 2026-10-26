"""Settings of crassostrea.conf the web UI shows. The file is readable by the
crassostrea group, so a change made by a root service shows without
restarting the web UI (its environment has the values of its start)."""
from flask import current_app


def read(keys):
    """{key: value} of the given keys found in crassostrea.conf (quotes removed)."""
    values = {}
    try:
        with open(current_app.config["CONF_FILE"], encoding="utf-8") as handle:
            for line in handle:
                key, sep, value = line.strip().partition("=")
                if sep and key in keys:
                    values[key] = value.strip().strip("\"'")
    except OSError:
        pass
    return values


def enabled(value, default=True):
    """IPV4_ENABLED/IPV6_ENABLED style switches: on unless set to a no value."""
    if value is None or value == "":
        return default
    return value.strip().lower() not in ("n", "no", "false", "0", "off")
