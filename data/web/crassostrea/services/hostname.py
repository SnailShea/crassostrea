"""Changing the gateway's hostname from the web UI (single gateway).

The web UI cannot reconfigure the system: it writes the requested name to
HOSTNAME_REQUEST (/var/lib/crassostrea/web/hostname), and
crassostrea-hostname.path starts system/libexec/set-hostname as root, which
checks the name again, updates crassostrea.conf and Postfix, restarts the
services that read the name (this one included) and requests a certificate.
"""
import re

from flask import current_app

from . import netcheck
from .errors import ServiceError
from .maps import _write_if_changed

# The rule of setup.sh and set-hostname
HOSTNAME_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")


def current():
    return current_app.config["HOSTNAME"]


def in_cluster():
    return bool(current_app.config["CLUSTER_NODES"])


def pending():
    """The requested name while set-hostname has not applied it yet, or None."""
    try:
        with open(current_app.config["HOSTNAME_REQUEST"], encoding="utf-8") as handle:
            return handle.read().strip() or None
    except OSError:
        return None


def normalize(name):
    name = (name if isinstance(name, str) else "").strip().lower()
    if len(name) > 253 or not HOSTNAME_RE.match(name):
        raise ServiceError("Enter a fully qualified host name, e.g. mx.example.com (no trailing dot)", "hostname")
    return name


def dns_warnings(name):
    """Why mail or the certificate would not work with the name yet (not an error:
    the records may still be propagating)."""
    try:
        found = netcheck.addresses(name)
    except netcheck.LookupFailed as exc:
        return [f"{name} could not be looked up ({exc})."]
    if not found:
        return [f"{name} does not resolve yet. Let's Encrypt can only issue its certificate once its A/AAAA "
                "record points to this server; until then the current certificate stays."]
    foreign = [a for a in found if not netcheck.is_local(a)]
    if foreign:
        return [f"{name} resolves to {', '.join(foreign)}, which is not an address of this server "
                "(fine if a firewall forwards it here)."]
    return []


def request_change(name):
    """Ask set-hostname to switch to ``name``. Returns DNS warnings."""
    if in_cluster():
        raise ServiceError("This gateway is a cluster member: its hostname identifies it to the other members "
                           "and cannot be changed here. To rename a member, replace it (system/cluster.sh leave, "
                           "members and bundle, then setup.sh --join).", "hostname", 409)
    name = normalize(name)
    if name == current() and pending() is None:
        raise ServiceError(f"The hostname already is {name}", "hostname")
    path = current_app.config["HOSTNAME_REQUEST"]
    try:
        _write_if_changed(path, name + "\n")
    except OSError as exc:
        raise ServiceError(f"Cannot request the change ({exc}); is crassostrea-hostname.path installed?",
                           "hostname", 503) from exc
    current_app.logger.info("hostname change to %s requested", name)
    return dns_warnings(name)
