"""Networks administrators may use the web UI from (Settings -> General,
admin_allowed_networks; empty: any). auth.py refuses administrator logins
from other addresses and ends administrator sessions that move to one. Mailbox
users and API keys (each with its own allowed networks) are not affected.
``flask admin-networks --clear`` empties the list from the server's shell.
"""
import ipaddress

from ..models import get_setting
from .errors import ServiceError


def networks(value=None):
    value = get_setting("admin_allowed_networks") if value is None else value
    result = []
    for item in (value or "").split():
        try:
            result.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            continue
    return result


def _address(ip):
    try:
        address = ipaddress.ip_address(ip or "")
    except ValueError:
        return None
    return address.ipv4_mapped or address if address.version == 6 else address


def allowed(ip, value=None):
    """Whether an administrator may use the web UI from ``ip``."""
    allowed_networks = networks(value)
    if not allowed_networks:
        return True
    address = _address(ip)
    return address is not None and any(address in network for network in allowed_networks)


def check_own_address(value, ip):
    """An administrator saving the list from an address outside it would be
    logged out at once and could not log in again."""
    if not allowed(ip, value):
        raise ServiceError(f"Your address {ip} is not in the list: saving it would lock you out. Add your "
                           "address or network.", "admin_allowed_networks")
