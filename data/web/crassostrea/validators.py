"""Input normalisation for everything that ends up in Postfix/Rspamd maps.

Values are strictly validated because they are written into lookup tables
and the Rspamd settings map.
"""
import ipaddress
import re

_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^(?:{_LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})$")
_HOST_RE = re.compile(rf"^(?:{_LABEL}\.)*{_LABEL}$")
_LOCAL_RE = re.compile(r"^[a-z0-9!#$%&'*+/=?^_`{|}~.-]{1,64}$")
# Sender patterns may contain "*" as wildcard; characters that have a
# meaning in rspamd regexp maps or UCL are not allowed.
_PATTERN_LOCAL_RE = re.compile(r"^[a-z0-9._%+=*-]{1,64}$")
_PATTERN_DOMAIN_RE = re.compile(r"^[a-z0-9.*-]{1,253}$")


class ValidationError(ValueError):
    pass


def normalize_domain(value):
    domain = (value or "").strip().lower().rstrip(".")
    if len(domain) > 253 or not _DOMAIN_RE.match(domain):
        raise ValidationError(f"'{value}' is not a valid domain name")
    return domain


def normalize_host(value):
    """Downstream server: hostname or IP address (without brackets)."""
    host = (value or "").strip().lower().strip("[]").rstrip(".")
    if host.startswith("ipv6:"):
        host = host[5:]
    try:
        return str(ipaddress.ip_address(host))
    except ValueError:
        pass
    if len(host) > 253 or not _HOST_RE.match(host):
        raise ValidationError(f"'{value}' is not a valid hostname or IP address")
    return host


def is_ip_address(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def normalize_email(value):
    address = (value or "").strip().lower()
    if address.count("@") != 1:
        raise ValidationError(f"'{value}' is not a valid e-mail address")
    local, domain = address.split("@")
    if not _LOCAL_RE.match(local) or local.startswith(".") or local.endswith("."):
        raise ValidationError(f"'{value}' is not a valid e-mail address")
    return f"{local}@{normalize_domain(domain)}"


def normalize_sender_pattern(value):
    """Normalise a sender allow/block entry.

    Accepted forms: ``user@example.com``, ``*@example.com``, ``@example.com``
    and ``example.com`` (both meaning the whole domain), ``*@*.example.com``.
    """
    pattern = (value or "").strip().lower()
    if not pattern:
        raise ValidationError("Sender pattern must not be empty")
    if pattern.startswith("@"):
        pattern = "*" + pattern
    elif "@" not in pattern:
        pattern = "*@" + pattern
    if pattern.count("@") != 1:
        raise ValidationError(f"'{value}' is not a valid sender pattern")
    local, domain = pattern.split("@")
    if not _PATTERN_LOCAL_RE.match(local) or not _PATTERN_DOMAIN_RE.match(domain):
        raise ValidationError(f"'{value}' contains invalid characters")
    if domain.replace("*", "").strip(".") == "":
        raise ValidationError(f"'{value}' would match every domain")
    if "*" not in domain:
        normalize_domain(domain)
    return pattern


def sender_pattern_to_regex(pattern):
    """Convert a normalised sender pattern into an rspamd regexp map entry."""
    out = []
    for char in pattern:
        if char == "*":
            out.append(".*")
        elif char in ".+=%":
            out.append("\\" + char)
        else:
            out.append(char)
    return "/^" + "".join(out) + "$/i"


def normalize_network(value):
    """IP address or network in CIDR notation."""
    try:
        network = ipaddress.ip_network((value or "").strip(), strict=False)
    except ValueError:
        raise ValidationError(f"'{value}' is not a valid IP address or network")
    return str(network)
