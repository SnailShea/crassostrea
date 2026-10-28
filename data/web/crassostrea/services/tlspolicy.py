"""The TLS policy lookups of Postfix (smtp_tls_policy_maps: postfix-tlspol,
DANE and MTA-STS).

Postfix asks the policy service before every delivery and defers the mail
("client TLS configuration problem") when the answer is not one it
understands, e.g. attributes of a newer Postfix. ``check`` asks the service
the way Postfix does, for a domain with an MTA-STS policy, and compares the
answer with what the installed Postfix accepts.
"""
import re
import shutil
import socket
import subprocess

from flask import current_app

LEVELS = ("none", "may", "encrypt", "dane", "dane-only", "fingerprint", "verify", "secure")
# Attributes of a policy, by the Postfix version that added them
ATTRIBUTES = (
    ((3, 4), ("ciphers", "exclude", "protocols", "match", "tafile", "connection_reuse", "servername")),
    ((3, 9), ("enable_rpk",)),
    ((3, 10), ("policy_type", "policy_domain", "mx_host_pattern", "policy_string", "policy_failure")),
)
_SOCKETMAP_RE = re.compile(r"^socketmap:inet:(\[[0-9A-Fa-f:.]+\]|[^:\s]+):(\d+):(\S+)$")
_TOKEN_RE = re.compile(r"\{[^}]*\}|\S+")


class PolicyError(Exception):
    pass


def _postconf():
    """(version tuple, version text, [maps]) of the installed Postfix, or
    None without one (a development machine)."""
    command = current_app.config["POSTCONF"]
    if not shutil.which(command):
        return None
    try:
        result = subprocess.run([command, "-hx", "mail_version", "smtp_tls_policy_maps"], capture_output=True,
                                text=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError) as exc:
        raise PolicyError(f"Postfix's configuration cannot be read: {exc}") from exc
    lines = result.stdout.splitlines() + ["", ""]
    version = lines[0].strip()
    numbers = tuple(int(part) for part in re.findall(r"\d+", version)[:2])
    return numbers, version, [m for m in re.split(r"[\s,]+", lines[1]) if m]


def allowed(version):
    """The policy attributes Postfix of this version (major, minor) accepts."""
    return {name for since, names in ATTRIBUTES if version >= since for name in names}


def _netstring(data):
    return f"{len(data)}:".encode() + data + b","


def _read_netstring(sock):
    """The body of one netstring, or None when it is incomplete or invalid."""
    data = b""
    while True:
        length, colon, rest = data.partition(b":")
        if colon:
            if not length.isdigit():
                return None
            if len(rest) > int(length):
                return rest[:int(length)] if rest[int(length):int(length) + 1] == b"," else None
        chunk = sock.recv(65536)
        if not chunk:
            return None
        data += chunk


def lookup(host, port, name, key, timeout=5):
    """The socketmap answer to Postfix's question: (status, value), e.g.
    ("OK", "secure match=..."), ("NOTFOUND", "")."""
    try:
        with socket.create_connection((host.strip("[]"), int(port)), timeout=timeout) as sock:
            sock.sendall(_netstring(f"{name} {key}".encode()))
            body = _read_netstring(sock)
    except OSError as exc:
        raise PolicyError(f"the policy service on {host}:{port} does not answer: {exc}") from exc
    if body is None:
        raise PolicyError(f"the policy service on {host}:{port} sent an invalid answer")
    status, _, value = body.decode("utf-8", "replace").partition(" ")
    return status, value


def attributes(policy):
    """The security level and the attribute names of a policy such as
    'secure match=a:b servername=hostname { policy_string = ... }'."""
    tokens = _TOKEN_RE.findall(policy)
    names = []
    for token in tokens[1:]:
        body = token[1:-1] if token.startswith("{") else token
        names.append(body.split("=", 1)[0].strip())
    return (tokens[0] if tokens else ""), names


def check():
    """{"ok", "message"} for the alert checks, or None without Postfix."""
    domain = current_app.config["TLS_POLICY_CHECK_DOMAIN"]
    try:
        postfix = _postconf()
        if postfix is None:
            return None
        version, version_text, maps = postfix
        services = [m.groups() for m in map(_SOCKETMAP_RE.match, maps) if m]
        if not services:
            return {"ok": True, "message": "Postfix uses no TLS policy service"}
        for host, port, name in services:
            status, value = lookup(host, port, name, domain)
            if status == "NOTFOUND":
                continue
            if status != "OK":
                return {"ok": False, "message": f"The TLS policy lookup of {domain} fails ({status} {value}".strip()
                        + "): Postfix defers mail whose policy it cannot look up"}
            level, names = attributes(value)
            unknown = list(dict.fromkeys(n for n in names if n not in allowed(version)))
            if level not in LEVELS or unknown:
                what = ", ".join(unknown) if unknown else f"level {level}"
                return {"ok": False, "message": f"Postfix {version_text} does not understand the TLS policy the "
                                                f"policy service returns for {domain} ({what}): mail to domains "
                                                "with such a policy is deferred (client TLS configuration problem)"}
            return {"ok": True, "message": f"TLS policies are looked up ({domain}: {level})"}
        return {"ok": True, "message": f"TLS policies are looked up ({domain}: no policy found)"}
    except PolicyError as exc:
        return {"ok": False, "message": f"TLS policies cannot be looked up: {exc}"}
