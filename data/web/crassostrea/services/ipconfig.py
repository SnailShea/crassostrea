"""IP addressing page: the addresses of the server's network interfaces and
which IP families they use.

The web UI reads the current state from NetworkManager (nmcli, read-only
for every user) and cannot change it: it writes a request for one interface
(IP_REQUEST), and crassostrea-network.path starts system/libexec/network-apply
as root. That checks the request again, applies it, tests that every family
with a gateway reaches the internet and restores the previous settings if
not; the outcome is in IP_STATUS. The rules below match network-apply's.

Either family can be off on any interface as long as one interface keeps one
of them. The gateway's services use a family if any interface has it
(IPV4_ENABLED, IPV6_ENABLED). A cluster member's addresses identify it: not
changed here.
"""
import ipaddress
import json
import os
import subprocess
import time

from flask import current_app

from . import sysconf
from .errors import ServiceError
from .maps import _write_if_changed

FAMILY = {4: "IPv4", 6: "IPv6"}
METHODS = {4: {"manual": "Manual", "auto": "DHCP"}, 6: {"manual": "Manual", "auto": "Automatic (SLAAC/DHCPv6)"}}
# A change that runs longer than this is assumed to have died
STALE_AFTER = 15 * 60


class NetworkStateError(Exception):
    pass


def nmcli(*args):
    """Terse nmcli output as (key, value) pairs; values are not escaped for
    single-value fields, so only the first colon separates."""
    try:
        result = subprocess.run(["nmcli", "-t", *args], capture_output=True, text=True, timeout=10, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetworkStateError(f"Cannot ask NetworkManager: {exc}") from exc
    if result.returncode != 0:
        raise NetworkStateError(f"Cannot ask NetworkManager: {result.stderr.strip() or result.returncode}")
    return [tuple(line.split(":", 1)) for line in result.stdout.splitlines() if ":" in line]


def _list(value):
    return [v.strip() for v in (value or "").split(",") if v.strip()]


# Devices that are no interface of the server (docker0 is a bridge NetworkManager
# does not manage: "connected (externally)")
SKIPPED_TYPES = ("loopback", "bridge", "tun", "wireguard", "dummy", "veth")


def _families(uuid):
    settings = dict(nmcli("-f", "connection.id,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv6.method,"
                                "ipv6.addresses,ipv6.gateway,ipv6.dns", "connection", "show", uuid))
    result = {"name": settings.get("connection.id", "")}
    for version, prefix in ((4, "ipv4"), (6, "ipv6")):
        method = settings.get(f"{prefix}.method", "disabled")
        result[prefix] = {
            "enabled": method not in ("disabled", "ignore"),
            "method": method if method in METHODS[version] else "manual",
            "addresses": _list(settings.get(f"{prefix}.addresses")),
            "gateway": "" if settings.get(f"{prefix}.gateway") in (None, "--") else settings[f"{prefix}.gateway"],
            "dns": _list(settings.get(f"{prefix}.dns")),
        }
    return result


def interfaces():
    """The interfaces NetworkManager manages, those with a default route first:
    [{device, type, uuid, name, live4, live6, gateway4, gateway6, default,
    ipv4, ipv6}]."""
    found = []
    for line in nmcli("-f", "DEVICE,TYPE,STATE,CONNECTION", "device"):
        device = dict(zip(("device", "type", "state", "connection"), (line[0], *line[1].split(":", 2))))
        if device.get("type") in SKIPPED_TYPES or device.get("state") != "connected":
            continue
        # IP4.ADDRESS[1], IP4.ADDRESS[2], ...: several entries per field
        live = nmcli("-f", "GENERAL.CON-UUID,IP4.GATEWAY,IP6.GATEWAY,IP4.ADDRESS,IP6.ADDRESS",
                     "device", "show", device["device"])
        info = dict(live)
        if not info.get("GENERAL.CON-UUID"):
            continue
        entry = {"device": device["device"], "type": device.get("type", ""), "uuid": info["GENERAL.CON-UUID"],
                 "live4": [v for k, v in live if k.startswith("IP4.ADDRESS")],
                 "live6": [v for k, v in live if k.startswith("IP6.ADDRESS")],
                 "gateway4": info.get("IP4.GATEWAY", ""), "gateway6": info.get("IP6.GATEWAY", "")}
        entry["default"] = bool(entry["gateway4"] or entry["gateway6"])
        entry.update(_families(entry["uuid"]))
        found.append(entry)
    if not found:
        raise NetworkStateError("No network interface managed by NetworkManager is connected")
    return sorted(found, key=lambda i: not i["default"])


def current(device=None):
    """One interface (``device``, else the one with the default route) and
    the list of all: its fields, plus interfaces, managed_resolver, cluster."""
    found = interfaces()
    chosen = next((i for i in found if i["device"] == device), None) if device else found[0]
    if chosen is None:
        raise ServiceError(f"There is no interface {device}", "device", status=404)
    conf = sysconf.read(("MANAGE_RESOLVER", "HA_NODES"))
    return {**chosen, "interfaces": found,
            # another interface keeps an address: this one may lose both families
            "others_enabled": any(i["ipv4"]["enabled"] or i["ipv6"]["enabled"]
                                  for i in found if i["device"] != chosen["device"]),
            "managed_resolver": sysconf.enabled(conf.get("MANAGE_RESOLVER")),
            "cluster": bool(conf.get("HA_NODES", "").strip()) or bool(current_app.config["CLUSTER_NODES"])}


# ---------------------------------------------------------------------------
# Validation (as system/libexec/network-apply)
# ---------------------------------------------------------------------------

def _family(data, version):
    name = FAMILY[version]
    enabled = data.get("enabled")
    if not isinstance(enabled, bool):
        raise ServiceError(f"{name}: enabled must be true or false", f"ipv{version}.enabled")
    method = data.get("method", "manual")
    if method not in METHODS[version]:
        raise ServiceError(f"{name}: method must be manual or auto", f"ipv{version}.method")
    result = {"enabled": enabled, "method": method, "addresses": [], "gateway": "", "dns": []}
    if not enabled:
        return result
    if method == "manual":
        raw = data.get("addresses")
        if not isinstance(raw, list) or not 1 <= len(raw) <= 16:
            raise ServiceError(f"{name}: give 1 to 16 addresses with prefix length, e.g. "
                               f"{'192.0.2.10/24' if version == 4 else '2001:db8::10/64'}", f"ipv{version}.addresses")
        networks = []
        for item in raw:
            try:
                interface = ipaddress.ip_interface(item)
            except (TypeError, ValueError):
                interface = None
            if interface is None or interface.version != version or "/" not in str(item):
                raise ServiceError(f"{name}: {item} is not an {name} address with prefix length",
                                   f"ipv{version}.addresses")
            ip = interface.ip
            if ip.is_loopback or ip.is_multicast or ip.is_unspecified or ip.is_link_local or ip.is_reserved:
                raise ServiceError(f"{name}: {ip} cannot be the interface's address", f"ipv{version}.addresses")
            if version == 4 and interface.network.prefixlen < 32 and ip in (interface.network.network_address,
                                                                             interface.network.broadcast_address):
                raise ServiceError(f"{name}: {interface} is the network or broadcast address",
                                   f"ipv{version}.addresses")
            result["addresses"].append(str(interface))
            networks.append(interface)
        raw_gateway = (data.get("gateway") or "").strip()
        if raw_gateway:
            try:
                gateway = ipaddress.ip_address(raw_gateway)
            except ValueError:
                raise ServiceError(f"{name}: the gateway {raw_gateway} is not an address",
                                   f"ipv{version}.gateway") from None
            if gateway.version != version:
                raise ServiceError(f"{name}: the gateway is not an {name} address", f"ipv{version}.gateway")
            if not any(gateway in n.network for n in networks) and not (version == 6 and gateway.is_link_local):
                raise ServiceError(f"{name}: the gateway {gateway} is not in the network of an address",
                                   f"ipv{version}.gateway")
            if any(gateway == n.ip for n in networks):
                raise ServiceError(f"{name}: the gateway cannot be the server's own address", f"ipv{version}.gateway")
            # none: an internal network; network-apply's test reverts a change
            # that leaves no way to the internet
            result["gateway"] = str(gateway)
    raw_dns = data.get("dns") or []
    if not isinstance(raw_dns, list) or len(raw_dns) > 3:
        raise ServiceError(f"{name}: at most 3 DNS servers", f"ipv{version}.dns")
    for item in raw_dns:
        try:
            server = ipaddress.ip_address(item)
        except (TypeError, ValueError):
            raise ServiceError(f"{name}: the DNS server {item} is not an address", f"ipv{version}.dns") from None
        if server.version != version:
            raise ServiceError(f"{name}: the DNS server {server} is not an {name} address", f"ipv{version}.dns")
        result["dns"].append(str(server))
    return result


def validate(data, others_enabled=False):
    """{"ipv4": {...}, "ipv6": {...}} of one interface as network-apply
    expects them; ``others_enabled``: another interface keeps a family."""
    if not isinstance(data, dict):
        raise ServiceError("The settings must be an object")
    families = {}
    for version in (4, 6):
        family = data.get(f"ipv{version}")
        if not isinstance(family, dict):
            raise ServiceError(f"ipv{version} is required", f"ipv{version}")
        families[f"ipv{version}"] = _family(family, version)
    if not families["ipv4"]["enabled"] and not families["ipv6"]["enabled"] and not others_enabled:
        raise ServiceError("IPv4 and IPv6 cannot both be off: no other interface has an address, the server would be "
                           "unreachable.", "ipv4.enabled")
    return families


# ---------------------------------------------------------------------------
# Status and the request
# ---------------------------------------------------------------------------

def status():
    """The outcome of the last change, or None."""
    try:
        with open(current_app.config["IP_STATUS"], encoding="utf-8") as handle:
            entry = json.load(handle).get("change")
    except (OSError, ValueError, AttributeError):
        return None
    if not isinstance(entry, dict):
        return None
    if entry.get("state") == "running" and time.time() - entry.get("at", 0) > STALE_AFTER:
        entry["state"] = "stale"
    # a failed change was either refused (nothing changed) or tested and reverted
    entry["outcome"] = {"ok": "applied", "running": "testing", "stale": "stopped"}.get(
        entry.get("state"), "reverted" if str(entry.get("message", "")).startswith("Reverted") else "refused")
    return entry


def busy():
    return os.path.exists(current_app.config["IP_REQUEST"]) or (status() or {}).get("state") == "running"


def request_change(data):
    """Validate and ask network-apply to apply, test and keep (or revert) the
    settings of one interface (``device`` in data, else the one with the
    default route)."""
    device = data.get("device") if isinstance(data, dict) else None
    if device is not None and not isinstance(device, str):
        raise ServiceError("device must be the name of an interface", "device")
    state = current(device or None)
    families = validate(data, others_enabled=state["others_enabled"])
    if state["cluster"]:
        raise ServiceError("This gateway is a cluster member: its addresses identify it to the other members.",
                           status=409)
    if busy():
        raise ServiceError("An IP change is still being applied and tested; wait for its result.", status=409)
    request = {"connection": state["uuid"], "device": state["device"], **families}
    try:
        _write_if_changed(current_app.config["IP_REQUEST"], json.dumps(request))
    except OSError as exc:
        raise ServiceError(f"Cannot request the change ({exc}); is crassostrea-network.path installed?",
                           status=503) from exc
    current_app.logger.info("IP change requested for %s: %s", state["device"], json.dumps(families))
    return {"device": state["device"], **families}
