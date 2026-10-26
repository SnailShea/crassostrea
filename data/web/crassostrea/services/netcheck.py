"""DNS records and ports the gateway needs, checked from the gateway itself
(page "DNS & ports").

Lookups go to the system resolver (the local unbound with MANAGE_RESOLVER=y),
port checks are plain TCP connects. Whether the internet reaches the
gateway cannot be told from inside: a port that accepts connections here may
still be blocked by a firewall in front of the server.

``settings()`` collects what the checks need from the configuration and the
database (in the request), ``run()`` performs them in worker threads.
"""
import ipaddress
import re
import socket
from concurrent.futures import ThreadPoolExecutor

import dns.exception
import dns.resolver
import dns.reversename
from flask import current_app

from ..models import Domain, RelayNetwork
from . import dkim

OK, WARN, ERROR, INFO = "ok", "warn", "error", "info"
DNS_TIMEOUT = 4
CONNECT_TIMEOUT = 4
# RFC 7208 4.6.4: DNS lookups an SPF evaluation may cause
SPF_LOOKUP_LIMIT = 10
# a, a:domain, a/24, a:domain/24//64 (and the same for mx)
SPF_HOST_MECHANISM = re.compile(r"^(a|mx)(?::([^/]+))?(?:/(\d+))?(?://(\d+))?$", re.IGNORECASE)
# Cluster ports that always listen; Galera's 4568 (IST) and 4444 (SST) only
# listen during a state transfer. The witness runs garbd and Sentinel.
CLUSTER_NODE_PORTS = ((4567, "Galera replication"), (6380, "Valkey replication (TLS)"),
                      (26379, "Valkey Sentinel"))
CLUSTER_WITNESS_PORTS = ((4567, "Galera arbitrator"), (26379, "Valkey Sentinel"))
LETS_ENCRYPT_API = ("acme-v02.api.letsencrypt.org", 443)
# Route lookups for the source address of outgoing connections (documentation
# addresses: nothing is sent)
ROUTE_PROBES = (("192.0.2.1", socket.AF_INET), ("2001:db8::1", socket.AF_INET6))


class NoRecords(Exception):
    """The name does not exist or has no records of the type."""


class LookupFailed(Exception):
    """The resolver gave no answer (timeout, SERVFAIL, ...)."""


def check(record, rtype, expected, found, status, message):
    return {"record": record, "type": rtype, "expected": expected, "found": found, "status": status,
            "message": message}


# ---------------------------------------------------------------------------
# Network primitives (replaced in the tests)
# ---------------------------------------------------------------------------

def lookup(name, rdtype):
    """Records of a name: addresses and names as strings, MX as (preference,
    host), CAA as (tag, value), TXT as the joined strings."""
    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT
    try:
        answer = resolver.resolve(name, rdtype, search=False)
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        raise NoRecords(name) from None
    except dns.exception.DNSException as exc:
        raise LookupFailed(f"{name} {rdtype}: {exc}") from exc
    records = []
    for rdata in answer:
        if rdtype == "MX":
            records.append((rdata.preference, _name(rdata.exchange.to_text())))
        elif rdtype == "CAA":
            records.append((rdata.tag.decode().lower(), rdata.value.decode(errors="replace")))
        elif rdtype == "TXT":
            records.append(b"".join(rdata.strings).decode(errors="replace"))
        elif rdtype == "PTR":
            records.append(_name(rdata.target.to_text()))
        else:
            records.append(rdata.to_text())
    return records


def connect(host, port):
    """(connected, detail) for a TCP connection to host:port."""
    try:
        with socket.create_connection((host, port), timeout=CONNECT_TIMEOUT) as sock:
            peer = sock.getpeername()[0]
    except OSError as exc:
        return False, str(exc) or exc.__class__.__name__
    return True, peer


def is_local(address):
    """Whether the address belongs to this server (a socket can be bound to it)."""
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.bind((address, 0))
    except OSError:
        return False
    return True


def source_addresses():
    """Addresses this server sends from to the internet (default routes)."""
    found = []
    for probe, family in ROUTE_PROBES:
        try:
            with socket.socket(family, socket.SOCK_DGRAM) as sock:
                sock.connect((probe, 9))
                found.append(sock.getsockname()[0])
        except OSError:
            pass
    return found


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _name(text):
    return text.rstrip(".").lower()


def _is_public(address):
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def addresses(name):
    """A and AAAA records of a name ([] if it has none)."""
    found, failures = [], []
    for rdtype in ("A", "AAAA"):
        try:
            found += lookup(name, rdtype)
        except NoRecords:
            pass
        except LookupFailed as exc:
            failures.append(exc)
    if failures and not found:
        raise failures[0]
    return found


def _short(value, limit=90):
    return value if len(value) <= limit else value[:limit - 1] + "…"


# ---------------------------------------------------------------------------
# Settings
# ---------------------------------------------------------------------------

def settings():
    """What the checks need, read in the request (app context)."""
    cfg = current_app.config
    domains = []
    for domain in Domain.query.filter_by(active=True).order_by(Domain.name):
        domains.append({
            "name": domain.name,
            "destination": (domain.destination_host, domain.destination_port, domain.use_mx),
            "dkim": dkim.dns_record(domain.dkim_key) if domain.dkim_key else None,
        })
    hostname = cfg["HOSTNAME"].lower()
    lets_encrypt = cfg["LETS_ENCRYPT"]
    # the cluster's membership (it can change while this process runs)
    from . import cluster
    members = cluster.nodes() if cfg["CLUSTER_NODES"] else []
    peers = [(name, address, CLUSTER_NODE_PORTS) for name, address in members]
    if members and cluster.witness():
        peers.append((*cluster.witness(), CLUSTER_WITNESS_PORTS))
    return {
        "hostname": hostname,
        # MX records may name any member of a cluster
        "gateway_names": {hostname} | {name for name, _ in members},
        "vip": cfg["CLUSTER_VIP"],
        "cluster_peers": [peer for peer in peers if peer[0] != hostname],
        "domains": domains,
        # Relay networks: the gateway sends the domains' outgoing mail
        "sends_outbound": RelayNetwork.query.count() > 0,
        "lets_encrypt": lets_encrypt,
        "http_01": lets_encrypt and not cfg["ACME_DNS_CHALLENGE"],
        "ports": {"smtp": 25, "http": cfg["HTTP_PORT"], "https": cfg["HTTPS_PORT"]},
        "binds": {"http": cfg["HTTP_BIND"], "https": cfg["HTTPS_BIND"]},
    }


# ---------------------------------------------------------------------------
# Gateway hostname
# ---------------------------------------------------------------------------

def check_host(hostname, found, error, vip, sources):
    expected = ", ".join(a for a in sources if _is_public(a)) or "an address of this server"
    if error:
        return check(hostname, "A/AAAA", expected, [], ERROR, f"Lookup failed: {error}")
    if not found:
        return check(hostname, "A/AAAA", expected, [], ERROR,
                     "No A or AAAA record. The MX records of the domains name this host, and Let's Encrypt "
                     "validates it.")
    foreign = [a for a in found if a != vip and not is_local(a)]
    if foreign:
        return check(hostname, "A/AAAA", expected, found, WARN,
                     f"{', '.join(foreign)} is not an address of this server. Fine if a firewall forwards it "
                     "here (NAT), otherwise mail for the domains goes elsewhere.")
    return check(hostname, "A/AAAA", expected, found, OK, "Points to this server.")


def check_ptr(address, hostname, host_addresses):
    record = dns.reversename.from_address(address).to_text(omit_final_dot=True)
    try:
        names = lookup(record, "PTR")
    except NoRecords:
        return check(record, "PTR", hostname, [], WARN,
                     f"No reverse DNS for {address}. Receiving servers reject or penalize mail from addresses "
                     "without one; the provider of the address sets it.")
    except LookupFailed as exc:
        return check(record, "PTR", hostname, [], WARN, f"Lookup failed: {exc}")
    if hostname not in names:
        return check(record, "PTR", hostname, names, WARN,
                     f"{address} does not point back to {hostname}. Receiving servers compare the two; "
                     "the provider of the address sets it.")
    if address not in host_addresses:
        return check(record, "PTR", hostname, names, WARN,
                     f"{hostname} does not resolve to {address}, so the reverse DNS is not confirmed.")
    return check(record, "PTR", hostname, names, OK, "Matches the hostname in both directions.")


def check_caa(hostname):
    """CAA records that apply to the hostname: those of the closest name that
    has any (RFC 8659 tree climbing)."""
    labels = hostname.split(".")
    for i in range(len(labels) - 1):
        name = ".".join(labels[i:])
        try:
            records = lookup(name, "CAA")
        except NoRecords:
            continue
        except LookupFailed as exc:
            return check(name, "CAA", "allows letsencrypt.org", [], WARN, f"Lookup failed: {exc}")
        found = [f'{tag} "{value}"' for tag, value in records]
        issuers = [value.split(";")[0].strip().lower() for tag, value in records if tag == "issue"]
        if not issuers or "letsencrypt.org" in issuers:
            return check(name, "CAA", "allows letsencrypt.org", found, OK, "Let's Encrypt may issue certificates.")
        return check(name, "CAA", "allows letsencrypt.org", found, ERROR,
                     "Let's Encrypt is not allowed to issue certificates for this name: add "
                     '0 issue "letsencrypt.org".')
    return check(hostname, "CAA", "allows letsencrypt.org", [], OK,
                 "No CAA records: every certificate authority may issue certificates.")


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

def _points_here(host, gateway_names, own_addresses):
    if host in gateway_names:
        return True
    try:
        return any(a in own_addresses or is_local(a) for a in addresses(host))
    except LookupFailed:
        return False


def check_mx(domain, hostname, gateway_names, own_addresses):
    expected = f"10 {hostname}"
    try:
        records = sorted(lookup(domain, "MX"))
    except NoRecords:
        return check(domain, "MX", expected, [], ERROR,
                     "No MX record: senders deliver to the domain's own address instead of the gateway.")
    except LookupFailed as exc:
        return check(domain, "MX", expected, [], WARN, f"Lookup failed: {exc}")
    found = [f"{preference} {host or '.'}" for preference, host in records]
    if records == [(0, "")]:
        return check(domain, "MX", expected, found, ERROR, "Null MX: the domain accepts no mail at all.")
    here = [(pref, host) for pref, host in records if _points_here(host, gateway_names, own_addresses)]
    others = [(pref, host) for pref, host in records if (pref, host) not in here]
    if not here:
        return check(domain, "MX", expected, found, ERROR, "No MX host is this gateway: mail bypasses the filter.")
    if others:
        names = ", ".join(host for _, host in others)
        if min(pref for pref, _ in others) < min(pref for pref, _ in here):
            return check(domain, "MX", expected, found, ERROR,
                         f"{names} has a higher priority (lower number) than the gateway: most mail bypasses "
                         "the filter.")
        return check(domain, "MX", expected, found, WARN,
                     f"{names} also accepts mail for the domain, without filtering. Spammers deliver to such "
                     "backup MX hosts to bypass the filter.")
    return check(domain, "MX", expected, found, OK, "Mail for the domain goes to the gateway.")


def _txt(name, tag):
    """TXT records of a name that start with a version tag (v=spf1, v=DMARC1)."""
    tag = tag.lower()
    return [t for t in lookup(name, "TXT") if t.lower().startswith(tag) and t[len(tag):len(tag) + 1] in ("", " ", ";")]


class SpfUnsupported(Exception):
    """Macros and other constructs this evaluator does not implement."""


class _SpfPermError(Exception):
    pass


def spf_evaluate(address, domain):
    """SPF result (pass, fail, softfail, neutral, none, permerror) of the domain
    for a sender address. Raises SpfUnsupported for macros, LookupFailed when
    the resolver gives no answer (temperror)."""
    counter = [0]
    try:
        return _spf(ipaddress.ip_address(address), domain, counter)
    except _SpfPermError as exc:
        return f"permerror ({exc})"


def _spf_count(counter):
    """Mechanisms and modifiers that cause DNS lookups (a, mx, include,
    exists, redirect) count towards the limit."""
    counter[0] += 1
    if counter[0] > SPF_LOOKUP_LIMIT:
        raise _SpfPermError(f"more than {SPF_LOOKUP_LIMIT} DNS lookups")


def _spf_lookup(name, rdtype):
    try:
        return lookup(name, rdtype)
    except NoRecords:
        return []


def _spf_addresses(ip, name):
    return [ipaddress.ip_address(a) for a in _spf_lookup(name, "AAAA" if ip.version == 6 else "A")]


def _in_network(ip, address, cidr4, cidr6):
    prefix = cidr6 if ip.version == 6 else cidr4
    return address.version == ip.version and ip in ipaddress.ip_network(f"{address}/{prefix}", strict=False)


def _spf(ip, domain, counter):
    try:
        records = _txt(domain, "v=spf1")
    except NoRecords:
        records = []
    if not records:
        return "none"
    if len(records) > 1:
        raise _SpfPermError(f"{len(records)} SPF records for {domain}")
    redirect = None
    for term in records[0].split()[1:]:
        if "%" in term:
            raise SpfUnsupported(f"macro in {term}")
        lowered = term.lower()
        if lowered.startswith("redirect="):
            redirect = term.split("=", 1)[1]
            continue
        if "=" in lowered.split(":")[0]:
            continue  # exp= and unknown modifiers
        qualifier = term[0] if term[0] in "+-~?" else "+"
        mechanism = term[1:] if term[0] in "+-~?" else term
        if _spf_matches(ip, domain, mechanism, counter):
            return {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}[qualifier]
    if redirect:
        _spf_count(counter)
        result = _spf(ip, redirect, counter)
        if result == "none":
            raise _SpfPermError(f"redirect to {redirect}, which has no SPF record")
        return result
    return "neutral"


def _spf_matches(ip, domain, mechanism, counter):
    host_mechanism = SPF_HOST_MECHANISM.match(mechanism)
    if host_mechanism:
        name, target, cidr4, cidr6 = host_mechanism.groups()
        target, cidr4, cidr6 = target or domain, int(cidr4 or 32), int(cidr6 or 128)
        _spf_count(counter)
        if name.lower() == "a":
            return any(_in_network(ip, a, cidr4, cidr6) for a in _spf_addresses(ip, target))
        # the addresses of at most 10 MX hosts are looked up (RFC 7208 4.6.4)
        hosts = [host for _, host in _spf_lookup(target, "MX")]
        return any(_in_network(ip, a, cidr4, cidr6) for host in hosts[:10] for a in _spf_addresses(ip, host))
    name, _, argument = mechanism.partition(":")
    name = name.lower()
    if name == "all":
        return True
    if name in ("ip4", "ip6"):
        try:
            network = ipaddress.ip_network(argument, strict=False)
        except ValueError:
            raise _SpfPermError(f"invalid {mechanism}") from None
        return network.version == ip.version and ip in network
    if name == "include":
        _spf_count(counter)
        result = _spf(ip, argument, counter)
        if result == "none":
            raise _SpfPermError(f"include:{argument} has no SPF record")
        return result == "pass"
    if name == "exists":
        _spf_count(counter)
        return bool(_spf_lookup(argument, "A"))
    if name == "ptr":
        return False  # deprecated (RFC 7208 5.5), receivers rarely evaluate it
    raise _SpfPermError(f"unknown mechanism {mechanism}")


def check_spf(domain, senders):
    expected = "authorizes this server"
    if senders:
        expected = " ".join(["v=spf1"] + [f"ip{ipaddress.ip_address(a).version}:{a}" for a in senders] + ["~all"])
    try:
        records = _txt(domain, "v=spf1")
    except NoRecords:
        records = []
    except LookupFailed as exc:
        return check(domain, "TXT (SPF)", expected, [], WARN, f"Lookup failed: {exc}")
    if not records:
        return check(domain, "TXT (SPF)", expected, [], WARN,
                     "No SPF record: receivers cannot tell that this gateway may send the domain's mail.")
    if len(records) > 1:
        return check(domain, "TXT (SPF)", expected, records, ERROR,
                     f"{len(records)} SPF records: receivers treat this as an error. Merge them into one.")
    if not senders:
        return check(domain, "TXT (SPF)", expected, records, INFO,
                     "This server has no public address to evaluate the record for.")
    results = {}
    for address in senders:
        try:
            results[address] = spf_evaluate(address, domain)
        except (SpfUnsupported, LookupFailed) as exc:
            return check(domain, "TXT (SPF)", expected, records, WARN, f"Could not evaluate the record: {exc}")
    failing = {a: r for a, r in results.items() if r != "pass"}
    if not failing:
        return check(domain, "TXT (SPF)", expected, records, OK, f"Authorizes {', '.join(senders)}.")
    detail = ", ".join(f"{a}: {r}" for a, r in failing.items())
    status = ERROR if any(r == "fail" or r.startswith("permerror") for r in failing.values()) else WARN
    return check(domain, "TXT (SPF)", expected, records, status,
                 f"Does not authorize this server ({detail}): add it, e.g. as ip4:/ip6: or with a:{domain}.")


def _dkim_key(value):
    for tag in value.split(";"):
        key, _, data = tag.strip().partition("=")
        if key.strip() == "p":
            return "".join(data.split())
    return None


def check_dkim(record):
    name = record["name"]
    expected = _short(record["value"])
    try:
        found = lookup(name, "TXT")
    except NoRecords:
        return check(name, "TXT (DKIM)", expected, [], ERROR,
                     "Not published: signatures of this gateway fail verification. The record is on the "
                     "domain's page.")
    except LookupFailed as exc:
        return check(name, "TXT (DKIM)", expected, [], WARN, f"Lookup failed: {exc}")
    wanted = _dkim_key(record["value"])
    shown = [_short(value) for value in found]
    if any(_dkim_key(value) == wanted for value in found):
        return check(name, "TXT (DKIM)", expected, shown, OK, "Matches the signing key.")
    return check(name, "TXT (DKIM)", expected, shown, ERROR,
                 "The published key is not the gateway's signing key: signatures fail verification. "
                 "Publish the record from the domain's page.")


def check_dmarc(domain):
    name = f"_dmarc.{domain}"
    expected = "v=DMARC1; p=quarantine (or reject)"
    try:
        records = _txt(name, "v=DMARC1")
    except NoRecords:
        records = []
    except LookupFailed as exc:
        return check(name, "TXT (DMARC)", expected, [], WARN, f"Lookup failed: {exc}")
    if not records:
        return check(name, "TXT (DMARC)", expected, [], WARN,
                     "No DMARC policy: receivers decide themselves what to do with mail that fails SPF and DKIM.")
    if len(records) > 1:
        return check(name, "TXT (DMARC)", expected, records, ERROR,
                     f"{len(records)} DMARC records: receivers ignore all of them.")
    tags = {k.strip().lower(): v.strip() for k, _, v in (t.partition("=") for t in records[0].split(";"))}
    policy = tags.get("p", "")
    if policy.lower() not in ("none", "quarantine", "reject"):
        return check(name, "TXT (DMARC)", expected, records, ERROR, "The record has no valid policy (p=).")
    if policy.lower() == "none":
        return check(name, "TXT (DMARC)", expected, records, INFO, "Policy p=none: monitoring only.")
    return check(name, "TXT (DMARC)", expected, records, OK, f"Policy p={policy}.")


# ---------------------------------------------------------------------------
# Ports
# ---------------------------------------------------------------------------

def check_listening(port, purpose, required, targets):
    for target in targets:
        connected, detail = connect(target, port)
        if not connected:
            status = ERROR if required else WARN
            return {"port": f"{port}/tcp", "purpose": purpose, "target": target, "status": status,
                    "message": f"No connection to {target}: {detail}."}
    return {"port": f"{port}/tcp", "purpose": purpose, "target": ", ".join(targets), "status": OK,
            "message": "Accepts connections here."}


def check_downstream(host, port, use_mx, domains):
    purpose = f"Delivery to the mail server of {', '.join(domains)}"
    target = f"{host}:{port}" + (" (MX)" if use_mx else "")
    hosts = [host]
    if use_mx:
        try:
            hosts = [name for _, name in sorted(lookup(host, "MX"))]
        except (NoRecords, LookupFailed) as exc:
            return {"port": f"{port}/tcp", "purpose": purpose, "target": target, "status": ERROR,
                    "message": f"MX lookup of {host} failed: {exc}"}
    errors = []
    for name in hosts:
        connected, detail = connect(name, port)
        if connected:
            return {"port": f"{port}/tcp", "purpose": purpose, "target": target, "status": OK,
                    "message": f"Connected to {name} ({detail})."}
        errors.append(f"{name}: {detail}")
    return {"port": f"{port}/tcp", "purpose": purpose, "target": target, "status": ERROR,
            "message": "No connection (" + "; ".join(errors) + "). Accepted mail stays in the queue."}


def check_outbound(host, port, purpose):
    connected, detail = connect(host, port)
    return {"port": f"{port}/tcp", "purpose": purpose, "target": f"{host}:{port}", "status": OK if connected else ERROR,
            "message": f"Connected ({detail})." if connected else f"No connection: {detail}."}


def check_peer(name, address, port, purpose):
    connected, detail = connect(address, port)
    return {"port": f"{port}/tcp", "purpose": purpose, "target": f"{name} ({address})",
            "status": OK if connected else ERROR,
            "message": "Connected." if connected else f"No connection: {detail}."}


# ---------------------------------------------------------------------------
# All checks
# ---------------------------------------------------------------------------

def run(s):
    hostname = s["hostname"]
    resolver_error = None
    try:
        host_addresses = addresses(hostname)
    except LookupFailed as exc:
        host_addresses, resolver_error = [], str(exc)
    sources = source_addresses()
    own = set(host_addresses) | set(sources) | ({s["vip"]} if s["vip"] else set())
    # Receiving servers see the public source address of the server, or
    # behind NAT presumably the one the hostname points to
    senders = [a for a in sources if _is_public(a)] or [a for a in host_addresses if _is_public(a)]
    local_targets = [a for a in host_addresses if is_local(a)] or sources or ["127.0.0.1"]
    ports, binds = s["ports"], s["binds"]

    with ThreadPoolExecutor(max_workers=16) as pool:
        gateway = [pool.submit(check_host, hostname, host_addresses, resolver_error, s["vip"], sources)]
        for address in sorted({a for a in host_addresses + sources if _is_public(a)}):
            gateway.append(pool.submit(check_ptr, address, hostname, host_addresses))
        if s["lets_encrypt"]:
            gateway.append(pool.submit(check_caa, hostname))

        domains = []
        for domain in s["domains"]:
            checks = [pool.submit(check_mx, domain["name"], hostname, s["gateway_names"], own)]
            if s["sends_outbound"]:
                checks.append(pool.submit(check_spf, domain["name"], senders))
            if domain["dkim"]:
                checks.append(pool.submit(check_dkim, domain["dkim"]))
            if s["sends_outbound"]:
                checks.append(pool.submit(check_dmarc, domain["name"]))
            domains.append((domain["name"], checks))

        http_purpose = "HTTP: Let's Encrypt validation, redirect to HTTPS" if s["http_01"] else "HTTP: redirect to HTTPS"
        inbound = [
            pool.submit(check_listening, ports["smtp"], "SMTP: mail from the internet (MX)", True, local_targets),
            pool.submit(check_listening, ports["http"], http_purpose, s["http_01"],
                        [binds["http"]] if binds["http"] else local_targets),
            pool.submit(check_listening, ports["https"], "HTTPS: web UI, links in quarantine digests", True,
                        [binds["https"]] if binds["https"] else local_targets),
        ]

        downstream = {}
        for domain in s["domains"]:
            downstream.setdefault(domain["destination"], []).append(domain["name"])
        outbound = [pool.submit(check_downstream, host, port, use_mx, names)
                    for (host, port, use_mx), names in sorted(downstream.items())]
        if s["lets_encrypt"]:
            outbound.append(pool.submit(check_outbound, *LETS_ENCRYPT_API, "HTTPS: Let's Encrypt (certificates)"))
        cluster = [pool.submit(check_peer, name, address, port, purpose)
                   for name, address, peer_ports in s["cluster_peers"] for port, purpose in peer_ports]

        outbound_rows = [{"port": "53/udp+tcp", "purpose": "DNS: lookups, blocklists", "target": "system resolver",
                          "status": ERROR if resolver_error else OK,
                          "message": f"No answer: {resolver_error}" if resolver_error else "Answers."}]
        outbound_rows += [f.result() for f in outbound]
        if s["sends_outbound"]:
            outbound_rows.append({"port": "25/tcp", "purpose": "SMTP: outgoing mail of the relay networks",
                                  "target": "mail servers on the internet", "status": INFO,
                                  "message": "Not tested (it would contact third-party servers). Many providers "
                                             "block it; ask yours if outgoing mail stays deferred."})
        return {
            "hostname": hostname,
            "gateway": [f.result() for f in gateway],
            "domains": [(name, [f.result() for f in checks]) for name, checks in domains],
            "inbound": [f.result() for f in inbound],
            "outbound": outbound_rows,
            "cluster": [f.result() for f in cluster],
            "sends_outbound": s["sends_outbound"],
        }


def summary(results):
    """Number of checks per status."""
    rows = results["gateway"] + [c for _, checks in results["domains"] for c in checks]
    rows += results["inbound"] + results["outbound"] + results["cluster"]
    counts = {OK: 0, WARN: 0, ERROR: 0, INFO: 0}
    for row in rows:
        counts[row["status"]] += 1
    return counts
