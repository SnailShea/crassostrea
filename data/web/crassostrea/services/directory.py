"""Valid recipients from a directory: LDAP (Active Directory, OpenLDAP) or
Microsoft 365 (Microsoft Graph).

A domain with recipient_check "directory" accepts the addresses of its
recipient list, like "list"; the rows with source "directory" are added and
removed by ``sync`` (crassostrea-job-directories.timer every 15 minutes, or
Synchronise on the Directories page), manual rows stay. Postfix keeps
reading the database, so the directory being down never rejects mail, and
a cluster gets the list by database replication. A synchronisation that
finds no address at all, or would remove more than half of a domain's
directory recipients, is refused (it is more likely a broken filter or
permission than real) unless forced.

LDAP: every address in the attributes (default: mail and proxyAddresses,
where only smtp: entries count) of the entries matching the filter below the
base DN, read with a paged search. Microsoft 365: mail and the smtp:
proxyAddresses of every user and group, read with an app registration's
client credentials (application permissions User.Read.All and
Group.Read.All, with admin consent).
"""
import re
import ssl

import requests
from ldap3 import ANONYMOUS, FIRST, SIMPLE, SUBTREE, Connection, Server, ServerPool, Tls
from ldap3.core.exceptions import LDAPException
from ldap3.utils.config import set_config_parameter

from ..extensions import db
from ..models import DIRECTORY_KINDS as KINDS, Directory, Recipient, utcnow
from .. import validators as v
from .errors import ServiceError

AD_FILTER = "(|(mail=*)(proxyAddresses=*))"
AD_ATTRIBUTES = "mail proxyAddresses"
GRAPH = "https://graph.microsoft.com/v1.0"
LOGIN = "https://login.microsoftonline.com"
TIMEOUT = 30
PAGE_SIZE = 500
MAX_ADDRESSES = 1_000_000
SECRETS = ("bind_password", "client_secret")
FIELDS = ("name", "kind", "ldap_urls", "ldap_starttls", "ldap_verify", "bind_dn", "bind_password", "base_dn",
          "ldap_filter", "ldap_attributes", "tenant_id", "client_id", "client_secret")
# A domain with at least this many directory recipients is protected from
# losing more than half of them at once
GUARD_MIN = 4

_URL_RE = re.compile(r"^ldaps?://(\[[0-9a-fA-F:.]+\]|[A-Za-z0-9.-]+)(:\d{1,5})?/?$")
_ATTRIBUTE_RE = re.compile(r"^[A-Za-z][A-Za-z0-9-]*$")
_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$")

# ldap3 waits this long after every server of the pool failed before it gives
# up (default 10 s)
set_config_parameter("POOLING_LOOP_TIMEOUT", 2)


class DirectoryError(Exception):
    """The directory could not be read, or the result looks wrong."""


# ---------------------------------------------------------------------------
# Directories
# ---------------------------------------------------------------------------

def _text(data, key, limit, required=False, label=None):
    value = data.get(key, "")
    value = "" if value is None else value
    if not isinstance(value, str) or len(value.strip()) > limit:
        raise ServiceError(f"{label or key} must be text of at most {limit} characters", key)
    value = value.strip()
    if required and not value:
        raise ServiceError(f"{label or key} is required", key)
    return value


def _flag(data, key):
    if not isinstance(data[key], bool):
        raise ServiceError(f"{key} must be true or false", key)
    return data[key]


def _filter(value):
    value = value or AD_FILTER
    depth = 0
    for char in value:
        depth += {"(": 1, ")": -1}.get(char, 0)
        if depth < 0:
            break
    if not (value.startswith("(") and value.endswith(")")) or depth != 0:
        raise ServiceError("The filter must be an LDAP filter in parentheses, e.g. " + AD_FILTER, "ldap_filter")
    return value


def _apply(directory, data):
    unknown = sorted(set(data) - set(FIELDS))
    if unknown:
        raise ServiceError(f"Unknown field {unknown[0]}", unknown[0])
    if "name" in data:
        name = _text(data, "name", 64, True, "The name")
        other = Directory.query.filter_by(name=name).first()
        if other and other is not directory:
            raise ServiceError(f"There already is a directory {name}", "name", 409)
        directory.name = name
    if "kind" in data:
        if data["kind"] not in KINDS:
            raise ServiceError(f"kind must be one of {', '.join(KINDS)}", "kind")
        directory.kind = data["kind"]
    for key, limit in (("bind_dn", 500), ("bind_password", 500), ("base_dn", 500), ("client_secret", 500)):
        if key in data:
            setattr(directory, key, _text(data, key, limit))
    for key in ("ldap_starttls", "ldap_verify"):
        if key in data:
            setattr(directory, key, _flag(data, key))
    if "ldap_urls" in data:
        urls = _text(data, "ldap_urls", 1000).split()
        bad = [url for url in urls if not _URL_RE.match(url)]
        if bad:
            raise ServiceError(f"{bad[0]} is not an LDAP URL like ldaps://dc1.example.com", "ldap_urls")
        directory.ldap_urls = " ".join(urls)
    if "ldap_filter" in data:
        directory.ldap_filter = _filter(_text(data, "ldap_filter", 1000))
    if "ldap_attributes" in data:
        names = _text(data, "ldap_attributes", 500).replace(",", " ").split() or AD_ATTRIBUTES.split()
        bad = [name for name in names if not _ATTRIBUTE_RE.match(name)]
        if bad:
            raise ServiceError(f"{bad[0]} is not an attribute name", "ldap_attributes")
        directory.ldap_attributes = " ".join(names)
    if "tenant_id" in data:
        tenant = _text(data, "tenant_id", 253).lower()
        if tenant and not _GUID_RE.match(tenant):
            try:
                tenant = v.normalize_domain(tenant)
            except v.ValidationError:
                raise ServiceError("The tenant is its ID or a domain like example.onmicrosoft.com",
                                   "tenant_id") from None
        directory.tenant_id = tenant
    if "client_id" in data:
        client = _text(data, "client_id", 64).lower()
        if client and not _GUID_RE.match(client):
            raise ServiceError("The application (client) ID is a GUID", "client_id")
        directory.client_id = client
    # what the kind needs
    if directory.kind == "ldap":
        if not directory.ldap_urls:
            raise ServiceError("Enter the URL of at least one LDAP server", "ldap_urls")
        if not directory.base_dn:
            raise ServiceError("Enter the base DN to search, e.g. DC=example,DC=com", "base_dn")
        if directory.ldap_starttls and any(u.startswith("ldaps:") for u in directory.ldap_urls.split()):
            raise ServiceError("STARTTLS is for ldap:// URLs; ldaps:// already uses TLS", "ldap_starttls")
        if directory.bind_dn and not directory.bind_password:
            raise ServiceError("Enter the password of the bind DN", "bind_password")
        directory.ldap_filter = directory.ldap_filter or AD_FILTER
        directory.ldap_attributes = directory.ldap_attributes or AD_ATTRIBUTES
    elif directory.kind == "m365":
        for key, label in (("tenant_id", "the tenant ID or domain"), ("client_id", "the application (client) ID"),
                           ("client_secret", "the client secret")):
            if not getattr(directory, key):
                raise ServiceError(f"Enter {label}", key)
    return directory


def create_directory(**data):
    for key in ("name", "kind"):
        if key not in data:
            raise ServiceError(f"{key} is required", key)
    directory = Directory(ldap_urls="", ldap_starttls=False, ldap_verify=True, bind_dn="", bind_password="",
                          base_dn="", ldap_filter="", ldap_attributes="", tenant_id="", client_id="",
                          client_secret="", sync_error="")
    _apply(directory, data)
    db.session.add(directory)
    return directory


def update_directory(directory, **data):
    return _apply(directory, data)


def delete_directory(directory):
    if directory.domains:
        raise ServiceError(f"{directory.name} is used by {', '.join(d.name for d in directory.domains)}: choose "
                           "another recipient validation for them first", "directory", 409)
    db.session.delete(directory)


def directories():
    return Directory.query.order_by(Directory.name).all()


# ---------------------------------------------------------------------------
# Reading addresses
# ---------------------------------------------------------------------------

def _address(value):
    value = value.strip() if isinstance(value, str) else ""
    if value[:5].lower() == "smtp:":
        value = value[5:]
    elif ":" in value.split("@", 1)[0]:
        # X500:, SIP:, x400: ... of proxyAddresses
        return None
    try:
        return v.normalize_email(value)
    except v.ValidationError:
        return None


def _ldap_connection(directory):
    """A connection to the first of the directory's servers that answers (not
    bound yet)."""
    tls = Tls(validate=ssl.CERT_REQUIRED if directory.ldap_verify else ssl.CERT_NONE)
    servers = [Server(url, use_ssl=url.startswith("ldaps:"), tls=tls, connect_timeout=10)
               for url in directory.ldap_urls.split()]
    return Connection(ServerPool(servers, FIRST, active=1, exhaust=True), user=directory.bind_dn or None,
                      password=directory.bind_password or None,
                      authentication=SIMPLE if directory.bind_dn else ANONYMOUS, read_only=True,
                      receive_timeout=TIMEOUT, raise_exceptions=True)


def _ldap_addresses(directory):
    attributes = directory.ldap_attributes.split() or AD_ATTRIBUTES.split()
    found = set()
    try:
        conn = _ldap_connection(directory)
        if directory.ldap_starttls:
            conn.open()
            conn.start_tls()
        conn.bind()
        try:
            for entry in conn.extend.standard.paged_search(directory.base_dn, directory.ldap_filter or AD_FILTER,
                                                           SUBTREE, attributes=attributes, paged_size=PAGE_SIZE,
                                                           generator=True):
                if entry.get("type") != "searchResEntry":
                    continue
                for name in attributes:
                    values = entry["attributes"].get(name) or []
                    for value in values if isinstance(values, list) else [values]:
                        address = _address(value)
                        if address:
                            found.add(address)
                if len(found) > MAX_ADDRESSES:
                    raise DirectoryError(f"More than {MAX_ADDRESSES} addresses: narrow the base DN or filter")
        finally:
            conn.unbind()
    except LDAPException as exc:
        raise DirectoryError(f"LDAP: {exc}") from exc
    return found


def _session():
    return requests.Session()


def _graph_error(response):
    try:
        body = response.json()
        message = body.get("error_description") or body.get("error", {}).get("message") or response.text
    except ValueError:
        message = response.text
    message = " ".join(str(message).split())[:300]
    if response.status_code == 403:
        message += (" — the app registration needs the application permissions User.Read.All and "
                    "Group.Read.All with admin consent")
    return DirectoryError(f"Microsoft 365: {response.status_code} {message}")


def _graph_addresses(directory):
    session = _session()
    try:
        response = session.post(f"{LOGIN}/{directory.tenant_id}/oauth2/v2.0/token", timeout=TIMEOUT, data={
            "grant_type": "client_credentials", "client_id": directory.client_id,
            "client_secret": directory.client_secret, "scope": "https://graph.microsoft.com/.default"})
        if response.status_code != 200:
            raise _graph_error(response)
        headers = {"Authorization": f"Bearer {response.json()['access_token']}"}
        found = set()
        for collection in ("users", "groups"):
            url = f"{GRAPH}/{collection}?$select=mail,proxyAddresses&$top=999"
            while url:
                response = session.get(url, headers=headers, timeout=TIMEOUT)
                if response.status_code != 200:
                    raise _graph_error(response)
                page = response.json()
                for item in page.get("value", []):
                    for value in [item.get("mail")] + list(item.get("proxyAddresses") or []):
                        address = _address(value)
                        if address:
                            found.add(address)
                if len(found) > MAX_ADDRESSES:
                    raise DirectoryError(f"More than {MAX_ADDRESSES} addresses")
                url = page.get("@odata.nextLink")
    except requests.RequestException as exc:
        raise DirectoryError(f"Microsoft 365: {exc}") from exc
    except (KeyError, ValueError) as exc:
        raise DirectoryError(f"Microsoft 365: unexpected answer ({exc})") from exc
    finally:
        session.close()
    return found


def fetch(directory):
    """Every address the directory has (lower case). Raises DirectoryError."""
    return _graph_addresses(directory) if directory.kind == "m365" else _ldap_addresses(directory)


def _by_domain(addresses, names):
    grouped = {name: set() for name in names}
    for address in addresses:
        domain = address.rsplit("@", 1)[1]
        if domain in grouped:
            grouped[domain].add(address)
    return grouped


def preview(directory):
    """What a synchronisation would find, without changing anything:
    {total, domains: {name: count}, sample: [addresses]}."""
    addresses = fetch(directory)
    names = [d.name for d in directory.domains]
    grouped = _by_domain(addresses, names)
    return {"total": len(addresses), "domains": {name: len(grouped[name]) for name in names},
            "sample": sorted(a for group in grouped.values() for a in group)[:20]}


def _domains(directory):
    return [d for d in directory.domains if d.recipient_check == "directory"]


def sync(directory, force=False):
    """Replace the directory recipients of the domains that use the directory.
    Returns {domain: {added, removed, total}}; records the outcome on the
    directory. Raises DirectoryError (nothing changed). Commits."""
    domains = _domains(directory)
    try:
        addresses = fetch(directory)
        if not addresses:
            raise DirectoryError("The directory returned no addresses: check the base DN, filter and permissions")
        grouped = _by_domain(addresses, [d.name for d in domains])
        plans = []
        for domain in domains:
            rows = {r.address: r for r in domain.recipients}
            current = {a for a, r in rows.items() if r.source == "directory"}
            wanted = grouped[domain.name]
            removed = current - wanted
            if not force and len(current) >= GUARD_MIN and len(removed) > len(current) / 2:
                raise DirectoryError(f"{domain.name} would lose {len(removed)} of its {len(current)} recipients: "
                                     "not synchronised. Check the directory, or synchronise from the "
                                     "Directories page with “remove anyway”.")
            plans.append((domain, rows, wanted, removed))
    except DirectoryError as exc:
        db.session.rollback()
        directory.sync_error = str(exc)
        directory.synced_at = utcnow()
        db.session.commit()
        raise
    results = {}
    for domain, rows, wanted, removed in plans:
        added = 0
        for address in sorted(wanted - set(rows)):
            db.session.add(Recipient(domain=domain, address=address, active=True, source="directory"))
            added += 1
        for address in removed:
            db.session.delete(rows[address])
        results[domain.name] = {"added": added, "removed": len(removed), "total": len(wanted)}
    directory.synced_at, directory.sync_error = utcnow(), ""
    directory.sync_count = sum(len(w) for _, _, w, _ in plans)
    db.session.commit()
    return results


def sync_all():
    """Synchronise every directory used by a domain. Returns {name: result
    or the error}."""
    outcome = {}
    for directory in directories():
        if not _domains(directory):
            continue
        try:
            outcome[directory.name] = sync(directory)
        except DirectoryError as exc:
            outcome[directory.name] = exc
    return outcome
