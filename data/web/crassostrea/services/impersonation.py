"""Impersonation checks of inbound mail, scored by rspamd
(data/conf/rspamd/lua/rspamd.local.lua, impersonation.json):

* IMPERSONATION_NAME: the From display name is a protected person's
  (Impersonation page) but the address is outside the protected domains and
  none of theirs.
* LOOKALIKE_DOMAIN: the From domain imitates a protected domain (the active
  domains and impersonation_extra_domains): the same name under another
  suffix, look-alike characters (rn for m, 0 for o, Cyrillic letters), one
  or two typing errors, the name joined with others by hyphens
  (example-secure.com), or the protected domain in front of another one.
* SPOOFED_OWN_DOMAIN: the From domain is a protected domain, the message
  does not come from a relay network and neither DMARC, DKIM nor SPF pass
  for it. Rspamd's DMARC check already punishes domains with p=quarantine or
  p=reject; this also covers p=none and no DMARC record.

Each adds its score (0: off); with a score at or above the reject threshold
such mail is rejected (and quarantined). The detectors are those of
data/conf/rspamd/lua/impersonation.lua, for the test of the web UI; keep them
alike.
"""
import json
import re
import string

from ..extensions import db
from ..models import Domain, ProtectedPerson, get_setting
from .. import validators as v
from .errors import ServiceError

CONFUSABLES = [("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("i", "l"), ("3", "e"), ("5", "s"),
               ("7", "t"), ("а", "a"), ("е", "e"), ("о", "o"), ("р", "p"), ("с", "c"),
               ("х", "x"), ("у", "y"), ("і", "l"), ("ο", "o"), ("α", "a")]
_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_PUNCT = re.compile("[" + re.escape(string.punctuation) + "\x00-\x1f\x7f]")
MAX_PEOPLE = 1000


# ---------------------------------------------------------------------------
# Detectors
# ---------------------------------------------------------------------------

def normalize_name(value):
    return " ".join(_PUNCT.sub(" ", (value or "").translate(_LOWER)).split())


def name_matches(display, name):
    wanted = normalize_name(name)
    if not wanted:
        return False
    if f" {wanted} " in f" {normalize_name(display)} ":
        return True
    match = re.match(r"^\s*([^,]+),\s*(.+)$", display or "", re.S)
    return bool(match) and f" {wanted} " in f" {normalize_name(match.group(2) + ' ' + match.group(1))} "


def core(domain):
    labels = [label for label in (domain or "").translate(_LOWER).rstrip(".").split(".") if label]
    if len(labels) >= 3 and len(labels[-1]) == 2 and len(labels[-2]) <= 3:
        return labels[-3]
    return labels[-2] if len(labels) >= 2 else (labels[0] if labels else "")


def skeleton(value):
    value = (value or "").translate(_LOWER)
    for old, new in CONFUSABLES:
        value = value.replace(old, new)
    return value


def distance(a, b):
    a, b = a.encode(), b.encode()
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def _own(domain, protected):
    return domain == protected or domain.endswith("." + protected)


def lookalike(domain, protected_domains, exempt=()):
    domain = (domain or "").translate(_LOWER).rstrip(".")
    if not domain or domain in exempt or any(_own(domain, p) for p in protected_domains):
        return None
    mine = core(domain)
    mine_skeleton = skeleton(mine)
    for protected in protected_domains:
        if domain.startswith(protected + ".") or f".{protected}." in domain:
            return protected
        theirs = core(protected)
        theirs_skeleton = skeleton(theirs)
        if len(theirs.encode()) < 3:
            continue
        if mine == theirs or mine_skeleton == theirs_skeleton:
            return protected
        # bigbank-secure.com
        if len(theirs.encode()) >= 4 and "-" in mine and any(
                token == theirs or skeleton(token) == theirs_skeleton for token in mine.split("-") if token):
            return protected
        size = len(theirs.encode())
        limit = 2 if size >= 9 else 1 if size >= 5 else 0
        if limit and abs(len(mine_skeleton.encode()) - len(theirs_skeleton.encode())) <= limit \
                and distance(mine_skeleton, theirs_skeleton) <= limit:
            return protected
    return None


# ---------------------------------------------------------------------------
# Protected people and the map
# ---------------------------------------------------------------------------

def _addresses(value):
    if not isinstance(value, (str, list)):
        raise ServiceError("addresses must be text, one address per line", "addresses")
    items = value if isinstance(value, list) else re.split(r"[\s,;]+", value)
    found = set()
    for item in items:
        if not isinstance(item, str):
            raise ServiceError("addresses must be text", "addresses")
        if item.strip():
            try:
                found.add(v.normalize_email(item))
            except v.ValidationError as exc:
                raise ServiceError(str(exc), "addresses") from None
    return "\n".join(sorted(found))


def _name(value, person=None):
    value = " ".join((value if isinstance(value, str) else "").split())
    if not 3 <= len(value) <= 128 or len(normalize_name(value)) < 3:
        raise ServiceError("Enter the person's name as it appears in mail, e.g. Jane Doe", "name")
    other = next((p for p in ProtectedPerson.query.all() if normalize_name(p.name) == normalize_name(value)), None)
    if other and other is not person:
        raise ServiceError(f"{other.name} is already protected", "name", 409)
    return value


def add_person(name, addresses=""):
    if ProtectedPerson.query.count() >= MAX_PEOPLE:
        raise ServiceError(f"At most {MAX_PEOPLE} people", "name")
    person = ProtectedPerson(name=_name(name), addresses=_addresses(addresses))
    db.session.add(person)
    return person


def update_person(person, **changes):
    unknown = sorted(set(changes) - {"name", "addresses"})
    if unknown:
        raise ServiceError(f"Unknown field {unknown[0]}", unknown[0])
    if "name" in changes:
        person.name = _name(changes["name"], person)
    if "addresses" in changes:
        person.addresses = _addresses(changes["addresses"])
    return person


def delete_person(person):
    db.session.delete(person)


def people():
    return ProtectedPerson.query.order_by(ProtectedPerson.name).all()


def protected_domains():
    names = {d.name for d in Domain.query.filter_by(active=True)}
    names |= set(get_setting("impersonation_extra_domains").split())
    return sorted(names)


def build_json():
    """impersonation.json for rspamd."""
    return json.dumps({
        "people": [{"name": p.name, "addresses": p.addresses.split()} for p in people()],
        "domains": protected_domains(),
        "exempt": get_setting("impersonation_exempt_domains").split(),
        "scores": {"name": get_setting("impersonation_name_score"),
                   "lookalike": get_setting("impersonation_lookalike_score"),
                   "spoof": get_setting("impersonation_spoof_score")},
    }, indent=1) + "\n"


def test(display_name, address):
    """Which of the name and look-alike checks a From header would trigger:
    {"name": person or None, "lookalike": protected domain or None,
    "own_domain": bool (then the spoofing check decides)}."""
    try:
        address = v.normalize_email(address)
    except v.ValidationError as exc:
        raise ServiceError(str(exc), "address") from None
    domain = address.rsplit("@", 1)[1]
    domains = protected_domains()
    own = any(_own(domain, p) for p in domains)
    person = None
    if not own:
        person = next((p for p in people() if name_matches(display_name, p.name)
                       and address not in p.addresses.split()), None)
    return {"name": person, "own_domain": own,
            "lookalike": lookalike(domain, domains, set(get_setting("impersonation_exempt_domains").split()))}
