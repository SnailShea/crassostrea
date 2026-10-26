"""DKIM keys for outbound mail.

Normal outbound mail is signed by rspamd (local.d/dkim_signing.conf), which
reads the keys from redis. Released outbound quarantine mail is re-injected
on a Postfix listener without milter, so it is signed here with the same key
and the same header list.
"""
import base64
import re
from email.parser import BytesHeaderParser
from email.utils import getaddresses

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from ..extensions import db
from ..models import DkimKey, Domain

KEY_SIZES = (2048, 4096)
SELECTOR_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

# Redis hashes read by rspamd (key_prefix / selector_prefix)
REDIS_KEYS = "DKIM_PRIV_KEYS"
REDIS_SELECTORS = "DKIM_SELECTORS"

# Keep in sync with sign_headers in data/conf/rspamd/local.d/dkim_signing.conf
# (o) = oversign: signed once more than present, so the header cannot be added
# (x) = oversign only if present
SIGN_HEADERS = (
    "(o)from:(x)sender:(o)reply-to:(o)subject:(x)date:(x)message-id:(o)to:(o)cc:(x)mime-version:"
    "(x)content-type:(x)content-transfer-encoding:resent-to:resent-cc:resent-from:resent-sender:"
    "resent-message-id:(x)in-reply-to:(x)references:list-id:list-help:list-owner:list-unsubscribe:"
    "list-unsubscribe-post:list-subscribe:list-post:(x)openpgp:(x)autocrypt"
)


class DkimError(ValueError):
    pass


def validate_selector(selector):
    selector = (selector or "").strip().lower()
    if not SELECTOR_RE.match(selector):
        raise DkimError("The selector may only contain letters, digits and hyphens (max. 63 characters)")
    return selector


def generate_private_key(key_size=2048):
    if key_size not in KEY_SIZES:
        raise DkimError(f"Unsupported key size {key_size}")
    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    return _pem(key), key_size


def import_private_key(pem):
    """Validate a pasted RSA private key, returns (PKCS#1 PEM, key size)."""
    try:
        key = serialization.load_pem_private_key((pem or "").strip().encode(), password=None)
    except (ValueError, TypeError) as exc:
        raise DkimError("This is not a valid unencrypted PEM private key") from exc
    if not isinstance(key, rsa.RSAPrivateKey):
        raise DkimError("Only RSA keys are supported")
    if key.key_size < 1024:
        raise DkimError("The key must have at least 1024 bits (2048 recommended)")
    return _pem(key), key.key_size


def _pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption()).decode()


def public_key_b64(private_pem):
    key = serialization.load_pem_private_key(private_pem.encode(), password=None)
    der = key.public_key().public_bytes(serialization.Encoding.DER,
                                        serialization.PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der).decode()


def dns_record(dkim_key):
    """DNS name, TXT value and the value split into 255 byte strings (zone file syntax)."""
    value = f"v=DKIM1; k=rsa; p={public_key_b64(dkim_key.private_key)}"
    chunks = [value[i:i + 255] for i in range(0, len(value), 255)]
    return {
        "name": f"{dkim_key.selector}._domainkey.{dkim_key.domain.name}",
        "value": value,
        "zone": " ".join(f'"{c}"' for c in chunks),
    }


def include_headers(present):
    """Header list (``h=``) for the given header names, applying (o)/(x)."""
    counts = {}
    for name in present:
        counts[name.lower()] = counts.get(name.lower(), 0) + 1
    result = []
    for spec in SIGN_HEADERS.split(":"):
        mode, name = (spec[1], spec[3:]) if spec.startswith("(") else ("", spec)
        count = counts.get(name, 0)
        if mode == "o":
            count += 1
        elif mode == "x" and count:
            count += 1
        result.extend([name.encode()] * count)
    return result


def _line_ending(raw):
    index = raw.find(b"\n")
    return b"\r\n" if index > 0 and raw[index - 1:index] == b"\r" else b"\n"


def header_from_domain(raw):
    """Domain of the single From header address, or None."""
    headers = BytesHeaderParser().parsebytes(raw)
    values = headers.get_all("From") or []
    if len(values) != 1:
        return None
    addresses = [addr for _, addr in getaddresses([str(values[0])]) if addr]
    if len(addresses) != 1 or "@" not in addresses[0]:
        return None
    return addresses[0].rsplit("@", 1)[1].lower()


def sign_outbound(raw):
    """Sign ``raw`` with the key of its From domain.

    Returns (message, signing domain or None). Messages of domains without
    key or with an ambiguous From header are returned unchanged.
    """
    domain = header_from_domain(raw)
    if domain is None:
        return raw, None
    key = (DkimKey.query.join(Domain)
           .filter(Domain.name == domain, Domain.active.is_(True)).first())
    if key is None:
        return raw, None
    present = BytesHeaderParser().parsebytes(raw).keys()
    signature = dkim.sign(raw, key.selector.encode(), domain.encode(), key.private_key.encode(),
                          include_headers=include_headers(present),
                          canonicalize=(b"relaxed", b"relaxed"), linesep=_line_ending(raw))
    return signature + raw, domain


def redis_state():
    """{field: value} for both rspamd hashes, from the database."""
    keys, selectors = {}, {}
    rows = (db.session.query(DkimKey, Domain).join(Domain)
            .filter(Domain.active.is_(True)).all())
    for key, domain in rows:
        keys[f"{key.selector}.{domain.name}"] = key.private_key
        selectors[domain.name] = key.selector
    return {REDIS_KEYS: keys, REDIS_SELECTORS: selectors}


def sync_redis(r):
    """Make the rspamd hashes match the database without an empty window."""
    for hash_name, wanted in redis_state().items():
        stale = set(r.hkeys(hash_name)) - set(wanted)
        if wanted:
            r.hset(hash_name, mapping=wanted)
        if stale:
            r.hdel(hash_name, *stale)
