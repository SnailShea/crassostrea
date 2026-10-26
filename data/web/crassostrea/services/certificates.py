"""Certificates & TLS page: the certificate of HTTPS and SMTP (Let's Encrypt or
uploaded files) and the oldest TLS versions they accept.

The web UI cannot change the system: it writes a request (TLS_REQUEST), and
crassostrea-tls.path starts system/libexec/tls-apply as root, which checks it
again, applies it (crassostrea.conf, nginx, Postfix, acme.sh) and records the
outcome in TLS_STATUS. Uploaded files are checked here first (``validate``)
and staged in TLS_UPLOAD_DIR; tls-apply installs only the staged files whose
SHA-256 the request names. A cluster member has its own certificate and
settings in crassostrea.conf: the page only shows them.
"""
import datetime
import hashlib
import json
import os
import re
import time

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.verification import PolicyBuilder, Store, VerificationError
from flask import current_app

from . import sysconf
from .errors import ServiceError
from .maps import _write_if_changed

HOSTNAME_RE = re.compile(r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$")
MAX_NAMES = 50
# The staging test a production request needs (tls-apply checks it as well)
TEST_MAX_AGE = 86400
# A request that runs longer than this is assumed to have died
STALE_AFTER = 20 * 60
TLS_MINIMUMS = ("1.2", "1.1", "1.0")
MAX_UPLOAD = 256 * 1024
EXPIRY_WARNING_DAYS = 14

CONF_KEYS = ("CRASSOSTREA_HOSTNAME", "SKIP_LETS_ENCRYPT", "ADDITIONAL_SAN", "ONLY_CRASSOSTREA_HOSTNAME",
             "ACME_DNS_CHALLENGE", "HTTPS_TLS_MIN", "SMTP_TLS_MIN", "HA_NODES")


def _yes(value):
    return str(value or "").strip().lower() in ("1", "y", "yes", "true", "on")


def _conf():
    return sysconf.read(CONF_KEYS)


def settings():
    conf = _conf()
    hostname = (conf.get("CRASSOSTREA_HOSTNAME") or current_app.config["HOSTNAME"]).lower()
    extra = [] if _yes(conf.get("ONLY_CRASSOSTREA_HOSTNAME")) else [
        n.strip().lower() for n in conf.get("ADDITIONAL_SAN", "").split(",") if n.strip()]
    skip = _yes(conf["SKIP_LETS_ENCRYPT"]) if "SKIP_LETS_ENCRYPT" in conf else not current_app.config["LETS_ENCRYPT"]
    return {
        "hostname": hostname,
        "mode": "manual" if skip else "letsencrypt",
        "extra_names": [n for n in extra if n != hostname],
        "dns_challenge": _yes(conf.get("ACME_DNS_CHALLENGE")),
        "https_min": conf.get("HTTPS_TLS_MIN") if conf.get("HTTPS_TLS_MIN") in TLS_MINIMUMS else "1.2",
        "smtp_min": conf.get("SMTP_TLS_MIN") if conf.get("SMTP_TLS_MIN") in TLS_MINIMUMS else "1.2",
        "cluster": bool(conf.get("HA_NODES", "").strip()) or bool(current_app.config["CLUSTER_NODES"]),
    }


# ---------------------------------------------------------------------------
# Certificates
# ---------------------------------------------------------------------------

def _now():
    return datetime.datetime.now(datetime.timezone.utc)


def _names(cert):
    try:
        return cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def _common_name(name):
    values = name.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
    return str(values[0].value) if values else name.rfc4514_string()


def _key_description(key):
    if isinstance(key, rsa.RSAPublicKey):
        return f"RSA {key.key_size} bit"
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ECDSA {key.curve.name}"
    return type(key).__name__.replace("PublicKey", "")


def covers(names, hostname):
    """Whether certificate names (with wildcards) include the hostname."""
    for name in names:
        name = name.lower()
        if name == hostname:
            return True
        if name.startswith("*.") and hostname.count(".") >= 2 and hostname.split(".", 1)[1] == name[2:]:
            return True
    return False


def describe(cert, chain_length=1):
    not_after = cert.not_valid_after_utc
    return {
        "subject": _common_name(cert.subject),
        "names": _names(cert),
        "issuer": _common_name(cert.issuer),
        "not_before": cert.not_valid_before_utc,
        "not_after": not_after,
        "days_left": (not_after - _now()).days,
        "key": _key_description(cert.public_key()),
        "self_signed": cert.issuer == cert.subject,
        "chain_length": chain_length,
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(":").upper(),
    }


def current_certificate():
    """The installed certificate (cert.pem: leaf and chain), or None."""
    try:
        with open(current_app.config["SSL_CERT"], "rb") as handle:
            certs = x509.load_pem_x509_certificates(handle.read())
    except (OSError, ValueError):
        return None
    return describe(certs[0], len(certs)) if certs else None


def _trust_store():
    with open(current_app.config["CA_BUNDLE"], "rb") as handle:
        return Store(x509.load_pem_x509_certificates(handle.read()))


def validate(cert_pem, key_pem, chain_pem=b""):
    """Check uploaded files. Returns a report: ``errors`` (the files cannot be
    used), ``warnings`` (they can, but clients may complain), ``info`` and,
    without errors, the normalized ``cert``/``key`` PEM to stage."""
    errors, warnings = [], []
    hostname = settings()["hostname"]
    report = {"errors": errors, "warnings": warnings, "info": None}
    if not cert_pem or not key_pem:
        errors.append("Upload the certificate and its private key.")
        return report
    if max(len(cert_pem), len(key_pem), len(chain_pem or b"")) > MAX_UPLOAD:
        errors.append("The files are too large for certificates.")
        return report
    try:
        certs = x509.load_pem_x509_certificates(cert_pem + b"\n" + (chain_pem or b""))
    except ValueError:
        errors.append("The certificate is not in PEM format (-----BEGIN CERTIFICATE-----).")
        return report
    try:
        key = serialization.load_pem_private_key(key_pem, password=None)
    except TypeError:
        errors.append("The private key is encrypted: upload it without a passphrase.")
        return report
    except (ValueError, UnsupportedAlgorithm):
        errors.append("The private key is not in PEM format (-----BEGIN PRIVATE KEY-----).")
        return report

    leaf, intermediates = certs[0], certs[1:]
    report["info"] = describe(leaf, len(certs))
    public = leaf.public_key()
    spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    if key.public_key().public_bytes(*spki) != public.public_bytes(*spki):
        if any(key.public_key().public_bytes(*spki) == c.public_key().public_bytes(*spki) for c in intermediates):
            errors.append("The certificates are out of order: the server certificate (the one of this key) must "
                          "come first, then each issuer.")
            return report
        errors.append("The private key does not belong to the certificate.")
    if isinstance(public, rsa.RSAPublicKey) and public.key_size < 2048:
        errors.append(f"The RSA key has {public.key_size} bits; at least 2048 are needed.")
    elif not isinstance(public, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey)):
        errors.append("Only RSA and ECDSA keys work with every client.")

    now = _now()
    if leaf.not_valid_before_utc > now:
        errors.append(f"The certificate is not valid before {leaf.not_valid_before_utc:%Y-%m-%d %H:%M} UTC.")
    if leaf.not_valid_after_utc < now:
        errors.append(f"The certificate expired on {leaf.not_valid_after_utc:%Y-%m-%d}.")
    elif report["info"]["days_left"] < EXPIRY_WARNING_DAYS:
        warnings.append(f"The certificate expires in {report['info']['days_left']} days.")
    for index, cert in enumerate(intermediates, 1):
        try:
            certs[index - 1].verify_directly_issued_by(cert)
        except (InvalidSignature, ValueError, TypeError):
            errors.append(f"Certificate {index + 1} of the chain did not issue certificate {index}: "
                          "the chain is incomplete or out of order (the server certificate comes first, "
                          "then each issuer).")
            break
    if errors:
        return report

    if not covers(_names(leaf), hostname):
        warnings.append(f"The certificate does not name {hostname}: browsers and some mail servers will "
                        "refuse it.")
    try:
        verifier = PolicyBuilder().store(_trust_store()).time(now).build_server_verifier(x509.DNSName(hostname))
        verifier.verify(leaf, intermediates)
    except VerificationError as exc:
        if covers(_names(leaf), hostname):
            warnings.append("The system's certificate authorities do not trust it (self-signed, a private CA, "
                            f"or a missing intermediate certificate): {exc}")
    except (OSError, ValueError) as exc:
        warnings.append(f"The chain could not be checked: {exc}")

    report["cert"] = b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)
    report["key"] = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
    return report


def stage(report):
    """Write validated files for tls-apply. Returns their SHA-256 (of
    cert.pem followed by key.pem, as tls-apply computes it)."""
    directory = current_app.config["TLS_UPLOAD_DIR"]
    os.makedirs(directory, mode=0o700, exist_ok=True)
    for name in ("cert.pem", "key.pem"):
        path = os.path.join(directory, name)
        fd = os.open(path + ".tmp", os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(report["cert" if name == "cert.pem" else "key"])
        os.replace(path + ".tmp", path)
    return hashlib.sha256(report["cert"] + report["key"]).hexdigest()


def staged_sha256():
    directory = current_app.config["TLS_UPLOAD_DIR"]
    try:
        with open(os.path.join(directory, "cert.pem"), "rb") as cert, open(os.path.join(directory, "key.pem"),
                                                                             "rb") as key:
            return hashlib.sha256(cert.read() + key.read()).hexdigest()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Status and requests
# ---------------------------------------------------------------------------

def status():
    """Outcome of the last requests, by action (le_test, le_apply,
    manual_apply, versions); a request that ran too long is marked stale."""
    try:
        with open(current_app.config["TLS_STATUS"], encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    for entry in data.values():
        if isinstance(entry, dict):
            entry["at_time"] = datetime.datetime.fromtimestamp(entry.get("at", 0), datetime.timezone.utc)
            if entry.get("state") == "running" and time.time() - entry.get("at", 0) > STALE_AFTER:
                entry["state"] = "stale"
    return data


def busy():
    if os.path.exists(current_app.config["TLS_REQUEST"]):
        return True
    return any(isinstance(e, dict) and e.get("state") == "running" for e in status().values())


def _request(data):
    if settings()["cluster"]:
        raise ServiceError("This gateway is a cluster member: its certificate and TLS settings are managed in "
                           "crassostrea.conf on each member.", status=409)
    if busy():
        raise ServiceError("Another certificate or TLS change is still being applied; wait for it to finish.",
                           status=409)
    try:
        _write_if_changed(current_app.config["TLS_REQUEST"], json.dumps(data))
    except OSError as exc:
        raise ServiceError(f"Cannot request the change ({exc}); is crassostrea-tls.path installed?",
                           status=503) from exc
    current_app.logger.info("certificate/TLS request: %s", data["action"])


def certificate_names(extra):
    """The hostname and the extra names (a list, or text with one per line or
    comma separated), validated: the names of a Let's Encrypt certificate."""
    s = settings()
    if isinstance(extra, str):
        extra = re.split(r"[\s,]+", extra)
    if not isinstance(extra, list) or not all(isinstance(n, str) for n in extra):
        raise ServiceError("names must be a list of host names", "names")
    names = [s["hostname"]]
    for name in (n.strip().lower().rstrip(".") for n in extra):
        if not name or name in names:
            continue
        wildcard = name.startswith("*.")
        if not HOSTNAME_RE.match(name[2:] if wildcard else name) or len(name) > 253:
            raise ServiceError(f"{name} is not a valid host name", "names")
        if wildcard and not s["dns_challenge"]:
            raise ServiceError(f"{name}: wildcard names need the DNS-01 challenge (ACME_DNS_CHALLENGE in "
                               "crassostrea.conf)", "names")
        names.append(name)
    if len(names) > MAX_NAMES:
        raise ServiceError(f"At most {MAX_NAMES} names per certificate", "names")
    return names


def passed_test(names):
    """The staging test that allows a production request for ``names``, or None."""
    test = status().get("le_test") or {}
    if test.get("state") == "ok" and sorted(test.get("names", [])) == sorted(names) \
            and time.time() - test.get("at", 0) < TEST_MAX_AGE:
        return test
    return None


def request_staging_test(extra):
    names = certificate_names(extra)
    _request({"action": "le-test", "names": names})
    return names


def request_letsencrypt(extra):
    names = certificate_names(extra)
    if passed_test(names) is None:
        raise ServiceError("Run a staging test of exactly these names first; it must have passed in the last "
                           "24 hours.", "names", 409)
    _request({"action": "le-apply", "names": names})
    return names


def request_manual(sha256):
    if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256) or staged_sha256() != sha256:
        raise ServiceError("Upload and check the files again: these are no longer the checked ones.", "sha256",
                           409)
    _request({"action": "manual-apply", "sha256": sha256})


def request_versions(https_min, smtp_min):
    for field, value in (("https_min", https_min), ("smtp_min", smtp_min)):
        if value not in TLS_MINIMUMS:
            raise ServiceError(f"{field} must be 1.2, 1.1 or 1.0", field)
    _request({"action": "versions", "https_min": https_min, "smtp_min": smtp_min})
