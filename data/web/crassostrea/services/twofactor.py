"""Two-factor login of administrators: time-based one-time passwords (TOTP,
RFC 6238: SHA-1, 6 digits, 30 seconds), as authenticator apps generate them,
and one-time recovery codes.

A code is accepted once: the time step of the last accepted code is kept, so
a code seen by someone else cannot be replayed. Recovery codes are stored as
SHA-256 hashes (they are random, so a slow hash adds nothing) and removed
when used. API keys are not affected: they are no password.
"""
import base64
import hashlib
import hmac
import json
import secrets
import struct
import time
from urllib.parse import quote

import segno

from ..models import get_setting, utcnow

DIGITS = 6
PERIOD = 30
# Steps before/after the current one that are accepted (clock drift)
DRIFT = 1
RECOVERY_CODES = 10


def new_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode()


def code_at(secret, step):
    key = base64.b32decode(secret)
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** DIGITS).zfill(DIGITS)


def _step(now=None):
    return int((time.time() if now is None else now) // PERIOD)


def matching_step(secret, code, after=None, now=None):
    """The time step whose code is ``code`` (within DRIFT), later than
    ``after``, or None."""
    code = "".join((code or "").split())
    if len(code) != DIGITS or not code.isdigit():
        return None
    current = _step(now)
    for step in range(current - DRIFT, current + DRIFT + 1):
        if (after is None or step > after) and hmac.compare_digest(code_at(secret, step), code):
            return step
    return None


def provisioning_uri(secret, account, issuer):
    label = quote(f"{issuer}:{account}", safe="")
    return (f"otpauth://totp/{label}?secret={secret}&issuer={quote(issuer, safe='')}"
            f"&algorithm=SHA1&digits={DIGITS}&period={PERIOD}")


def qr_data_uri(uri):
    return segno.make(uri, error="m").svg_data_uri(scale=5, border=2, dark="#000", light="#fff")


def _hash(code):
    return hashlib.sha256(code.replace("-", "").lower().encode()).hexdigest()


def new_recovery_codes():
    """Codes to show once (xxxx-xxxx, 40 random bits each) and their hashes."""
    alphabet = "abcdefghjkmnpqrstuvwxyz23456789"
    codes = ["".join(secrets.choice(alphabet) for _ in range(8)) for _ in range(RECOVERY_CODES)]
    codes = [f"{c[:4]}-{c[4:]}" for c in codes]
    return codes, json.dumps([_hash(c) for c in codes])


def recovery_codes_left(admin):
    try:
        return len(json.loads(admin.recovery_codes or "[]"))
    except ValueError:
        return 0


# ---------------------------------------------------------------------------
# Administrators
# ---------------------------------------------------------------------------

def enabled(admin):
    return bool(getattr(admin, "totp_secret", None) and admin.totp_enabled_at)


def required():
    """Every administrator must use two-factor login (Settings)."""
    return bool(get_setting("require_admin_2fa"))


def enable(admin, secret, code):
    """Turn two-factor login on after the app showed a matching code. Returns
    the recovery codes to show once, or None if the code does not match."""
    step = matching_step(secret, code)
    if step is None:
        return None
    codes, hashes = new_recovery_codes()
    admin.totp_secret, admin.totp_enabled_at, admin.totp_last_step = secret, utcnow(), step
    admin.recovery_codes = hashes
    return codes


def disable(admin):
    admin.totp_secret = admin.totp_enabled_at = admin.totp_last_step = admin.recovery_codes = None


def verify(admin, code):
    """A login code: a TOTP code not used before, or an unused recovery code.
    Returns "totp", "recovery" or None; marks the code used."""
    if not enabled(admin):
        return None
    step = matching_step(admin.totp_secret, code, after=admin.totp_last_step)
    if step is not None:
        admin.totp_last_step = step
        return "totp"
    try:
        hashes = json.loads(admin.recovery_codes or "[]")
    except ValueError:
        hashes = []
    digest = _hash((code or "").strip())
    for stored in hashes:
        if hmac.compare_digest(stored, digest):
            hashes.remove(stored)
            admin.recovery_codes = json.dumps(hashes)
            return "recovery"
    return None


def regenerate_recovery_codes(admin):
    codes, admin.recovery_codes = new_recovery_codes()
    return codes
