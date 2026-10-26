"""Password hashes of mailbox users, including ones imported from other mail
systems.

New passwords are hashed by Werkzeug (scrypt). Accounts created through the
API may bring the hash of their previous system instead (``password_hash``);
``normalize`` checks it and returns what is stored, ``verify`` checks a
password against it, and the first successful login replaces an imported hash
with scrypt (``needs_upgrade``).

Accepted, with or without the Dovecot/LDAP scheme prefix where one exists:

- Werkzeug: ``scrypt:...``, ``pbkdf2:sha256:...`` (stored as they are)
- crypt(3) strings, verified by libxcrypt: ``$6$`` SHA512-CRYPT, ``$5$``
  SHA256-CRYPT, ``$1$`` MD5-CRYPT, ``$2a$``/``$2b$``/``$2y$`` bcrypt
  (BLF-CRYPT), ``$y$``/``$gy$`` yescrypt, ``$7$`` scrypt, ``$sha1$``;
  prefixes ``{CRYPT}``, ``{SHA512-CRYPT}``, ``{SHA256-CRYPT}``,
  ``{MD5-CRYPT}``, ``{BLF-CRYPT}``, Dovecot's ``{MD5}``
- Argon2 (``$argon2id$``, ``$argon2i$``, ``$argon2d$``), also ``{ARGON2ID}``,
  ``{ARGON2I}`` and Django's ``argon2$...``
- salted and plain digests: ``{SSHA512}``, ``{SSHA256}``, ``{SSHA}``,
  ``{SMD5}``, ``{SHA512}``, ``{SHA256}``, ``{SHA}``, ``{PLAIN-MD5}``,
  ``{LDAP-MD5}``, LDAP's ``{MD5}``; Base64 or hex (``.HEX``/``.B64`` suffix,
  or recognised by length)
- PBKDF2: Django's ``pbkdf2_sha256$...``/``pbkdf2_sha1$...``, Dovecot's
  ``{PBKDF2}$1$...``
- clear text: ``{PLAIN}``, ``{CLEAR}``, ``{CLEARTEXT}`` (hashed with scrypt
  at once, never stored)

Stored forms other than Werkzeug's carry a scheme prefix of their own
(``{CRYPT}``, ``{ARGON2}``, ``{SSHA256}``, ...). Costs are capped so an imported
hash cannot make a login take minutes.
"""
import base64
import binascii
import ctypes
import ctypes.util
import hashlib
import hmac
import re
import threading

from werkzeug.security import check_password_hash, generate_password_hash


class HashError(ValueError):
    pass


SUPPORTED = ("Werkzeug scrypt/pbkdf2, crypt(3) ($6$, $5$, $1$, $2y$/$2b$ bcrypt, $y$ yescrypt, $7$, $sha1$), "
             "Argon2, {SSHA512}, {SSHA256}, {SSHA}, {SMD5}, {SHA512}, {SHA256}, {SHA}, {PLAIN-MD5}, PBKDF2 "
             "(Django, Dovecot) and {PLAIN}")

# crypt(3) identifiers accepted (no DES, no broken $2x$)
CRYPT_RE = re.compile(r"^\$(1|5|6|2a|2b|2y|y|gy|7|sha1)\$[./A-Za-z0-9$=,+-]{4,240}$")
CRYPT_PREFIXES = ("CRYPT", "SHA512-CRYPT", "SHA256-CRYPT", "MD5-CRYPT", "BLF-CRYPT", "MD5")
WERKZEUG_RE = re.compile(r"^(scrypt:\d+:\d+:\d+|pbkdf2:sha(256|512)(:\d+)?)\$[A-Za-z0-9]{1,64}\$[0-9a-f]{64,128}$")
ARGON2_RE = re.compile(r"^\$argon2(id|i|d)\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$[A-Za-z0-9+/]+\$[A-Za-z0-9+/]+$")
DJANGO_PBKDF2_RE = re.compile(r"^pbkdf2_(sha256|sha1)\$(\d+)\$([^$]{1,128})\$([A-Za-z0-9+/=]+)$")
DOVECOT_PBKDF2_RE = re.compile(r"^\$1\$([^$]{1,128})\$(\d+)\$([0-9a-fA-F]{40})$")
# digest name, length; salted schemes have the salt after the digest
DIGESTS = {"SHA512": ("sha512", 64), "SHA256": ("sha256", 32), "SHA": ("sha1", 20), "MD5": ("md5", 16)}
SALTED = {"SSHA512": "SHA512", "SSHA256": "SHA256", "SSHA": "SHA", "SMD5": "MD5"}
PLAIN_DIGESTS = {"SHA512": "SHA512", "SHA256": "SHA256", "SHA": "SHA", "SHA1": "SHA", "PLAIN-MD5": "MD5",
                 "LDAP-MD5": "MD5", "MD5": "MD5"}
CLEAR = ("PLAIN", "CLEAR", "CLEARTEXT", "PLAINTEXT")

MAX_BCRYPT_COST = 16
MAX_SHA_CRYPT_ROUNDS = 1_000_000
MAX_PBKDF2_ITERATIONS = 2_000_000
MAX_ARGON2_MEMORY_KIB = 262_144
MAX_ARGON2_TIME = 16
MAX_ARGON2_LANES = 16
MAX_LENGTH = 255

_PREFIX_RE = re.compile(r"^\{([A-Za-z0-9-]+)(?:\.(HEX|B64|BASE64))?\}(.*)$", re.S)


def hash_new(password):
    return generate_password_hash(password)


# ---------------------------------------------------------------------------
# Import
# ---------------------------------------------------------------------------

def normalize(value):
    """The stored form of an imported hash. Raises HashError."""
    if not isinstance(value, str) or not value.strip():
        raise HashError("password_hash must be a non-empty string")
    value = value.strip()
    if len(value) > 1000:
        raise HashError("password_hash is too long")
    match = _PREFIX_RE.match(value)
    if match:
        scheme, encoding, payload = match.group(1).upper(), match.group(2), match.group(3)
        stored = _prefixed(scheme, encoding and encoding.upper(), payload)
    else:
        stored = _bare(value)
    if len(stored) > MAX_LENGTH:
        raise HashError("password_hash is too long")
    return stored


def _bare(value):
    if WERKZEUG_RE.match(value):
        _check_werkzeug(value)
        return value
    if value.startswith("$argon2"):
        return "{ARGON2}" + _argon2(value)
    if value.startswith("argon2$"):  # Django
        return "{ARGON2}" + _argon2(value[len("argon2"):])
    if DJANGO_PBKDF2_RE.match(value):
        _check_django_pbkdf2(value)
        return "{PBKDF2-DJANGO}" + value
    if value.startswith("$"):
        return "{CRYPT}" + _crypt(value)
    raise HashError(f"Unsupported password hash format. Supported: {SUPPORTED}")


def _prefixed(scheme, encoding, payload):
    if scheme in CLEAR:
        if not payload:
            raise HashError("The clear text password is empty")
        return hash_new(payload)
    if scheme in CRYPT_PREFIXES and payload.startswith("$"):
        return "{CRYPT}" + _crypt(payload)
    if scheme in ("ARGON2", "ARGON2I", "ARGON2ID", "ARGON2D"):
        return "{ARGON2}" + _argon2(payload)
    if scheme == "PBKDF2":
        match = DOVECOT_PBKDF2_RE.match(payload)
        if not match:
            raise HashError("{PBKDF2} must be Dovecot's $1$salt$rounds$hex")
        if not 1 <= int(match.group(2)) <= MAX_PBKDF2_ITERATIONS:
            raise HashError(f"PBKDF2 iterations must be 1 to {MAX_PBKDF2_ITERATIONS}")
        return "{PBKDF2-DOVECOT}" + payload
    if scheme in SALTED:
        digest = _decode(payload, encoding, DIGESTS[SALTED[scheme]][1], salted=True)
        return "{" + scheme + "}" + base64.b64encode(digest).decode()
    if scheme in PLAIN_DIGESTS:
        name = PLAIN_DIGESTS[scheme]
        # Dovecot's PLAIN-MD5 is hex by default, the others Base64
        digest = _decode(payload, encoding or ("HEX" if scheme == "PLAIN-MD5" else None), DIGESTS[name][1],
                         salted=False)
        return "{" + name + "}" + base64.b64encode(digest).decode()
    raise HashError(f"Unsupported password scheme {{{scheme}}}. Supported: {SUPPORTED}")


def _decode(payload, encoding, length, salted):
    """Raw bytes of a digest (and salt), Base64 or hex."""
    payload = payload.strip()
    candidates = []
    if encoding in (None, "HEX") and re.fullmatch(r"[0-9a-fA-F]+", payload) and len(payload) % 2 == 0:
        candidates.append(binascii.unhexlify(payload))
    if encoding in (None, "B64", "BASE64"):
        try:
            candidates.append(base64.b64decode(payload, validate=True))
        except (binascii.Error, ValueError):
            pass
    for raw in candidates:
        if (len(raw) > length and len(raw) <= length + 64) if salted else len(raw) == length:
            return raw
    kind = "a digest with a salt" if salted else f"a digest of {length} bytes"
    raise HashError(f"The hash is not {kind} in Base64 or hex")


def _check_werkzeug(value):
    method = value.split("$", 1)[0]
    if method.startswith("pbkdf2:"):
        parts = method.split(":")
        if len(parts) == 3 and not 1 <= int(parts[2]) <= MAX_PBKDF2_ITERATIONS:
            raise HashError(f"PBKDF2 iterations must be 1 to {MAX_PBKDF2_ITERATIONS}")
    else:
        n, r, p = (int(x) for x in method.split(":")[1:])
        if n > 2 ** 20 or r > 16 or p > 16:
            raise HashError("The scrypt parameters are too large")


def _check_django_pbkdf2(value):
    iterations = int(DJANGO_PBKDF2_RE.match(value).group(2))
    if not 1 <= iterations <= MAX_PBKDF2_ITERATIONS:
        raise HashError(f"PBKDF2 iterations must be 1 to {MAX_PBKDF2_ITERATIONS}")


def _argon2(value):
    match = ARGON2_RE.match(value)
    if not match:
        raise HashError("Not an Argon2 hash ($argon2id$v=19$m=...,t=...,p=...$salt$hash)")
    memory, time_cost, lanes = (int(match.group(i)) for i in (2, 3, 4))
    if memory > MAX_ARGON2_MEMORY_KIB or time_cost > MAX_ARGON2_TIME or lanes > MAX_ARGON2_LANES:
        raise HashError(f"The Argon2 parameters are too large (at most m={MAX_ARGON2_MEMORY_KIB}, "
                        f"t={MAX_ARGON2_TIME}, p={MAX_ARGON2_LANES})")
    return value


def _crypt(value):
    if not CRYPT_RE.match(value):
        raise HashError("Not a supported crypt(3) hash ($6$, $5$, $1$, $2y$/$2b$/$2a$, $y$, $gy$, $7$, $sha1$)")
    ident = value.split("$")[1]
    if ident in ("2a", "2b", "2y"):
        cost = re.match(r"^\$2[aby]\$(\d\d)\$", value)
        if not cost or int(cost.group(1)) > MAX_BCRYPT_COST:
            raise HashError(f"bcrypt hashes must have a cost of at most {MAX_BCRYPT_COST}")
    if ident in ("5", "6"):
        rounds = re.match(r"^\$[56]\$rounds=(\d+)\$", value)
        if rounds and int(rounds.group(1)) > MAX_SHA_CRYPT_ROUNDS:
            raise HashError(f"SHA-crypt hashes must have at most {MAX_SHA_CRYPT_ROUNDS} rounds")
    if _libcrypt() is None:
        raise HashError("crypt(3) hashes need libxcrypt (libcrypt.so.2), which is missing")
    # a hash libxcrypt cannot compute with is refused now, not at the first login
    if _crypt_rn("probe", value) is None:
        raise HashError("libxcrypt does not accept this crypt(3) hash")
    return value


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------

def scheme(stored):
    """Short name of a stored hash: scrypt, pbkdf2, crypt, argon2, ssha256, ..."""
    if stored.startswith("{"):
        return stored[1:stored.index("}")].lower()
    return stored.split(":", 1)[0]


def needs_upgrade(stored):
    """Anything but Werkzeug's scrypt is replaced at the next login."""
    return not stored.startswith("scrypt:")


def verify(stored, password):
    if not stored or password is None:
        return False
    try:
        if not stored.startswith("{"):
            return check_password_hash(stored, password)
        kind, payload = stored[1:].split("}", 1)
        secret = password.encode("utf-8")
        if kind == "CRYPT":
            result = _crypt_rn(password, payload)
            return result is not None and hmac.compare_digest(result, payload)
        if kind == "ARGON2":
            from argon2 import PasswordHasher
            from argon2.exceptions import Argon2Error
            try:
                return PasswordHasher().verify(payload, password)
            except Argon2Error:
                return False
        if kind in SALTED:
            name, length = DIGESTS[SALTED[kind]]
            raw = base64.b64decode(payload)
            digest, salt = raw[:length], raw[length:]
            return hmac.compare_digest(hashlib.new(name, secret + salt).digest(), digest)
        if kind in DIGESTS:
            return hmac.compare_digest(hashlib.new(DIGESTS[kind][0], secret).digest(), base64.b64decode(payload))
        if kind == "PBKDF2-DJANGO":
            algorithm, iterations, salt, expected = DJANGO_PBKDF2_RE.match(payload).groups()
            digest = hashlib.pbkdf2_hmac(algorithm, secret, salt.encode(), int(iterations))
            return hmac.compare_digest(base64.b64encode(digest).decode(), expected)
        if kind == "PBKDF2-DOVECOT":
            salt, iterations, expected = DOVECOT_PBKDF2_RE.match(payload).groups()
            digest = hashlib.pbkdf2_hmac("sha1", secret, salt.encode(), int(iterations))
            return hmac.compare_digest(digest.hex(), expected.lower())
    except (ValueError, TypeError, AttributeError, binascii.Error, ImportError):
        return False
    return False


# ---------------------------------------------------------------------------
# libxcrypt
# ---------------------------------------------------------------------------

_lib = None
_lib_lock = threading.Lock()
# struct crypt_data of libxcrypt
_CRYPT_DATA_SIZE = 32768


def _libcrypt():
    global _lib
    with _lib_lock:
        if _lib is None:
            name = ctypes.util.find_library("crypt")
            try:
                lib = ctypes.CDLL(name or "libcrypt.so.2")
                lib.crypt_rn.restype = ctypes.c_char_p
                lib.crypt_rn.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_void_p, ctypes.c_int]
                _lib = lib
            except (OSError, AttributeError):
                _lib = False
        return _lib or None


def _crypt_rn(password, setting):
    """crypt_rn(3): the hash of ``password`` with the settings (and salt) of
    ``setting``, or None. Thread-safe: every call has its own buffer."""
    lib = _libcrypt()
    if lib is None:
        return None
    phrase = password.encode("utf-8")
    if b"\0" in phrase:
        return None
    data = ctypes.create_string_buffer(_CRYPT_DATA_SIZE)
    result = lib.crypt_rn(phrase, setting.encode("ascii"), data, _CRYPT_DATA_SIZE)
    if not result or result.startswith(b"*"):
        return None
    return result.decode("ascii")
