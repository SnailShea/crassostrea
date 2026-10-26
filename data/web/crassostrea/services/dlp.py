"""Outbound data loss prevention: rules that stop mail from the relay
networks holding card numbers, IBANs, US social security numbers, keywords
or matches of a regular expression.

The active rules are written to dlp_rules.json; rspamd
(data/conf/rspamd/lua/rspamd.local.lua) checks the subject, the text and
the text attachments (text/*, CSV, JSON, XML) of each outbound message with
the detectors of data/conf/rspamd/lua/dlp_detectors.lua. The detectors below
are the same, for the rule test of the web UI; keep them alike. A rule
matches with at least min_matches different values. "quarantine" rejects the
message and keeps it in the outbound quarantine (even if outbound quarantine
is off) for an administrator to release; "reject" only rejects it; "header"
delivers it with X-DLP-Match. Office documents and PDFs are not looked into.
"""
import json
import re
import string

from ..extensions import db
from ..models import DLP_ACTIONS as ACTIONS, DLP_DETECTORS as DETECTORS, DlpRule
from .. import validators as v
from .errors import ServiceError
from .outbound import normalize_sender

MAX_KEYWORDS = 200
MAX_PATTERN = 1000
# Values shown per rule in a test
SHOWN = 10

# IBAN length by country (dlp_detectors.lua's IBAN_LENGTHS)
IBAN_LENGTHS = {
    "AD": 24, "AE": 23, "AL": 28, "AT": 20, "AZ": 28, "BA": 20, "BE": 16, "BG": 22, "BH": 22, "BR": 29, "CH": 21,
    "CR": 22, "CY": 28, "CZ": 24, "DE": 22, "DK": 18, "DO": 28, "EE": 20, "EG": 29, "ES": 24, "FI": 18, "FO": 18,
    "FR": 27, "GB": 22, "GE": 22, "GI": 23, "GL": 18, "GR": 27, "GT": 28, "HR": 21, "HU": 28, "IE": 22, "IL": 23,
    "IQ": 23, "IS": 26, "IT": 27, "JO": 30, "KW": 30, "KZ": 20, "LB": 28, "LC": 32, "LI": 21, "LT": 20, "LU": 20,
    "LV": 21, "MC": 27, "MD": 24, "ME": 22, "MK": 19, "MR": 27, "MT": 31, "MU": 30, "NL": 18, "NO": 15, "PK": 24,
    "PL": 28, "PS": 29, "PT": 25, "QA": 29, "RO": 24, "RS": 22, "SA": 24, "SC": 31, "SE": 24, "SI": 19, "SK": 24,
    "SM": 27, "TL": 23, "TN": 24, "TR": 26, "UA": 29, "VA": 22, "VG": 24, "XK": 20,
}
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_ASCII_UPPER = str.maketrans(string.ascii_lowercase, string.ascii_uppercase)
_ALNUM = set(string.ascii_letters + string.digits)


# ---------------------------------------------------------------------------
# Detectors: the different values found in a text
# ---------------------------------------------------------------------------

def _luhn(digits):
    total = 0
    for index, char in enumerate(reversed(digits)):
        d = int(char)
        if index % 2:
            d = d * 2 - 9 if d > 4 else d * 2
        total += d
    return total % 10 == 0


def credit_card(text):
    found = set()
    for run in re.findall(r"[0-9 \-]+", text):
        for piece in re.split(r"[ \-][ \-]+", run):
            digits = re.sub(r"[ \-]", "", piece)
            if 13 <= len(digits) <= 19 and digits[0] in "23456" and _luhn(digits):
                found.add(digits)
    return found


def _iban_valid(iban):
    rearranged = iban[4:] + iban[:4]
    return int("".join(c if c.isdigit() else str(ord(c) - 55) for c in rearranged)) % 97 == 1


def iban(text):
    found = set()
    upper = text.translate(_ASCII_UPPER)
    for match in re.finditer(r"(?<![A-Za-z0-9])([A-Z]{2})[0-9]{2}", upper):
        length = IBAN_LENGTHS.get(match.group(1))
        if not length:
            continue
        chars, i = [], match.start()
        while len(chars) < length and i < len(upper):
            c = upper[i]
            if c in _ALNUM:
                chars.append(c)
            elif not (c == " " and i + 1 < len(upper) and upper[i + 1] in _ALNUM and chars):
                break
            i += 1
        value = "".join(chars)
        if len(value) == length and not (i < len(upper) and upper[i] in _ALNUM) and _iban_valid(value):
            found.add(value)
    return found


def us_ssn(text):
    found = set()
    for area, group, serial in re.findall(r"(?<![0-9])([0-9]{3})-([0-9]{2})-([0-9]{4})(?![0-9])", text):
        if area not in ("000", "666") and not area.startswith("9") and group != "00" and serial != "0000":
            found.add(f"{area}-{group}-{serial}")
    return found


def keywords(text, words):
    lower = text.translate(_ASCII_LOWER)
    return {word.translate(_ASCII_LOWER) for word in words if word.translate(_ASCII_LOWER) in lower}


def regex(text, pattern):
    return {m.group(0) for m in re.finditer(pattern, text)}


def detect(rule, text):
    if rule.detector == "keywords":
        return keywords(text, _keywords(rule.pattern))
    if rule.detector == "regex":
        return regex(text, rule.pattern)
    return {"credit_card": credit_card, "iban": iban, "us_ssn": us_ssn}[rule.detector](text)


# ---------------------------------------------------------------------------
# Rules
# ---------------------------------------------------------------------------

def _keywords(pattern):
    return [line.strip() for line in (pattern or "").splitlines() if line.strip()]


def _name(value):
    value = (value if isinstance(value, str) else "").strip()
    if not 1 <= len(value) <= 64:
        raise ServiceError("Give the rule a name of at most 64 characters", "name")
    if any(c in value for c in '",') or not value.isprintable():
        raise ServiceError("The name cannot contain quotes or commas", "name")
    return value


def _pattern(detector, value):
    value = value if isinstance(value, str) else ""
    if detector == "keywords":
        words = _keywords(value)
        if not words:
            raise ServiceError("Enter at least one keyword or phrase, one per line", "pattern")
        if len(words) > MAX_KEYWORDS or any(len(w) > 200 for w in words):
            raise ServiceError(f"At most {MAX_KEYWORDS} keywords of at most 200 characters", "pattern")
        return "\n".join(words)
    if detector == "regex":
        value = value.strip()
        if not value or len(value) > MAX_PATTERN:
            raise ServiceError(f"Enter a regular expression of at most {MAX_PATTERN} characters", "pattern")
        if value.startswith("/"):
            raise ServiceError("Enter the expression without slashes; use (?i) to ignore case", "pattern")
        try:
            compiled = re.compile(value)
        except re.error as exc:
            raise ServiceError(f"Invalid regular expression: {exc}", "pattern") from None
        if compiled.match(""):
            raise ServiceError("The expression must not match an empty text", "pattern")
        return value
    return ""


def _fields(rule, data):
    if "name" in data:
        name = _name(data["name"])
        other = DlpRule.query.filter_by(name=name).first()
        if other and other is not rule:
            raise ServiceError(f"There already is a rule {name}", "name", 409)
        rule.name = name
    if "detector" in data:
        if data["detector"] not in DETECTORS:
            raise ServiceError(f"detector must be one of {', '.join(DETECTORS)}", "detector")
        rule.detector = data["detector"]
    if "pattern" in data or "detector" in data:
        rule.pattern = _pattern(rule.detector, data.get("pattern", rule.pattern))
    if "min_matches" in data:
        value = data["min_matches"]
        if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 1000:
            raise ServiceError("min_matches must be a whole number from 1 to 1000", "min_matches")
        rule.min_matches = value
    if "sender" in data:
        rule.sender = normalize_sender(data["sender"]) if (data["sender"] or "").strip() else ""
    if "action" in data:
        if data["action"] not in ACTIONS:
            raise ServiceError(f"action must be one of {', '.join(ACTIONS)}", "action")
        rule.action = data["action"]
    if "active" in data:
        if not isinstance(data["active"], bool):
            raise ServiceError("active must be true or false", "active")
        rule.active = data["active"]
    if "comment" in data:
        comment = "" if data["comment"] is None else data["comment"]
        if not isinstance(comment, str) or len(comment.strip()) > 255:
            raise ServiceError("The comment must be text of at most 255 characters", "comment")
        rule.comment = comment.strip()
    return rule


def add_rule(**data):
    for key in ("name", "detector"):
        if key not in data:
            raise ServiceError(f"{key} is required", key)
    rule = _fields(DlpRule(min_matches=1, sender="", action="quarantine", active=True, comment="", pattern=""),
                   {"pattern": "", **data})
    db.session.add(rule)
    return rule


def update_rule(rule, **data):
    return _fields(rule, data)


def delete_rule(rule):
    db.session.delete(rule)


def rules():
    return DlpRule.query.order_by(DlpRule.name).all()


def build_json():
    """dlp_rules.json for rspamd: the active rules."""
    out = []
    for rule in DlpRule.query.filter_by(active=True).order_by(DlpRule.name):
        entry = {"name": rule.name, "detector": rule.detector, "min_matches": rule.min_matches,
                 "sender": rule.sender, "action": rule.action}
        if rule.detector == "keywords":
            entry["keywords"] = _keywords(rule.pattern)
        elif rule.detector == "regex":
            entry["pattern"] = rule.pattern
        out.append(entry)
    return json.dumps({"rules": out}, indent=1) + "\n"


def applies(rule, sender):
    sender = (sender or "").strip().lower()
    return not rule.sender or rule.sender == sender or rule.sender == sender.rsplit("@", 1)[-1]


def test(text, sender=""):
    """What the rules find in ``text`` sent by ``sender`` (every sender if
    empty): [{rule, applies, found, count, matched}] for all rules; found
    has at most SHOWN values."""
    if not isinstance(text, str) or not text:
        raise ServiceError("Enter a text to test", "text")
    if sender:
        try:
            sender = v.normalize_email(sender)
        except v.ValidationError as exc:
            raise ServiceError(str(exc), "sender") from None
    results = []
    for rule in rules():
        relevant = not sender or applies(rule, sender)
        values = sorted(detect(rule, text)) if relevant else []
        results.append({"rule": rule, "applies": relevant, "found": values[:SHOWN], "count": len(values),
                        "matched": relevant and len(values) >= rule.min_matches})
    return results
