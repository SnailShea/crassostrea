"""Content rules of the administrators: a part of a message (subject, From,
envelope sender, recipients, a header, the text, links, attachment names)
that contains, is or matches a value adds a score (negative to favour),
rejects the message or adds X-Content-Rule. The active rules are written to
content_rules.json and applied by rspamd (data/conf/rspamd/lua/rspamd.local.lua)
before the other checks; ``test`` does the same matching for the page.
"contains" and "is" ignore the case of ASCII letters; regular expressions
are PCRE in rspamd (Python's here, which rarely differs).
"""
import email
import json
import re
import string
from email import policy
from email.utils import getaddresses

from ..extensions import db
from ..models import (CONTENT_ACTIONS as ACTIONS, CONTENT_DIRECTIONS as DIRECTIONS, CONTENT_FIELDS as FIELDS,
                      CONTENT_MATCHES as MATCHES, ContentRule)
from .errors import ServiceError

COLUMNS = ("name", "active", "field", "header", "match", "value", "action", "score", "message", "direction",
           "comment")
_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)
_HEADER_RE = re.compile(r"^[!-9;-~]{1,128}$")


def _text(data, key, limit, required=False):
    value = data[key] if data.get(key) is not None else ""
    if not isinstance(value, str) or len(value) > limit:
        raise ServiceError(f"{key} must be text of at most {limit} characters", key)
    if required and not value.strip():
        raise ServiceError(f"{key} is required", key)
    return value


def _apply(rule, data):
    unknown = sorted(set(data) - set(COLUMNS))
    if unknown:
        raise ServiceError(f"Unknown field {unknown[0]}", unknown[0])
    if "name" in data:
        name = _text(data, "name", 64, True).strip()
        if any(c in name for c in '",') or not name.isprintable():
            raise ServiceError("The name cannot contain quotes or commas", "name")
        other = ContentRule.query.filter_by(name=name).first()
        if other and other is not rule:
            raise ServiceError(f"There already is a rule {name}", "name", 409)
        rule.name = name
    for key, choices in (("field", FIELDS), ("match", MATCHES), ("action", ACTIONS), ("direction", DIRECTIONS)):
        if key in data:
            if data[key] not in choices:
                raise ServiceError(f"{key} must be one of {', '.join(choices)}", key)
            setattr(rule, key, data[key])
    if "header" in data:
        rule.header = _text(data, "header", 128).strip()
    if rule.field == "header" and not _HEADER_RE.match(rule.header or ""):
        raise ServiceError("Enter the name of the header, e.g. X-Mailer", "header")
    if rule.field != "header":
        rule.header = ""
    if "value" in data:
        rule.value = _text(data, "value", 1000, True)
    if rule.match == "regex":
        if rule.value.startswith("/"):
            raise ServiceError("Enter the expression without slashes; use (?i) to ignore case", "value")
        try:
            re.compile(rule.value)
        except re.error as exc:
            raise ServiceError(f"Invalid regular expression: {exc}", "value") from None
    if "score" in data:
        value = data["score"]
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not -1000 <= value <= 1000:
            raise ServiceError("score must be a number from -1000 to 1000", "score")
        rule.score = float(value)
    if "message" in data:
        message = _text(data, "message", 255).strip()
        if message and not message.isprintable():
            raise ServiceError("The message must be one line of text", "message")
        rule.message = message
    if "active" in data:
        if not isinstance(data["active"], bool):
            raise ServiceError("active must be true or false", "active")
        rule.active = data["active"]
    if "comment" in data:
        rule.comment = _text(data, "comment", 255).strip()
    if rule.action == "score" and not rule.score:
        raise ServiceError("Give the score to add (negative to favour such mail)", "score")
    return rule


def add_rule(**data):
    for key in ("name", "field", "value"):
        if key not in data:
            raise ServiceError(f"{key} is required", key)
    rule = ContentRule(active=True, header="", match="contains", action="score", score=0.0, message="",
                       direction="inbound", comment="")
    _apply(rule, data)
    db.session.add(rule)
    return rule


def update_rule(rule, **data):
    return _apply(rule, data)


def delete_rule(rule):
    db.session.delete(rule)


def rules():
    return ContentRule.query.order_by(ContentRule.name).all()


def build_json():
    """content_rules.json: the active rules, reject rules first."""
    active = ContentRule.query.filter_by(active=True).all()
    active.sort(key=lambda r: (r.action != "reject", r.name))
    return json.dumps({"rules": [{key: getattr(r, key) for key in COLUMNS if key not in ("active", "comment")}
                                 for r in active]}, indent=1) + "\n"


def matches(rule, value):
    if rule.match == "regex":
        return re.search(rule.value, value) is not None
    value, needle = value.translate(_LOWER), rule.value.translate(_LOWER)
    return value == needle if rule.match == "equals" else needle in value


def test(values, direction="inbound"):
    """Which rules match a message described by ``values`` ({field: [texts]},
    headers as "header:<name>"): [{rule, matched, value}] for every rule of
    the direction."""
    if direction not in ("inbound", "outbound"):
        raise ServiceError("direction must be inbound or outbound", "direction")
    results = []
    for rule in rules():
        if rule.direction not in ("both", direction):
            continue
        key = f"header:{rule.header.lower()}" if rule.field == "header" else rule.field
        hit = next((v for v in values.get(key, []) if matches(rule, v)), None)
        results.append({"rule": rule, "matched": hit is not None, "value": hit})
    return results


_URL_RE = re.compile(r"""https?://[^\s<>"'\[\]]+""", re.I)


def message_values(source, envelope_from="", recipients=()):
    """The values of a pasted message (its source) as rspamd sees them."""
    if not isinstance(source, str) or not source.strip():
        raise ServiceError("Paste the source of a message (headers, a blank line, the text)", "source")
    msg = email.message_from_string(source.replace("\r\n", "\n"), policy=policy.default)
    values = {"subject": [str(msg.get("Subject", ""))], "envelope_from": [envelope_from.strip()],
              "recipient": [r.strip() for r in recipients if r.strip()], "body": [], "url": [], "attachment": []}
    values["from"] = [f"{name} <{addr}>" if name else addr
                      for name, addr in getaddresses([str(v) for v in msg.get_all("From", [])])]
    for name, value in msg.items():
        values.setdefault(f"header:{name.lower()}", []).append(str(value))
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        if filename:
            values["attachment"].append(filename)
        elif part.get_content_maintype() == "text":
            try:
                text = part.get_content()
            except (LookupError, ValueError):
                text = part.get_payload(decode=True).decode("utf-8", "replace") if part.get_payload() else ""
            if part.get_content_subtype() == "html":
                values["url"] += re.findall(r"""href\s*=\s*["']([^"']+)""", text, re.I)
                text = re.sub(r"<[^>]+>", " ", text)
            values["body"].append(text)
            values["url"] += _URL_RE.findall(text)
    return values
