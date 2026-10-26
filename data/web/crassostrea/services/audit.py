"""Audit log: who changed what, when and from where.

Every state-changing request (POST, PUT, PATCH, DELETE) of the web UI and the
REST API is recorded after it ran, with the submitted fields minus secrets
(passwords, keys, codes, tokens) and its outcome: failed when the response is
an error or the page reported one (a "danger" message), otherwise ok. Logins
are requests as well, so failed logins appear under the name that was tried.
Management commands record themselves (``record``).

Entries are written over a connection of their own: a request that left
changes in the session after an error never gets them committed here.
"""
import json
import re
from datetime import timedelta

from flask import current_app, g, has_request_context, message_flashed, request
from flask_login import current_user
from sqlalchemy import insert

from ..extensions import db
from ..models import AuditEntry, get_setting, utcnow
from . import siem

WRITE_METHODS = ("POST", "PUT", "PATCH", "DELETE")
# Requests that change nothing worth recording
# cluster_join.join: polled while a node joins; it records the outcome itself
SKIP = {"static", "branding.set_theme", "cluster_join.join"}
SENSITIVE = re.compile(r"pass|secret|token|private|csrf|confirm|current|(^|[_-])(code|key)$", re.IGNORECASE)
MAX_FIELDS = 30
MAX_VALUE = 300


def init_app(app):
    message_flashed.connect(_collect_flash, app)
    app.before_request(_start_request)
    app.after_request(_record_request)


def _start_request():
    """g can outlive a request (an app context that was pushed already): the
    values this module reads must come from this request."""
    for name in ("audit_flashes", "api_key", "digest_address"):
        g.pop(name, None)


def _collect_flash(sender, message, category, **extra):
    if has_request_context():
        g.setdefault("audit_flashes", []).append((category, str(message)))


def _clip(value):
    value = str(value)
    return value if len(value) <= MAX_VALUE else value[:MAX_VALUE - 1] + "…"


def _fields():
    """Submitted fields without secrets: form fields, file names, or the JSON body."""
    fields = {}
    if request.is_json:
        body = request.get_json(silent=True)
        items = body.items() if isinstance(body, dict) else []
    else:
        items = list(request.form.lists())
        items += [(name, [f.filename for f in files if f]) for name, files in request.files.lists()]
    for name, value in items:
        if len(fields) >= MAX_FIELDS:
            break
        if SENSITIVE.search(name):
            if value not in (None, "", []):
                fields[name] = "(hidden)"
            continue
        if isinstance(value, list) and len(value) == 1:
            value = value[0]
        if isinstance(value, (dict, list)):
            value = json.dumps(value)
        fields[name] = _clip(value)
    return fields


def _actor():
    if request.blueprint == "api":
        key = g.get("api_key")
        return f"api:{key.name}" if key is not None else None
    if g.get("digest_address"):
        return f"link:{g.digest_address}"
    if current_user.is_authenticated:
        return current_user.username if current_user.is_admin else f"user:{current_user.email}"
    if request.endpoint == "auth.login":
        return _clip(request.form.get("username", "")) or "(anonymous)"
    return "(anonymous)"


def _target():
    rule = request.url_rule.rule if request.url_rule else ""
    arguments = {k: v for k, v in (request.view_args or {}).items() if not SENSITIVE.search(k)}
    return _clip(rule + (" " + " ".join(f"{k}={v}" for k, v in arguments.items()) if arguments else ""))


def _outcome(response):
    flashes = g.get("audit_flashes", [])
    message = " ".join(text for _, text in flashes)
    if response.status_code >= 400:
        if not message and response.is_json:
            message = str((response.get_json(silent=True) or {}).get("error", ""))
        return "failed", message or f"HTTP {response.status_code}"
    if any(category == "danger" for category, _ in flashes):
        return "failed", message
    return "ok", message


def _record_request(response):
    if request.method not in WRITE_METHODS or not request.endpoint or request.endpoint in SKIP:
        return response
    try:
        actor = _actor()
        if actor is None:  # API request without a valid key: rejected, logged by the throttling
            return response
        outcome, message = _outcome(response)
        _write(actor=actor, ip=request.remote_addr or "", method=request.method, action=request.endpoint,
               target=_target(), outcome=outcome, message=message, details=_fields())
    except Exception as exc:  # the audit log must never break a request
        current_app.logger.error("cannot write the audit log: %s", exc)
    return response


def _write(**entry):
    entry["details"] = json.dumps(entry.get("details") or {}, ensure_ascii=False)
    entry["message"] = (entry.get("message") or "")[:2000]
    entry["at"] = utcnow()
    with db.engine.begin() as connection:
        connection.execute(insert(AuditEntry).values(**entry))
    row = AuditEntry(**entry)
    siem.enqueue("audit", siem.audit_event(row, describe(row)))


def event(action, target="", message=""):
    """An entry for a request that changes nothing but must be recorded (a backup download)."""
    _write(actor=_actor() or "(anonymous)", ip=request.remote_addr or "", method=request.method, action=action,
           target=_clip(target), outcome="ok", message=message, details={})


def record(action, target="", message="", actor="cli", outcome="ok", details=None):
    """An entry for a change made outside a request (management commands)."""
    _write(actor=actor, ip="", method="", action=action, target=_clip(target), outcome=outcome,
           message=message, details=details)


def cleanup():
    """Delete entries older than the retention period; returns (count, days)."""
    days = get_setting("audit_retention_days")
    cutoff = utcnow() - timedelta(days=days)
    return AuditEntry.query.filter(AuditEntry.at < cutoff).delete(synchronize_session=False), days


def filtered(actor="", outcome="", search=""):
    query = AuditEntry.query
    if actor:
        query = query.filter(AuditEntry.actor == actor)
    if outcome in ("ok", "failed"):
        query = query.filter(AuditEntry.outcome == outcome)
    search = search.strip()
    if search:
        like = "%" + search.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        query = query.filter(db.or_(AuditEntry.action.ilike(like, escape="\\"),
                                    AuditEntry.target.ilike(like, escape="\\"),
                                    AuditEntry.message.ilike(like, escape="\\"),
                                    AuditEntry.details.ilike(like, escape="\\"),
                                    AuditEntry.ip == search))
    return query.order_by(AuditEntry.at.desc(), AuditEntry.id.desc())


# ---------------------------------------------------------------------------
# Display
# ---------------------------------------------------------------------------

AREAS = {"api": "API", "apikeys": "API keys", "attachments": "Attachments", "auth": "Account", "backups": "Backups",
         "cli": "Command line", "content_rules": "Content rules", "directories": "Directories",
         "dlp": "Data loss prevention", "domains": "Domains", "impersonation": "Impersonation",
         "ipconfig": "IP addressing", "journal": "Journaling", "linkprotection": "Link protection",
         "lists": "Allow & block lists", "logs": "Banned IPs", "mailboxes": "Mailbox users",
         "monitoring": "Monitoring", "maillog": "Mail log", "outbound": "Outbound limits", "portal": "Mailbox user",
         "quarantine": "Quarantine", "queue": "Mail queue", "reports": "DMARC & TLS reports", "settings": "Settings",
         "statistics": "Statistics", "tls": "Certificates & TLS", "token": "Digest link", "training": "Training",
         "users": "Administrators"}
OPERATIONS = {"auth.login": "Log in", "auth.login_code": "Log in (two-factor code)", "auth.logout": "Log out",
              "auth.account": "Change password", "auth.twofactor_setup": "Set up two-factor login",
              "auth.twofactor_disable": "Turn off two-factor login",
              "auth.twofactor_recovery_codes": "New recovery codes", "users.index": "Create administrator",
              "mailboxes.index": "Create mailbox user", "training.index": "Training: learn messages",
              "logs.unban": "Banned IPs: unban",
              "cli.reset-2fa": "Turn off two-factor login", "cli.create-admin": "Create administrator",
              "cli.reset-password": "Reset password"}


def describe(entry):
    """Readable action of an entry, e.g. "Quarantine: action (release)"."""
    area, _, operation = entry.action.partition(".")
    label = OPERATIONS.get(entry.action) or f"{AREAS.get(area, area)}: {operation.replace('_', ' ')}"
    try:
        details = json.loads(entry.details or "{}")
    except ValueError:
        details = {}
    if isinstance(details, dict) and isinstance(details.get("action"), str):
        label += f" ({details['action']})"
    return label


def details(entry):
    try:
        value = json.loads(entry.details or "{}")
    except ValueError:
        return {}
    return value if isinstance(value, dict) else {}


def actors():
    return [row[0] for row in db.session.query(AuditEntry.actor).distinct().order_by(AuditEntry.actor).limit(500)]
