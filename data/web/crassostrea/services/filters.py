"""Business rules for the filter configuration: domains and their recipients,
allow/block lists, relay networks, global settings and DKIM keys.

Used by the web UI and the REST API so both enforce the same constraints.
Functions raise ServiceError with a user facing message. Callers commit and
then call maps.sync_all(), which writes the rspamd and Postfix maps.
"""
import ipaddress
import json
import re

from ..extensions import db
from ..models import (DIGEST_INTERVALS, LIMIT_PERIODS, LIST_KINDS, LIST_TYPES, MAX_MAILLOG_DAYS, MAX_MESSAGE_MB,
                      MAX_OUTBOUND_LIMIT, RECIPIENT_CHECKS, Directory, DkimKey, Domain, ListEntry, Recipient,
                      RelayNetwork, get_setting, set_setting, touch_config)
from .. import validators as v
from . import dkim
from .accounts import SCORE_FIELDS, global_scores
from .errors import ServiceError
from .outbound import normalize_sender

SCORE_RANGE = (-100.0, 10000.0)


# ---------------------------------------------------------------------------
# Value checks
# ---------------------------------------------------------------------------

def _normalized(func, value, field):
    if not isinstance(value, str):
        raise ServiceError(f"{field} must be text", field)
    try:
        return func(value)
    except v.ValidationError as exc:
        raise ServiceError(str(exc), field)


def _bool(value, field):
    if not isinstance(value, bool):
        raise ServiceError(f"{field} must be true or false", field)
    return value


def _int(value, field, low, high):
    if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
        raise ServiceError(f"{field} must be a whole number from {low} to {high}", field)
    return value


def _text(value, field, max_length=255):
    if value is None:
        return ""
    if not isinstance(value, str) or len(value.strip()) > max_length:
        raise ServiceError(f"{field} must be text of at most {max_length} characters", field)
    return value.strip()


def _score(value, field):
    if value is None:
        return None
    low, high = SCORE_RANGE
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not low <= value <= high:
        raise ServiceError(f"Thresholds must be numbers from {low:g} to {high:g}", field)
    return float(value)


def _choice(value, field, choices, nullable=False):
    if value is None and nullable:
        return None
    if value not in choices:
        allowed = ", ".join(choices) + (" or null" if nullable else "")
        raise ServiceError(f"{field} must be one of {allowed}", field)
    return value


def check_threshold_order(scores, hint=""):
    if not scores["greylist_score"] <= scores["add_header_score"] < scores["reject_score"]:
        raise ServiceError("Thresholds must satisfy: greylist ≤ mark as spam < reject" + hint, "reject_score")


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

DOMAIN_FIELDS = ("description", "active", "destination_host", "destination_port", "use_mx", "recipient_check",
                 "directory_id", "quarantine_enabled", "link_protection", "digest_interval") + SCORE_FIELDS


def create_domain(name, **fields):
    name = _normalized(v.normalize_domain, name, "name")
    if Domain.query.filter_by(name=name).first():
        raise ServiceError("This domain already exists", "name", status=409)
    if not fields.get("destination_host"):
        raise ServiceError("destination_host is required", "destination_host")
    domain = Domain(name=name, description="", active=True, destination_port=25, use_mx=False,
                    recipient_check="any", quarantine_enabled=True, link_protection=False)
    update_domain(domain, **fields)
    db.session.add(domain)
    return domain


def update_domain(domain, **changes):
    """Apply changes to the fields in DOMAIN_FIELDS (the name cannot change)."""
    unknown = sorted(set(changes) - set(DOMAIN_FIELDS))
    if unknown:
        raise ServiceError(f"Unknown field {unknown[0]}", unknown[0])
    if "description" in changes:
        domain.description = _text(changes["description"], "description")
    for field in ("active", "use_mx", "quarantine_enabled", "link_protection"):
        if field in changes:
            setattr(domain, field, _bool(changes[field], field))
    if "destination_host" in changes:
        domain.destination_host = _normalized(v.normalize_host, changes["destination_host"], "destination_host")
    if "destination_port" in changes:
        domain.destination_port = _int(changes["destination_port"], "destination_port", 1, 65535)
    if "recipient_check" in changes:
        domain.recipient_check = _choice(changes["recipient_check"], "recipient_check", RECIPIENT_CHECKS)
    if "directory_id" in changes:
        value = changes["directory_id"]
        directory = None
        if value is not None:
            directory = db.session.get(Directory, value) if isinstance(value, int) and \
                not isinstance(value, bool) else None
            if directory is None:
                raise ServiceError("There is no such directory", "directory_id")
        domain.directory = directory
    if domain.recipient_check == "directory" and domain.directory is None:
        raise ServiceError("Choose the directory the recipients come from", "directory_id")
    if "digest_interval" in changes:
        domain.digest_interval = _choice(changes["digest_interval"] or None, "digest_interval", DIGEST_INTERVALS,
                                         nullable=True)
    if domain.use_mx and v.is_ip_address(domain.destination_host or ""):
        raise ServiceError("MX lookup is not possible for an IP address", "use_mx")
    scores = {f: _score(changes[f], f) for f in SCORE_FIELDS if f in changes}
    if scores:
        merged = {f: scores[f] if f in scores else getattr(domain, f) for f in SCORE_FIELDS}
        defaults = global_scores()
        check_threshold_order({f: defaults[f] if merged[f] is None else merged[f] for f in SCORE_FIELDS},
                              " (including global defaults)")
        for field, value in scores.items():
            setattr(domain, field, value)
    touch_config()
    return domain


def delete_domain(domain):
    """Recipients, list entries, mailbox users and the DKIM key go with it."""
    db.session.delete(domain)
    touch_config()


# ---------------------------------------------------------------------------
# Recipients (read by Postfix directly, no map to write)
# ---------------------------------------------------------------------------

def add_recipients(domain, addresses):
    """Addresses or local parts of ``domain``.

    Returns {"added": [addresses], "skipped": number already present,
    "invalid": [inputs that are no valid address of the domain]}.
    """
    result = {"added": [], "skipped": 0, "invalid": []}
    existing = {r.address for r in Recipient.query.with_entities(Recipient.address)}
    for raw in addresses:
        line = raw.strip() if isinstance(raw, str) else ""
        if not line:
            if not isinstance(raw, str):
                result["invalid"].append(str(raw))
            continue
        candidate = line if "@" in line else f"{line}@{domain.name}"
        try:
            address = v.normalize_email(candidate)
        except v.ValidationError:
            result["invalid"].append(line)
            continue
        if not address.endswith("@" + domain.name):
            result["invalid"].append(line)
            continue
        if address in existing:
            result["skipped"] += 1
            continue
        db.session.add(Recipient(domain=domain, address=address))
        existing.add(address)
        result["added"].append(address)
    return result


def delete_recipients(domain, ids):
    """Returns the number of deleted recipients."""
    if not ids:
        return 0
    return (Recipient.query.filter(Recipient.domain_id == domain.id, Recipient.id.in_(ids))
            .delete(synchronize_session=False))


# ---------------------------------------------------------------------------
# Allow/block lists of the administrators: global or per domain
# ---------------------------------------------------------------------------

def global_list_entries():
    """Query for the global entries (personal entries of mailbox users have
    no domain either, but must never apply to everyone)."""
    return ListEntry.query.filter(ListEntry.domain_id.is_(None), ListEntry.mailbox_user_id.is_(None))


def domain_list_entries(domain):
    return ListEntry.query.filter(ListEntry.domain_id == domain.id)


def add_list_entry(list_type, kind, value, comment="", domain=None):
    """Global entry, or an entry of ``domain``. Senders may be patterns
    (see validators.normalize_sender_pattern), IPs may be networks."""
    list_type = _choice(list_type, "list_type", LIST_TYPES)
    kind = _choice(kind, "kind", LIST_KINDS)
    value = _normalized(v.normalize_network if kind == "ip" else v.normalize_sender_pattern, value, "value")
    comment = _text(comment, "comment")
    query = domain_list_entries(domain) if domain is not None else global_list_entries()
    if query.filter_by(list_type=list_type, kind=kind, value=value).first():
        raise ServiceError("This entry already exists", "value", status=409)
    entry = ListEntry(domain=domain, list_type=list_type, kind=kind, value=value, comment=comment)
    db.session.add(entry)
    touch_config()
    return entry


def delete_list_entry(entry):
    db.session.delete(entry)
    touch_config()


# ---------------------------------------------------------------------------
# Relay networks
# ---------------------------------------------------------------------------

def add_relay_network(cidr, comment=""):
    cidr = _normalized(v.normalize_network, cidr, "cidr")
    if RelayNetwork.query.filter_by(cidr=cidr).first():
        raise ServiceError("This network already exists", "cidr", status=409)
    network = RelayNetwork(cidr=cidr, comment=_text(comment, "comment"))
    db.session.add(network)
    return network


def delete_relay_network(network):
    db.session.delete(network)


# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------

SETTINGS = ("greylist_score", "add_header_score", "reject_score", "quarantine_retention_days",
            "quarantine_max_size_mb", "quarantine_outbound", "maillog_retention_days", "max_message_size_mb",
            "max_attachment_size_mb", "require_admin_2fa", "audit_retention_days", "digest_interval",
            "digest_sender", "digest_token_days", "mailbox_auto_create", "mailbox_invite_days", "virus_scanning",
            "ptr_check", "admin_allowed_networks", "timezone", "session_lifetime_minutes", "login_max_failures",
            "login_max_account_failures", "login_failure_window_minutes", "http_redirect", "rspamd_ui_networks",
            "trusted_proxies", "spamhaus_dqs_key", "postfix_log_lines")
PTR_CHECKS = ("off", "defer", "reject")
UPDATE_SETTINGS = ("update_channel", "update_branch")
UPDATE_CHANNELS = ("release", "main")
_WEBHOOK_RE = re.compile(r"^https?://[^\s\"'`\\]+$")
_BRANCH_RE = re.compile(r"^[A-Za-z0-9._][A-Za-z0-9._/-]{0,99}$")
WATCHDOG_SETTINGS = ("watchdog_notify_email", "watchdog_notify_webhook", "watchdog_notify_webhook_body",
                     "watchdog_subject", "watchdog_notify_start", "watchdog_notify_ban")

# Edited on the Backups and Outbound limits pages; the API's settings have all
BACKUP_SETTINGS = ("backup_keep", "backup_include_mail_log", "backup_include_quarantine")
OUTBOUND_SETTINGS = ("outbound_limit", "outbound_limit_period")
# Rate limits page (services/ratelimits.py)
SMTP_LIMIT_SETTINGS = ("smtp_connection_count_limit", "smtp_connection_rate_limit", "smtp_message_rate_limit",
                       "smtp_recipient_rate_limit")
INBOUND_LIMIT_SETTINGS = ("inbound_ip_limit", "inbound_ip_period", "inbound_rcpt_limit", "inbound_rcpt_period",
                          "inbound_bounce_limit", "inbound_bounce_period")
RATE_LIMIT_SETTINGS = SMTP_LIMIT_SETTINGS + INBOUND_LIMIT_SETTINGS + ("rate_limit_exempt",)
MAX_SMTP_RATE = 100_000
MAX_EXEMPT_NETWORKS = 500
ATTACHMENT_SETTINGS = ("attachment_blocked_extensions", "attachment_scan_archives", "attachment_block_encrypted",
                       "attachment_outbound", "attachment_exempt_senders")
IMPERSONATION_SETTINGS = ("impersonation_name_score", "impersonation_lookalike_score", "impersonation_spoof_score",
                          "impersonation_extra_domains", "impersonation_exempt_domains")
HASHCHECK_SETTINGS = ("hashcheck_mhr", "hashcheck_mhr_percent", "hashcheck_mhr_score", "hashcheck_mb_key",
                      "hashcheck_mb_score", "hashcheck_vt_key", "hashcheck_vt_engines", "hashcheck_vt_score",
                      "hashcheck_vt_per_minute")
# never returned: get_settings gives <key>_set instead
SECRET_SETTINGS = ("hashcheck_mb_key", "hashcheck_vt_key", "spamhaus_dqs_key")
REPORT_SETTINGS = ("report_retention_days", "dmarc_send_reports")
STATS_SETTINGS = ("stats_retention_days",)
USER_REPORT_SETTINGS = ("user_reports_enabled", "user_reports_confirm", "user_reports_per_hour")
MONITORING_SETTINGS = ("siem_host", "siem_port", "siem_protocol", "siem_format", "siem_verify_tls", "siem_mail_log",
                       "siem_audit", "alert_recipients", "alert_deferred_count", "alert_deferred_hours",
                       "alert_cert_days", "alert_backup_hours")
JOURNAL_SETTINGS = ("journal_address", "journal_inbound", "journal_outbound", "journal_rejected", "journal_format")
JOURNAL_FORMATS = ("envelope", "copy")
SIEM_PROTOCOLS = ("udp", "tcp", "tls")
SIEM_FORMATS = ("json", "rfc5424")
LINK_SETTINGS = ("link_protection_exempt_hosts", "link_protection_block_domains", "link_protection_allow_continue",
                 "link_protection_days")
ALL_SETTINGS = (SETTINGS + BACKUP_SETTINGS + OUTBOUND_SETTINGS + RATE_LIMIT_SETTINGS + ATTACHMENT_SETTINGS
                + IMPERSONATION_SETTINGS
                + LINK_SETTINGS + HASHCHECK_SETTINGS + REPORT_SETTINGS + STATS_SETTINGS + MONITORING_SETTINGS
                + JOURNAL_SETTINGS + USER_REPORT_SETTINGS + UPDATE_SETTINGS + WATCHDOG_SETTINGS)
BOOLEAN_SETTINGS = ("quarantine_outbound", "require_admin_2fa", "backup_include_mail_log", "backup_include_quarantine",
                    "attachment_scan_archives", "attachment_block_encrypted", "attachment_outbound",
                    "link_protection_allow_continue", "hashcheck_mhr", "dmarc_send_reports", "siem_verify_tls",
                    "siem_mail_log", "siem_audit", "journal_inbound", "journal_outbound", "journal_rejected",
                    "user_reports_enabled", "user_reports_confirm", "mailbox_auto_create", "virus_scanning",
                    "http_redirect", "watchdog_notify_start", "watchdog_notify_ban")
MAX_EXTENSIONS = 500
MAX_EXEMPT_SENDERS = 500
_EXTENSION_RE = re.compile(r"^[a-z0-9_~$-]{1,32}$")


def _network_list(value, field, allow_any=False):
    """Networks (CIDR) or addresses, one per line, as stored: normalized, sorted."""
    value = value if value is not None else ""
    if not isinstance(value, str):
        raise ServiceError(f"{field} must be text", field)
    networks = set()
    for item in re.split(r"[\s,;]+", value):
        if not item:
            continue
        try:
            networks.add(ipaddress.ip_network(item, strict=False))
        except ValueError:
            raise ServiceError(f"{item} is not a network or an address", field) from None
    if len(networks) > MAX_EXEMPT_NETWORKS:
        raise ServiceError(f"At most {MAX_EXEMPT_NETWORKS} networks", field)
    if not allow_any and any(n.prefixlen == 0 for n in networks):
        raise ServiceError("Every address cannot be exempt: that turns the rate limits off", field)
    return "\n".join(str(n) for n in sorted(networks, key=lambda n: (n.version, n)))


def _timezone(value):
    """An IANA time zone name, or empty (the system's)."""
    value = (value or "").strip() if isinstance(value, (str, type(None))) else None
    if value is None:
        raise ServiceError("timezone must be text", "timezone")
    if value and value not in timezones():
        raise ServiceError(f"{value} is not a time zone", "timezone")
    return value


def timezones():
    """The IANA time zone names Python knows, sorted (with UTC)."""
    import zoneinfo
    return sorted(zoneinfo.available_timezones() | {"UTC"})


def _extensions(value):
    """File extensions as stored: lower case, without dots, sorted, space-separated."""
    if not isinstance(value, str):
        raise ServiceError("attachment_blocked_extensions must be text", "attachment_blocked_extensions")
    items = sorted({item.strip().lstrip("*").lstrip(".").lower() for item in re.split(r"[\s,;]+", value)} - {""})
    bad = [item for item in items if not _EXTENSION_RE.match(item)]
    if bad:
        raise ServiceError(f"{bad[0]} is not a file extension", "attachment_blocked_extensions")
    if len(items) > MAX_EXTENSIONS:
        raise ServiceError(f"At most {MAX_EXTENSIONS} extensions", "attachment_blocked_extensions")
    return " ".join(items)


def _domain_list(value, field):
    """Domains, one per line as stored."""
    if not isinstance(value, str):
        raise ServiceError(f"{field} must be text", field)
    items = set()
    for item in re.split(r"[\s,;]+", value):
        if item.strip():
            items.add(_normalized(v.normalize_domain, item, field))
    if len(items) > MAX_EXEMPT_SENDERS:
        raise ServiceError(f"At most {MAX_EXEMPT_SENDERS} domains", field)
    return "\n".join(sorted(items))


def _sender_list(value, field):
    """Addresses and domains, one per line as stored."""
    if not isinstance(value, str):
        raise ServiceError(f"{field} must be text", field)
    items = sorted({normalize_sender(item) for item in re.split(r"[\s,;]+", value) if item.strip()})
    if len(items) > MAX_EXEMPT_SENDERS:
        raise ServiceError(f"At most {MAX_EXEMPT_SENDERS} senders", field)
    return "\n".join(items)


def get_settings():
    data = {key: get_setting(key) for key in ALL_SETTINGS}
    for key in BOOLEAN_SETTINGS:
        data[key] = bool(data[key])
    for key in SECRET_SETTINGS:
        data[f"{key}_set"] = bool(data.pop(key))
    return data


def update_settings(**changes):
    unknown = sorted(set(changes) - set(ALL_SETTINGS))
    if unknown:
        raise ServiceError(f"Unknown setting {unknown[0]}", unknown[0])
    values = {}
    for field in SCORE_FIELDS:
        if field in changes:
            if changes[field] is None:
                raise ServiceError("Global thresholds cannot be empty", field)
            values[field] = _score(changes[field], field)
    if values:
        check_threshold_order({f: values.get(f, get_setting(f)) for f in SCORE_FIELDS})
    if "quarantine_retention_days" in changes:
        values["quarantine_retention_days"] = _int(changes["quarantine_retention_days"],
                                                   "quarantine_retention_days", 1, 3650)
    if "quarantine_max_size_mb" in changes:
        values["quarantine_max_size_mb"] = _int(changes["quarantine_max_size_mb"], "quarantine_max_size_mb", 1, 100)
    if "maillog_retention_days" in changes:
        values["maillog_retention_days"] = _int(changes["maillog_retention_days"], "maillog_retention_days", 1,
                                                MAX_MAILLOG_DAYS)
    for field, low in (("max_message_size_mb", 1), ("max_attachment_size_mb", 0)):
        if field in changes:
            values[field] = _int(changes[field], field, low, MAX_MESSAGE_MB)
    if {"max_message_size_mb", "max_attachment_size_mb"} & set(values):
        message = values.get("max_message_size_mb", get_setting("max_message_size_mb"))
        attachment = values.get("max_attachment_size_mb", get_setting("max_attachment_size_mb"))
        if attachment > message:
            raise ServiceError("The attachment limit cannot exceed the message size limit "
                               f"({message} MiB)", "max_attachment_size_mb")
    if "quarantine_outbound" in changes:
        values["quarantine_outbound"] = int(_bool(changes["quarantine_outbound"], "quarantine_outbound"))
    if "audit_retention_days" in changes:
        values["audit_retention_days"] = _int(changes["audit_retention_days"], "audit_retention_days", 30, 3650)
    for key in ("require_admin_2fa", "backup_include_mail_log", "backup_include_quarantine",
                "attachment_scan_archives", "attachment_block_encrypted", "attachment_outbound",
                "link_protection_allow_continue", "hashcheck_mhr", "dmarc_send_reports", "siem_verify_tls",
                "siem_mail_log", "siem_audit", "journal_inbound", "journal_outbound", "journal_rejected",
                "user_reports_enabled", "user_reports_confirm", "mailbox_auto_create", "virus_scanning",
                "http_redirect", "watchdog_notify_start", "watchdog_notify_ban"):
        if key in changes:
            values[key] = int(_bool(changes[key], key))
    if "mailbox_invite_days" in changes:
        values["mailbox_invite_days"] = _int(changes["mailbox_invite_days"], "mailbox_invite_days", 1, 30)
    if "ptr_check" in changes:
        values["ptr_check"] = _choice(changes["ptr_check"], "ptr_check", PTR_CHECKS)
    if "admin_allowed_networks" in changes:
        values["admin_allowed_networks"] = _network_list(changes["admin_allowed_networks"],
                                                         "admin_allowed_networks", allow_any=True)
    if "timezone" in changes:
        values["timezone"] = _timezone(changes["timezone"])
    for key, low, high in (("session_lifetime_minutes", 5, 7 * 24 * 60), ("login_max_failures", 1, 1000),
                           ("login_max_account_failures", 1, 10000), ("login_failure_window_minutes", 1, 24 * 60),
                           ("postfix_log_lines", 100, 1_000_000)):
        if key in changes:
            values[key] = _int(changes[key], key, low, high)
    for key in ("rspamd_ui_networks", "trusted_proxies"):
        if key in changes:
            values[key] = _network_list(changes[key], key, allow_any=True)
    if "update_channel" in changes:
        values["update_channel"] = _choice(changes["update_channel"], "update_channel", UPDATE_CHANNELS)
    if "update_branch" in changes:
        branch = changes["update_branch"].strip() if isinstance(changes["update_branch"], str) else None
        if not branch or not _BRANCH_RE.match(branch) or ".." in branch:
            raise ServiceError("update_branch must be a branch name", "update_branch")
        values["update_branch"] = branch
    if "watchdog_notify_email" in changes:
        value = changes["watchdog_notify_email"] if changes["watchdog_notify_email"] is not None else ""
        if not isinstance(value, str):
            raise ServiceError("watchdog_notify_email must be text", "watchdog_notify_email")
        values["watchdog_notify_email"] = "\n".join(sorted({
            _normalized(v.normalize_email, item, "watchdog_notify_email") for item in re.split(r"[\s,;]+", value)
            if item.strip()}))
    if "watchdog_notify_webhook" in changes:
        url = (changes["watchdog_notify_webhook"] or "").strip() if isinstance(
            changes["watchdog_notify_webhook"], (str, type(None))) else None
        if url is None or len(url) > 500 or (url and not _WEBHOOK_RE.match(url)):
            raise ServiceError("watchdog_notify_webhook must be an http(s) URL without spaces",
                               "watchdog_notify_webhook")
        values["watchdog_notify_webhook"] = url
    if "watchdog_notify_webhook_body" in changes:
        body = _text(changes["watchdog_notify_webhook_body"], "watchdog_notify_webhook_body", 2000)
        if body:
            try:
                json.loads(body.replace("${SUBJECT}", "").replace("${BODY}", ""))
            except ValueError:
                raise ServiceError("watchdog_notify_webhook_body must be JSON", "watchdog_notify_webhook_body") \
                    from None
        values["watchdog_notify_webhook_body"] = " ".join(body.split())
    if "watchdog_subject" in changes:
        subject = _text(changes["watchdog_subject"], "watchdog_subject", 100)
        if not subject:
            raise ServiceError("watchdog_subject cannot be empty", "watchdog_subject")
        values["watchdog_subject"] = " ".join(subject.split())
    if "backup_keep" in changes:
        values["backup_keep"] = _int(changes["backup_keep"], "backup_keep", 1, 90)
    for key in ("impersonation_name_score", "impersonation_lookalike_score", "impersonation_spoof_score"):
        if key in changes:
            value = changes[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1000:
                raise ServiceError(f"{key} must be a number from 0 to 1000", key)
            values[key] = float(value)
    for key, low, high in (("hashcheck_mhr_percent", 1, 100), ("hashcheck_vt_engines", 1, 100),
                           ("hashcheck_vt_per_minute", 1, 1000)):
        if key in changes:
            values[key] = _int(changes[key], key, low, high)
    for key in ("hashcheck_mhr_score", "hashcheck_mb_score", "hashcheck_vt_score"):
        if key in changes:
            value = changes[key]
            if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1000:
                raise ServiceError(f"{key} must be a number from 0 to 1000", key)
            values[key] = float(value)
    if "spamhaus_dqs_key" in changes:
        value = (changes["spamhaus_dqs_key"] if changes["spamhaus_dqs_key"] is not None else "")
        if not isinstance(value, str) or not re.match(r"^[A-Za-z0-9]{0,64}$", value.strip()):
            raise ServiceError("spamhaus_dqs_key must be a key of letters and digits", "spamhaus_dqs_key")
        values["spamhaus_dqs_key"] = value.strip()
    for key in ("hashcheck_mb_key", "hashcheck_vt_key"):
        if key in changes:
            value = changes[key] if changes[key] is not None else ""
            if not isinstance(value, str) or len(value.strip()) > 200 or not re.match(r"^[\x21-\x7e]*$",
                                                                                      value.strip()):
                raise ServiceError(f"{key} must be an API key (printable characters, no spaces)", key)
            values[key] = value.strip()
    if "user_reports_per_hour" in changes:
        values["user_reports_per_hour"] = _int(changes["user_reports_per_hour"], "user_reports_per_hour", 1, 10000)
    if "journal_address" in changes:
        address = changes["journal_address"] if changes["journal_address"] is not None else ""
        values["journal_address"] = (_normalized(v.normalize_email, address, "journal_address")
                                     if str(address).strip() else "")
    if "journal_format" in changes:
        values["journal_format"] = _choice(changes["journal_format"], "journal_format", JOURNAL_FORMATS)
    if "siem_host" in changes:
        host = changes["siem_host"] if changes["siem_host"] is not None else ""
        values["siem_host"] = _normalized(v.normalize_host, host, "siem_host") if str(host).strip() else ""
    if "siem_port" in changes:
        values["siem_port"] = _int(changes["siem_port"], "siem_port", 1, 65535)
    if "siem_protocol" in changes:
        values["siem_protocol"] = _choice(changes["siem_protocol"], "siem_protocol", SIEM_PROTOCOLS)
    if "siem_format" in changes:
        values["siem_format"] = _choice(changes["siem_format"], "siem_format", SIEM_FORMATS)
    if "alert_recipients" in changes:
        value = changes["alert_recipients"] if changes["alert_recipients"] is not None else ""
        if not isinstance(value, str):
            raise ServiceError("alert_recipients must be text", "alert_recipients")
        values["alert_recipients"] = "\n".join(sorted({
            _normalized(v.normalize_email, item, "alert_recipients") for item in re.split(r"[\s,;]+", value)
            if item.strip()}))
    for key, low, high in (("alert_deferred_count", 1, 1_000_000), ("alert_deferred_hours", 1, 240),
                           ("alert_cert_days", 1, 90), ("alert_backup_hours", 1, 24 * 30)):
        if key in changes:
            values[key] = _int(changes[key], key, low, high)
    if "stats_retention_days" in changes:
        values["stats_retention_days"] = _int(changes["stats_retention_days"], "stats_retention_days", 30, 3650)
    if "report_retention_days" in changes:
        values["report_retention_days"] = _int(changes["report_retention_days"], "report_retention_days", 7, 3650)
    if "link_protection_days" in changes:
        values["link_protection_days"] = _int(changes["link_protection_days"], "link_protection_days", 1, 3650)
    for key in ("impersonation_extra_domains", "impersonation_exempt_domains", "link_protection_exempt_hosts",
                "link_protection_block_domains"):
        if key in changes:
            values[key] = _domain_list(changes[key], key)
    if "attachment_blocked_extensions" in changes:
        values["attachment_blocked_extensions"] = _extensions(changes["attachment_blocked_extensions"])
    if "attachment_exempt_senders" in changes:
        try:
            values["attachment_exempt_senders"] = _sender_list(changes["attachment_exempt_senders"],
                                                               "attachment_exempt_senders")
        except ServiceError as exc:
            raise ServiceError(str(exc), "attachment_exempt_senders") from None
    if "outbound_limit" in changes:
        values["outbound_limit"] = _int(changes["outbound_limit"], "outbound_limit", 0, MAX_OUTBOUND_LIMIT)
    if "outbound_limit_period" in changes:
        values["outbound_limit_period"] = _choice(changes["outbound_limit_period"], "outbound_limit_period",
                                                  LIMIT_PERIODS)
    if "smtp_connection_count_limit" in changes:
        values["smtp_connection_count_limit"] = _int(changes["smtp_connection_count_limit"],
                                                     "smtp_connection_count_limit", 0, 1000)
    for key in SMTP_LIMIT_SETTINGS[1:]:
        if key in changes:
            values[key] = _int(changes[key], key, 0, MAX_SMTP_RATE)
    for kind in ("ip", "rcpt", "bounce"):
        if f"inbound_{kind}_limit" in changes:
            values[f"inbound_{kind}_limit"] = _int(changes[f"inbound_{kind}_limit"], f"inbound_{kind}_limit", 0,
                                                   MAX_OUTBOUND_LIMIT)
        if f"inbound_{kind}_period" in changes:
            values[f"inbound_{kind}_period"] = _choice(changes[f"inbound_{kind}_period"], f"inbound_{kind}_period",
                                                       LIMIT_PERIODS)
    if "rate_limit_exempt" in changes:
        values["rate_limit_exempt"] = _network_list(changes["rate_limit_exempt"], "rate_limit_exempt")
    if "digest_interval" in changes:
        values["digest_interval"] = _choice(changes["digest_interval"], "digest_interval", DIGEST_INTERVALS)
    if "digest_sender" in changes:
        sender = changes["digest_sender"] or ""
        values["digest_sender"] = _normalized(v.normalize_email, sender, "digest_sender") if sender else ""
    if "digest_token_days" in changes:
        values["digest_token_days"] = _int(changes["digest_token_days"], "digest_token_days", 1, 30)
    for key, value in values.items():
        set_setting(key, value)
    touch_config()
    return get_settings()


# ---------------------------------------------------------------------------
# DKIM keys
# ---------------------------------------------------------------------------

def set_dkim_key(domain, selector, key_size=None, private_key=None):
    """Generate a key (``key_size``) or import one (``private_key``, PEM).
    Replaces the domain's key. Returns True if a key was replaced."""
    if (key_size is None) == (private_key is None):
        raise ServiceError("Give either key_size (generate a key) or private_key (import one)", "private_key")
    try:
        selector = dkim.validate_selector(selector if isinstance(selector, str) else "")
    except dkim.DkimError as exc:
        raise ServiceError(str(exc), "selector")
    try:
        if private_key is not None:
            if not isinstance(private_key, str):
                raise dkim.DkimError("private_key must be text")
            pem, size = dkim.import_private_key(private_key)
        else:
            if isinstance(key_size, bool) or key_size not in dkim.KEY_SIZES:
                raise ServiceError(f"key_size must be one of {', '.join(map(str, dkim.KEY_SIZES))}", "key_size")
            pem, size = dkim.generate_private_key(key_size)
    except dkim.DkimError as exc:
        raise ServiceError(str(exc), "private_key" if private_key is not None else "key_size")
    replaced = domain.dkim_key is not None
    if replaced:
        db.session.delete(domain.dkim_key)
        db.session.flush()
    domain.dkim_key = DkimKey(selector=selector, private_key=pem, key_size=size)
    return replaced


def delete_dkim_key(domain):
    if domain.dkim_key is None:
        raise ServiceError("This domain has no DKIM key", status=404)
    db.session.delete(domain.dkim_key)
