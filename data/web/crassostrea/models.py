"""Database schema.

The ``domains`` and ``recipients`` tables are read directly by Postfix
(see system/libexec/postfix-setup), keep column names in sync.
"""
import hashlib
import json
import secrets
import time
from datetime import datetime, timezone

from flask_login import UserMixin
from sqlalchemy.dialects import mysql
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def utcnow():
    return datetime.now(timezone.utc).replace(tzinfo=None)


admin_domains = db.Table(
    "admin_domains",
    db.Column("admin_id", db.Integer, db.ForeignKey("admins.id", ondelete="CASCADE"), primary_key=True),
    db.Column("domain_id", db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), primary_key=True),
)

# Administrators: "admin" manages everything, "domain" only the mail of its
# domains (quarantine, mail log, domain settings, mailbox users, statistics,
# reports); views/__init__.py protected_blueprint(domain_admins=...)
ADMIN_ROLES = {"admin": "Administrator", "domain": "Domain administrator"}


class Admin(UserMixin, db.Model):
    __tablename__ = "admins"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime)
    # Two-factor login (services/twofactor.py): base32 TOTP secret, time step
    # of the last accepted code, hashes of the unused recovery codes (JSON)
    totp_secret = db.Column(db.String(64))
    totp_enabled_at = db.Column(db.DateTime)
    totp_last_step = db.Column(db.BigInteger)
    recovery_codes = db.Column(db.Text)
    role = db.Column(db.String(16), nullable=False, default="admin")

    domains = db.relationship("Domain", secondary=admin_domains, order_by="Domain.name",
                              backref=db.backref("admins", order_by="Admin.username"))

    is_admin = True

    @property
    def is_full_admin(self):
        return self.role != "domain"

    @property
    def domain_scope(self):
        """The domain names a domain administrator manages; None: all."""
        return None if self.is_full_admin else {d.name for d in self.domains}

    @property
    def is_active(self):
        return self.active

    def get_id(self):
        # Prefixed so admin and mailbox user sessions can never be confused
        return f"admin:{self.id}"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class MailboxUser(UserMixin, db.Model):
    """End user who manages the inbound quarantine of one address."""
    __tablename__ = "mailbox_users"

    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(320), unique=True, nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_login_at = db.Column(db.DateTime)
    # Created for quarantined mail (services/invites.py): when the link to set
    # the password was sent; NULL once the user set it
    invited_at = db.Column(db.DateTime)

    # Personal spam thresholds, NULL = domain/global value
    reject_score = db.Column(db.Float)
    add_header_score = db.Column(db.Float)
    greylist_score = db.Column(db.Float)
    # Quarantine digest interval, NULL = domain/global value
    digest_interval = db.Column(db.String(16))

    # ORM cascade (not passive): the entries go with the user in any database
    list_entries = db.relationship("ListEntry", backref="mailbox_user", cascade="all, delete-orphan")

    is_admin = False
    is_full_admin = False

    @property
    def has_custom_scores(self):
        return any(v is not None for v in (self.reject_score, self.add_header_score, self.greylist_score))

    @property
    def username(self):
        return self.email

    @property
    def is_active(self):
        return self.active

    def get_id(self):
        return f"user:{self.id}"

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        """Also imported hashes of other systems (passwords.py); a right
        password replaces one with scrypt (the caller commits)."""
        from . import passwords
        if not passwords.verify(self.password_hash, password):
            return False
        if passwords.needs_upgrade(self.password_hash):
            self.set_password(password)
        return True


RECIPIENT_CHECKS = {
    "any": "Accept all recipients",
    "list": "Only recipients from the list",
    "verify": "Verify with the downstream server (SMTP call-ahead)",
    "directory": "Only recipients from a directory (LDAP, Active Directory, Microsoft 365)",
}


class Domain(db.Model):
    __tablename__ = "domains"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(253), unique=True, nullable=False)
    description = db.Column(db.String(255), nullable=False, default="")
    active = db.Column(db.Boolean, nullable=False, default=True)

    # Where clean mail is delivered to
    destination_host = db.Column(db.String(255), nullable=False)
    destination_port = db.Column(db.Integer, nullable=False, default=25)
    use_mx = db.Column(db.Boolean, nullable=False, default=False)

    recipient_check = db.Column(db.String(16), nullable=False, default="any")
    # recipient_check "directory": the recipients are synchronised from it
    directory_id = db.Column(db.Integer, db.ForeignKey("directories.id"), nullable=True)
    quarantine_enabled = db.Column(db.Boolean, nullable=False, default=True)
    # links of inbound mail are checked when clicked (services/links.py)
    link_protection = db.Column(db.Boolean, nullable=False, default=False)

    # Per-domain spam thresholds, NULL = use the global value
    reject_score = db.Column(db.Float)
    add_header_score = db.Column(db.Float)
    greylist_score = db.Column(db.Float)

    # Quarantine digest interval, NULL = global value
    digest_interval = db.Column(db.String(16))

    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    recipients = db.relationship(
        "Recipient", backref="domain", cascade="all, delete-orphan",
        passive_deletes=True, order_by="Recipient.address")
    list_entries = db.relationship(
        "ListEntry", backref="domain", cascade="all, delete-orphan",
        passive_deletes=True)
    mailbox_users = db.relationship(
        "MailboxUser", backref="domain", cascade="all, delete-orphan",
        passive_deletes=True, order_by="MailboxUser.email")
    dkim_key = db.relationship(
        "DkimKey", backref="domain", cascade="all, delete-orphan",
        passive_deletes=True, uselist=False)

    @property
    def has_custom_scores(self):
        return any(v is not None for v in (self.reject_score, self.add_header_score, self.greylist_score))

    @property
    def destination(self):
        if self.use_mx:
            return f"MX of {self.destination_host}:{self.destination_port}"
        return f"{self.destination_host}:{self.destination_port}"


class Recipient(db.Model):
    __tablename__ = "recipients"

    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, index=True)
    address = db.Column(db.String(320), unique=True, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    # "manual", or "directory": added and removed by the directory sync
    source = db.Column(db.String(16), nullable=False, default="manual")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


DIRECTORY_KINDS = {"ldap": "LDAP or Active Directory", "m365": "Microsoft 365"}


class Directory(db.Model):
    """Where the valid recipients of domains come from (services/directory.py):
    an LDAP server (Active Directory, OpenLDAP) or a Microsoft 365 tenant."""
    __tablename__ = "directories"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    kind = db.Column(db.String(16), nullable=False)
    # LDAP: one or more URLs (failover), STARTTLS on ldap://, certificate check
    ldap_urls = db.Column(db.String(1000), nullable=False, default="")
    ldap_starttls = db.Column(db.Boolean, nullable=False, default=False)
    ldap_verify = db.Column(db.Boolean, nullable=False, default=True)
    bind_dn = db.Column(db.String(500), nullable=False, default="")
    bind_password = db.Column(db.String(500), nullable=False, default="")
    base_dn = db.Column(db.String(500), nullable=False, default="")
    ldap_filter = db.Column(db.String(1000), nullable=False, default="")
    # attributes with addresses, space-separated (proxyAddresses: only smtp:)
    ldap_attributes = db.Column(db.String(500), nullable=False, default="")
    # Microsoft 365 (Graph, application permissions User.Read.All, Group.Read.All)
    tenant_id = db.Column(db.String(253), nullable=False, default="")
    client_id = db.Column(db.String(64), nullable=False, default="")
    client_secret = db.Column(db.String(500), nullable=False, default="")
    # Last synchronisation
    synced_at = db.Column(db.DateTime)
    sync_error = db.Column(db.Text, nullable=False, default="")
    sync_count = db.Column(db.Integer)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    domains = db.relationship("Domain", backref="directory", order_by="Domain.name")


class DkimKey(db.Model):
    """Key used to sign outbound mail of a domain (see services/dkim.py)."""
    __tablename__ = "dkim_keys"

    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), nullable=False, unique=True)
    selector = db.Column(db.String(63), nullable=False)
    # PEM, PKCS#1. Stored like every other secret of the stack (DB credentials,
    # rspamd password) - protect database backups accordingly.
    private_key = db.Column(db.Text, nullable=False)
    key_size = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


LIST_TYPES = {"allow": "Allow", "block": "Block"}
LIST_KINDS = {"sender": "Sender address", "ip": "IP address / network"}


class ListEntry(db.Model):
    """Allow/block list entry.

    Scope: ``domain_id`` set = domain, ``mailbox_user_id`` set = one mailbox
    user, both NULL = global.
    """
    __tablename__ = "list_entries"

    id = db.Column(db.Integer, primary_key=True)
    list_type = db.Column(db.String(8), nullable=False)
    kind = db.Column(db.String(8), nullable=False)
    value = db.Column(db.String(255), nullable=False)
    domain_id = db.Column(db.Integer, db.ForeignKey("domains.id", ondelete="CASCADE"), index=True)
    mailbox_user_id = db.Column(db.Integer, db.ForeignKey("mailbox_users.id", ondelete="CASCADE"), index=True)
    comment = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class RelayNetwork(db.Model):
    """Networks allowed to relay outbound mail through the gateway."""
    __tablename__ = "relay_networks"

    id = db.Column(db.Integer, primary_key=True)
    cidr = db.Column(db.String(64), unique=True, nullable=False)
    comment = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class OutboundLimit(db.Model):
    """A sending limit for one sender address or the senders of a domain,
    instead of the default (setting outbound_limit). Counted by
    data/conf/rspamd/lua/rspamd.local.lua from outbound_limits.map."""
    __tablename__ = "outbound_limits"

    id = db.Column(db.Integer, primary_key=True)
    # an address, or a domain for each of its senders
    sender = db.Column(db.String(255), unique=True, nullable=False)
    # recipients per period; 0: no limit
    max_recipients = db.Column(db.Integer, nullable=False)
    period = db.Column(db.String(16), nullable=False, default="hour")
    comment = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class DlpRule(db.Model):
    """An outbound data loss prevention rule, checked by
    data/conf/rspamd/lua/rspamd.local.lua (dlp_rules.json)."""
    __tablename__ = "dlp_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    # services/dlp.py DETECTORS; pattern: keywords (one per line) or a regex
    detector = db.Column(db.String(32), nullable=False)
    pattern = db.Column(db.Text, nullable=False, default="")
    # different matches needed
    min_matches = db.Column(db.Integer, nullable=False, default=1)
    # "": every sender; an address or a domain
    sender = db.Column(db.String(255), nullable=False, default="")
    # services/dlp.py ACTIONS
    action = db.Column(db.String(16), nullable=False, default="quarantine")
    comment = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class ProtectedPerson(db.Model):
    """Someone whose name in the From header of external mail is suspicious
    (services/impersonation.py)."""
    __tablename__ = "protected_people"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(128), unique=True, nullable=False)
    # their own addresses, one per line: mail from them is not flagged
    addresses = db.Column(db.Text, nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class ContentRule(db.Model):
    """A rule of the administrators for a part of a message, checked by
    data/conf/rspamd/lua/rspamd.local.lua (content_rules.json)."""
    __tablename__ = "content_rules"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True, nullable=False)
    active = db.Column(db.Boolean, nullable=False, default=True)
    # services/content_rules.py FIELDS, MATCHES, ACTIONS, DIRECTIONS
    field = db.Column(db.String(16), nullable=False)
    header = db.Column(db.String(128), nullable=False, default="")
    match = db.Column(db.String(16), nullable=False, default="contains")
    value = db.Column(db.String(1000), nullable=False)
    action = db.Column(db.String(16), nullable=False, default="score")
    score = db.Column(db.Float, nullable=False, default=0.0)
    message = db.Column(db.String(255), nullable=False, default="")
    direction = db.Column(db.String(16), nullable=False, default="inbound")
    comment = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class UserReport(db.Model):
    """A message a user sent to spam@ or ham@<hostname> (services/user_reports.py)."""
    __tablename__ = "user_reports"

    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    reporter = db.Column(db.String(320), nullable=False)
    kind = db.Column(db.String(8), nullable=False)
    # learned, refused or empty (no attached message)
    status = db.Column(db.String(16), nullable=False)
    learned = db.Column(db.Integer, nullable=False, default=0)
    subjects = db.Column(db.String(1000), nullable=False, default="")
    detail = db.Column(db.String(1000), nullable=False, default="")


class StatBucket(db.Model):
    """Messages scanned in an hour, per domain, direction and outcome
    (services/stats.py); kept longer than the mail log."""
    __tablename__ = "stats_hourly"
    __table_args__ = (db.UniqueConstraint("hour", "domain", "direction", "category"),)

    id = db.Column(db.Integer, primary_key=True)
    hour = db.Column(db.DateTime, nullable=False, index=True)
    domain = db.Column(db.String(253), nullable=False, default="")
    direction = db.Column(db.String(8), nullable=False)
    category = db.Column(db.String(16), nullable=False)
    messages = db.Column(db.Integer, nullable=False, default=0)
    bytes = db.Column(db.BigInteger, nullable=False, default=0)
    viruses = db.Column(db.Integer, nullable=False, default=0)


class DmarcReport(db.Model):
    """A DMARC aggregate report about a protected domain (services/reports.py)."""
    __tablename__ = "dmarc_reports"
    __table_args__ = (db.UniqueConstraint("org", "report_id"),)

    id = db.Column(db.Integer, primary_key=True)
    org = db.Column(db.String(255), nullable=False)
    report_id = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(253), nullable=False, index=True)
    policy = db.Column(db.String(16), nullable=False, default="")
    begin = db.Column(db.DateTime, nullable=False, index=True)
    end = db.Column(db.DateTime, nullable=False)
    messages = db.Column(db.Integer, nullable=False, default=0)
    passed = db.Column(db.Integer, nullable=False, default=0)
    received_at = db.Column(db.DateTime, nullable=False, default=utcnow)

    records = db.relationship("DmarcRecord", backref="report", cascade="all, delete-orphan", passive_deletes=True)


class DmarcRecord(db.Model):
    """A row of a DMARC report: messages from one source."""
    __tablename__ = "dmarc_records"

    id = db.Column(db.Integer, primary_key=True)
    report_id = db.Column(db.Integer, db.ForeignKey("dmarc_reports.id", ondelete="CASCADE"), nullable=False,
                          index=True)
    source_ip = db.Column(db.String(64), nullable=False)
    count = db.Column(db.Integer, nullable=False)
    disposition = db.Column(db.String(16), nullable=False, default="none")
    # aligned DKIM and SPF results of DMARC (pass/fail)
    dkim = db.Column(db.String(16), nullable=False, default="")
    spf = db.Column(db.String(16), nullable=False, default="")
    header_from = db.Column(db.String(253), nullable=False, default="")
    envelope_from = db.Column(db.String(253), nullable=False, default="")


class TlsReport(db.Model):
    """A TLS report (RFC 8460) about connections to a protected domain's MX."""
    __tablename__ = "tls_reports"
    __table_args__ = (db.UniqueConstraint("org", "report_id", "domain"),)

    id = db.Column(db.Integer, primary_key=True)
    org = db.Column(db.String(255), nullable=False)
    report_id = db.Column(db.String(255), nullable=False)
    domain = db.Column(db.String(253), nullable=False, index=True)
    policy_type = db.Column(db.String(16), nullable=False, default="")
    begin = db.Column(db.DateTime, nullable=False, index=True)
    end = db.Column(db.DateTime, nullable=False)
    successful = db.Column(db.Integer, nullable=False, default=0)
    failed = db.Column(db.Integer, nullable=False, default=0)
    # failure-details as JSON
    failures = db.Column(db.Text, nullable=False, default="[]")
    received_at = db.Column(db.DateTime, nullable=False, default=utcnow)


CONTENT_FIELDS = {"subject": "Subject", "from": "From (name and address)", "envelope_from": "Envelope sender",
                  "recipient": "A recipient", "header": "A header", "body": "The text", "url": "A link",
                  "attachment": "An attachment name"}
CONTENT_MATCHES = {"contains": "contains", "equals": "is", "regex": "matches the regular expression"}
CONTENT_ACTIONS = {"score": "Add a score", "reject": "Reject", "tag": "Deliver with X-Content-Rule"}
CONTENT_DIRECTIONS = {"inbound": "Inbound", "outbound": "Outbound", "both": "Both"}

DLP_DETECTORS = {"credit_card": "Payment card numbers", "iban": "IBANs", "us_ssn": "US social security numbers",
                 "keywords": "Keywords", "regex": "Regular expression"}
DLP_ACTIONS = {"quarantine": "Reject and quarantine", "reject": "Reject", "header": "Deliver with X-DLP-Match"}

# Periods of outbound limits, in seconds
LIMIT_PERIODS = {"minute": 60, "hour": 3600, "day": 86400}
MAX_OUTBOUND_LIMIT = 1_000_000

DIRECTIONS = {"inbound": "Inbound", "outbound": "Outbound"}


class ScanSymbols:
    """Rspamd symbols of a scanned message (``symbols`` column, JSON)."""

    @property
    def symbol_list(self):
        """Symbols as a list of dicts sorted by score (highest first).

        Rspamd sends either a list of objects or a mapping of name -> object.
        """
        try:
            data = json.loads(self.symbols or "[]")
        except ValueError:
            return []
        if isinstance(data, dict):
            data = [dict(v, name=k) if isinstance(v, dict) else {"name": k, "score": v}
                    for k, v in data.items()]
        result = []
        for item in data if isinstance(data, list) else []:
            if not isinstance(item, dict):
                continue
            result.append({
                "name": str(item.get("name", "")),
                "score": float(item.get("score") or 0),
                "options": item.get("options") or [],
            })
        return sorted(result, key=lambda s: s["score"], reverse=True)

    @property
    def is_virus(self):
        return any(s["name"] in ("CLAM_VIRUS", "VIRUS_FOUND") for s in self.symbol_list)


class QuarantineItem(ScanSymbols, db.Model):
    """Rejected message, one row per recipient.

    Inbound: ``domain`` is the protected recipient domain, mailbox users see
    the rows addressed to them. Outbound (sent from a relay network): only
    administrators see these, ``domain`` is the sender's domain.
    """
    __tablename__ = "quarantine"

    id = db.Column(db.Integer, primary_key=True)
    direction = db.Column(db.String(8), nullable=False, default="inbound", server_default="inbound")
    qid = db.Column(db.String(64), nullable=False, default="")
    subject = db.Column(db.String(500), nullable=False, default="")
    sender = db.Column(db.String(320), nullable=False, default="")
    rcpt = db.Column(db.String(320), nullable=False, index=True)
    domain = db.Column(db.String(253), nullable=False, index=True)
    score = db.Column(db.Float, nullable=False, default=0.0)
    action = db.Column(db.String(32), nullable=False, default="")
    ip = db.Column(db.String(64), nullable=False, default="")
    symbols = db.Column(db.Text, nullable=False, default="[]")
    size = db.Column(db.Integer, nullable=False, default=0)
    message = db.deferred(db.Column(db.LargeBinary().with_variant(mysql.LONGBLOB(), "mysql"), nullable=False))
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    released_at = db.Column(db.DateTime)
    released_by = db.Column(db.String(64))


class MailLogEntry(ScanSymbols, db.Model):
    """Every message Rspamd scanned for a protected domain or from a relay
    network, one row per message (all recipients), with the message as
    scanned. Also recipients Postfix refused because they do not exist
    (reject_reason set): no message, nothing scanned."""
    __tablename__ = "mail_log"

    id = db.Column(db.Integer, primary_key=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    direction = db.Column(db.String(8), nullable=False, default="inbound")
    qid = db.Column(db.String(64), nullable=False, default="", index=True)
    message_id = db.Column(db.String(255), nullable=False, default="")
    sender = db.Column(db.String(320), nullable=False, default="")
    # Envelope recipients, comma separated
    rcpts = db.Column(db.Text, nullable=False, default="")
    header_from = db.Column(db.String(500), nullable=False, default="")
    subject = db.Column(db.String(500), nullable=False, default="")
    score = db.Column(db.Float, nullable=False, default=0.0)
    action = db.Column(db.String(32), nullable=False, default="")
    ip = db.Column(db.String(64), nullable=False, default="")
    symbols = db.Column(db.Text, nullable=False, default="[]")
    size = db.Column(db.Integer, nullable=False, default=0)
    scan_ms = db.Column(db.Integer, nullable=False, default=0)
    message = db.deferred(db.Column(db.LargeBinary().with_variant(mysql.LONGBLOB(), "mysql"), nullable=False))
    requeued_at = db.Column(db.DateTime)
    requeued_by = db.Column(db.String(64))
    # Postfix's reason for refusing the recipient (services/maillog.py
    # store_refused); empty for scanned messages
    reject_reason = db.Column(db.String(255), nullable=False, default="", server_default="")

    @property
    def refused(self):
        """A recipient refused before the message was sent: no message."""
        return bool(self.reject_reason)

    @property
    def rcpt_list(self):
        return [r for r in self.rcpts.split(",") if r]


class MailDelivery(db.Model):
    """What Postfix did with a queued message, from its log
    (system/libexec/logship, services/deliveries.py): per recipient the
    latest delivery attempt (kind "delivery"), the notices Postfix sent the
    sender ("bounce_notice", "delay_notice", "dsn_notice", with the notice's
    own queue ID) and the expiry of a message that could not be delivered
    ("expired"). Joined to the mail log by queue ID."""
    __tablename__ = "mail_delivery"
    __table_args__ = (db.UniqueConstraint("qid", "kind", "rcpt", name="uq_mail_delivery"),)

    id = db.Column(db.Integer, primary_key=True)
    qid = db.Column(db.String(32), nullable=False, index=True)
    kind = db.Column(db.String(16), nullable=False, default="delivery")
    rcpt = db.Column(db.String(320), nullable=False, default="")
    status = db.Column(db.String(16), nullable=False, default="")
    dsn = db.Column(db.String(16), nullable=False, default="")
    relay = db.Column(db.String(255), nullable=False, default="")
    detail = db.Column(db.String(500), nullable=False, default="")
    notice_qid = db.Column(db.String(32), nullable=False, default="")
    attempts = db.Column(db.Integer, nullable=False, default=1)
    first_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)


class AuditEntry(db.Model):
    """A change made through the web UI, the REST API or a management command
    (services/audit.py). Only appended to, and removed after
    audit_retention_days."""
    __tablename__ = "audit_log"

    id = db.Column(db.Integer, primary_key=True)
    at = db.Column(db.DateTime, nullable=False, default=utcnow, index=True)
    # admin name, "user:<address>", "link:<address>" (digest link), "api:<key name>", "cli"
    actor = db.Column(db.String(400), nullable=False, default="", index=True)
    ip = db.Column(db.String(64), nullable=False, default="")
    method = db.Column(db.String(8), nullable=False, default="")
    # Flask endpoint (e.g. quarantine.action) or cli.<command>
    action = db.Column(db.String(128), nullable=False, default="")
    # URL rule with its arguments; never the path (digest links have the token in it)
    target = db.Column(db.String(512), nullable=False, default="")
    outcome = db.Column(db.String(16), nullable=False, default="ok")
    message = db.Column(db.Text, nullable=False, default="")
    # submitted fields without secrets (JSON)
    details = db.Column(db.Text, nullable=False, default="{}")


DIGEST_INTERVALS = {"never": "Never", "hourly": "Hourly", "daily": "Daily", "weekly": "Weekly"}
DIGEST_SECONDS = {"never": None, "hourly": 3600, "daily": 86400, "weekly": 7 * 86400}


def hash_token(token):
    """Tokens are long random strings, a plain SHA-256 is sufficient."""
    return hashlib.sha256(token.encode()).hexdigest()


class ApiKey(db.Model):
    __tablename__ = "api_keys"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), nullable=False)
    prefix = db.Column(db.String(12), nullable=False)
    key_hash = db.Column(db.String(64), unique=True, nullable=False)
    read_only = db.Column(db.Boolean, nullable=False, default=False)
    # Comma separated networks, empty = any source
    allow_from = db.Column(db.String(1024), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    last_used_at = db.Column(db.DateTime)

    @classmethod
    def create(cls, name, read_only=False, allow_from=""):
        """Returns (ApiKey, plaintext key). The key is only available here."""
        token = "sfk_" + secrets.token_urlsafe(32)
        return cls(name=name, prefix=token[:12], key_hash=hash_token(token), read_only=read_only,
                   allow_from=allow_from), token


class DigestToken(db.Model):
    """Grants access to the quarantine of one address, sent in digests."""
    __tablename__ = "digest_tokens"

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    rcpt = db.Column(db.String(320), nullable=False, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    last_used_at = db.Column(db.DateTime)

    @classmethod
    def create(cls, rcpt, expires_at):
        token = secrets.token_urlsafe(32)
        return cls(token_hash=hash_token(token), rcpt=rcpt, expires_at=expires_at), token


class AccountToken(db.Model):
    """A link to set the password of a mailbox user (services/invites.py):
    one use, until expires_at. Only its SHA-256 is stored."""
    __tablename__ = "account_tokens"

    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("mailbox_users.id", ondelete="CASCADE"), nullable=False,
                        index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)

    @classmethod
    def create(cls, user_id, expires_at):
        token = secrets.token_urlsafe(32)
        return cls(token_hash=hash_token(token), user_id=user_id, expires_at=expires_at), token


class DigestState(db.Model):
    """When the last digest was sent to an address."""
    __tablename__ = "digest_state"

    rcpt = db.Column(db.String(320), primary_key=True)
    last_sent_at = db.Column(db.DateTime, nullable=False)


class ClusterReport(db.Model):
    """The state a cluster node reports about itself every few seconds
    (flask cluster-report, services/cluster.py). Each node writes only its
    own row, so the reports of the nodes never conflict in Galera."""
    __tablename__ = "cluster_reports"

    hostname = db.Column(db.String(253), primary_key=True)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    # JSON: services/cluster.py collect()
    data = db.Column(db.Text, nullable=False, default="{}")


class ClusterControl(db.Model):
    """What the administrators want of a cluster node (Cluster page,
    system/cluster.sh maintenance): applied by that node's cluster-report
    and system/libexec/cluster-node."""
    __tablename__ = "cluster_control"

    hostname = db.Column(db.String(253), primary_key=True)
    maintenance = db.Column(db.Boolean, nullable=False, default=False)
    changed_by = db.Column(db.String(64), nullable=False, default="")
    changed_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    # A request to make the node the Valkey master, and when it was made
    promote_token = db.Column(db.String(32), nullable=False, default="")
    promote_at = db.Column(db.DateTime)


class ClusterMembership(db.Model):
    """The members of the cluster as the administrators set them (one row):
    every member applies it to its crassostrea.conf (HA_NODES, HA_WITNESS),
    firewall and cluster services (cluster-report, system/libexec/cluster-node).
    Created from a member's configuration when the cluster is set up."""
    __tablename__ = "cluster_membership"

    id = db.Column(db.Integer, primary_key=True)
    nodes = db.Column(db.Text, nullable=False, default="")  # hostname=address,...
    witness = db.Column(db.String(300), nullable=False, default="")
    changed_by = db.Column(db.String(64), nullable=False, default="")
    changed_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class ClusterJoinToken(db.Model):
    """The secret of a join information (Cluster page): one-time, short-lived.
    Only its SHA-256 is stored."""
    __tablename__ = "cluster_join_tokens"

    token_hash = db.Column(db.String(64), primary_key=True)
    created_by = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=utcnow)
    expires_at = db.Column(db.DateTime, nullable=False)
    used_at = db.Column(db.DateTime)
    used_by = db.Column(db.String(253), nullable=False, default="")


class BrandAsset(db.Model):
    """Uploaded logo or favicon (validated in services/branding.py)."""
    __tablename__ = "brand_assets"

    name = db.Column(db.String(16), primary_key=True)
    content_type = db.Column(db.String(64), nullable=False)
    data = db.Column(db.LargeBinary().with_variant(mysql.MEDIUMBLOB(), "mysql"), nullable=False)
    updated_at = db.Column(db.DateTime, nullable=False, default=utcnow)


class Setting(db.Model):
    __tablename__ = "settings"

    key = db.Column(db.String(64), primary_key=True)
    value = db.Column(db.Text, nullable=False)


# Mail log retention (days), and the largest message the gateway can be set
# to accept (MiB): the internal API, Rspamd's max_message and MariaDB's
# max_allowed_packet are sized for it
MAX_MAILLOG_DAYS = 31
MAX_MESSAGE_MB = 100

SETTING_DEFAULTS = {
    "reject_score": 15.0,
    "add_header_score": 8.0,
    "greylist_score": 7.0,
    "quarantine_retention_days": 14,
    "quarantine_max_size_mb": 10,
    # Store rejected mail sent from relay networks (1/0)
    "quarantine_outbound": 1,
    # Accounts for recipients of quarantined mail that exist downstream, with
    # a link to set the password valid for mailbox_invite_days (1/0)
    "mailbox_auto_create": 0,
    "mailbox_invite_days": 7,
    # Scan mail with ClamAV (1/0; clamd keeps running, SKIP_CLAMD removes it)
    "virus_scanning": 1,
    # Hosts without a reverse DNS name (PTR): off, defer (450) or reject (550)
    "ptr_check": "off",
    # Networks administrators may log in from, one per line; empty: any
    "admin_allowed_networks": "",
    # Time zone of the servers and the web interface (IANA name); empty: the
    # system's, times shown in UTC
    "timezone": "",
    # Every administrator must use two-factor login (1/0)
    "require_admin_2fa": 0,
    "audit_retention_days": 365,
    # Backups (system/libexec/backup reads these): scheduled backups kept,
    # rows of the mail log and the quarantine included (1/0)
    "backup_keep": 7,
    "backup_include_mail_log": 0,
    "backup_include_quarantine": 1,
    # Impersonation checks (services/impersonation.py): score added for each
    # (0: off); more domains to protect and look-alikes that are legitimate
    "impersonation_name_score": 6.0,
    "impersonation_lookalike_score": 6.0,
    "impersonation_spoof_score": 8.0,
    "impersonation_extra_domains": "",
    "impersonation_exempt_domains": "",
    # Link protection (services/links.py): hosts whose links stay as they
    # are, sites blocked when clicked, a way on past the warning, days a
    # rewritten link works
    "link_protection_exempt_hosts": "",
    "link_protection_block_domains": "",
    "link_protection_allow_continue": 0,
    "link_protection_days": 90,
    # Journaling (services/journal.py): where copies of all mail go, which
    # directions, rejected mail too, envelope report or plain copy
    "journal_address": "",
    "journal_inbound": 1,
    "journal_outbound": 1,
    "journal_rejected": 0,
    "journal_format": "envelope",
    # Monitoring (services/monitoring.py, services/siem.py): the SHA-256 of
    # the /metrics token; where and how events go to a SIEM; who gets alerts
    # and when
    "metrics_token_hash": "",
    "siem_host": "",
    "siem_port": 514,
    "siem_protocol": "tcp",
    "siem_format": "json",
    "siem_verify_tls": 1,
    "siem_mail_log": 1,
    "siem_audit": 1,
    "alert_recipients": "",
    "alert_deferred_count": 100,
    "alert_deferred_hours": 6,
    "alert_cert_days": 14,
    "alert_backup_hours": 36,
    # Messages users report to spam@ and ham@<hostname> (services/user_reports.py)
    "user_reports_enabled": 0,
    "user_reports_confirm": 1,
    "user_reports_per_hour": 50,
    # Statistics (services/stats.py): days the hourly counts are kept
    "stats_retention_days": 730,
    # DMARC and TLS reports (services/reports.py): days kept; send DMARC
    # aggregate reports about received mail (rspamd, libexec/dmarc-report)
    "report_retention_days": 180,
    "dmarc_send_reports": 0,
    # Hash lookups of attachments (services/hashcheck.py): per source on or
    # off, its score and threshold; the API keys are copied to Valkey
    "hashcheck_mhr": 0,
    "hashcheck_mhr_percent": 10,
    "hashcheck_mhr_score": 20.0,
    "hashcheck_mb_key": "",
    "hashcheck_mb_score": 20.0,
    "hashcheck_vt_key": "",
    "hashcheck_vt_engines": 3,
    "hashcheck_vt_score": 20.0,
    "hashcheck_vt_per_minute": 4,
    # Attachment policy (Attachments page, services/maps.py): file
    # extensions rejected, also inside archives; password-protected archives;
    # outbound mail too; senders (addresses, domains) it does not apply to
    "attachment_blocked_extensions": ("ace ade adp app appx appxbundle application bat cab chm cmd com cpl dll exe "
                                      "gadget hta inf ins iso jar jnlp js jse lnk msc msi msix msixbundle msp "
                                      "mst pif ps1 psc1 reg scf scr sct shb shs url vb vbe vbs vhd vhdx ws wsc "
                                      "wsf wsh xll"),
    "attachment_scan_archives": 1,
    "attachment_block_encrypted": 0,
    "attachment_outbound": 0,
    "attachment_exempt_senders": "",
    # Outbound limit of each sender: recipients per period (0: none)
    "outbound_limit": 0,
    "outbound_limit_period": "hour",
    # Rate limits page (services/ratelimits.py). Postfix, per sending host and
    # node: simultaneous connections (its default 50), and connections,
    # messages and recipients per minute (0: none)
    "smtp_connection_count_limit": 50,
    "smtp_connection_rate_limit": 0,
    "smtp_message_rate_limit": 0,
    "smtp_recipient_rate_limit": 0,
    # rspamd, counted in Valkey (all nodes): inbound messages per sending IP,
    # per recipient, bounces per recipient (0: none) and their periods
    "inbound_ip_limit": 0,
    "inbound_ip_period": "hour",
    "inbound_rcpt_limit": 0,
    "inbound_rcpt_period": "hour",
    "inbound_bounce_limit": 0,
    "inbound_bounce_period": "hour",
    # networks without rate limits (one per line); relay networks never have any
    "rate_limit_exempt": "",
    # Mail log: every scanned message, in full
    "maillog_retention_days": 7,
    # Size limits for all mail: Postfix refuses larger messages, Rspamd
    # rejects messages with a larger attachment (0: no limit)
    "max_message_size_mb": 50,
    "max_attachment_size_mb": 0,
    # Quarantine digests
    "digest_interval": "daily",
    "digest_sender": "",
    "digest_token_days": 7,
    # Branding
    "brand_name": "Spam Filter",
    "brand_accent": "",
    "brand_footer": "",
    "brand_theme": "system",
    # Changes with every branding update, used to version asset URLs
    "brand_version": 0,
    # Unix timestamp of the last change, used for HTTP caching of the
    # rspamd settings map
    "config_updated_at": 0,
}


def get_setting(key):
    default = SETTING_DEFAULTS[key]
    row = db.session.get(Setting, key)
    if row is None:
        return default
    try:
        return type(default)(row.value)
    except (TypeError, ValueError):
        return default


def set_setting(key, value):
    row = db.session.get(Setting, key)
    if row is None:
        row = Setting(key=key, value=str(value))
        db.session.add(row)
    else:
        row.value = str(value)


def touch_config():
    """Mark the filter configuration as changed (rspamd re-fetches settings).

    The value is strictly increasing so a change made within the same second
    as rspamd's last fetch still produces a newer Last-Modified header.
    """
    previous = get_setting("config_updated_at")
    set_setting("config_updated_at", max(int(time.time()), previous + 1))
