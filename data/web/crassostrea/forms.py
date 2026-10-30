import re

from flask_wtf import FlaskForm
from flask_wtf.file import FileField
from wtforms import (BooleanField, FloatField, IntegerField, PasswordField, SelectField, SelectMultipleField,
                     StringField, TextAreaField)
from wtforms.validators import EqualTo, InputRequired, Length, NumberRange, Optional, ValidationError

from .models import (ADMIN_ROLES, CONTENT_ACTIONS, CONTENT_DIRECTIONS, CONTENT_FIELDS, CONTENT_MATCHES,
                     DIGEST_INTERVALS, DIRECTORY_KINDS, DLP_ACTIONS, DLP_DETECTORS, LIMIT_PERIODS, LIST_KINDS,
                     LIST_TYPES, MAX_MAILLOG_DAYS, MAX_MESSAGE_MB, MAX_OUTBOUND_LIMIT, RECIPIENT_CHECKS, Directory,
                     Domain)
from . import validators as v


def _normalizer(func):
    def check(form, field):
        if field.data:
            try:
                field.data = func(field.data)
            except v.ValidationError as exc:
                raise ValidationError(str(exc))
    return check


class OverrideSelectField(SelectField):
    """Select for an optional override: NULL in the database is the "" choice."""

    def process_data(self, value):
        super().process_data("" if value is None else value)


def _optional_id(value):
    return int(value) if value not in (None, "", "None") else None


class LoginForm(FlaskForm):
    username = StringField("Username or e-mail address", validators=[InputRequired(), Length(max=320)])
    password = PasswordField("Password", validators=[InputRequired()])


class ForgotPasswordForm(FlaskForm):
    email = StringField("Your e-mail address", validators=[InputRequired(), Length(max=320)])


class CodeForm(FlaskForm):
    code = StringField("Code", validators=[InputRequired(), Length(max=32)])


class TwoFactorDisableForm(FlaskForm):
    password = PasswordField("Password", validators=[InputRequired()])
    code = StringField("Code from your app", validators=[InputRequired(), Length(max=32)])


class DomainForm(FlaskForm):
    name = StringField("Domain", validators=[InputRequired(), _normalizer(v.normalize_domain)])
    description = StringField("Description", validators=[Optional(), Length(max=255)])
    active = BooleanField("Active", default=True)
    destination_host = StringField("Downstream server", validators=[InputRequired(), _normalizer(v.normalize_host)])
    destination_port = IntegerField("Port", default=25, validators=[InputRequired(), NumberRange(1, 65535)])
    use_mx = BooleanField("Look up MX records of the downstream server name")
    recipient_check = SelectField("Recipient validation", choices=list(RECIPIENT_CHECKS.items()), default="any")
    directory_id = SelectField("Directory", coerce=_optional_id, choices=[("", "–")], validate_choice=False)
    quarantine_enabled = BooleanField("Quarantine rejected mail", default=True)
    link_protection = BooleanField("Check links when they are clicked (link protection)")
    digest_interval = OverrideSelectField("Quarantine digest",
                                          choices=[("", "Use global setting")] + list(DIGEST_INTERVALS.items()))
    greylist_score = FloatField("Greylist", validators=[Optional(), NumberRange(-100, 10000)])
    add_header_score = FloatField("Mark as spam", validators=[Optional(), NumberRange(-100, 10000)])
    reject_score = FloatField("Reject", validators=[Optional(), NumberRange(-100, 10000)])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.directory_id.choices = [("", "–")] + [(d.id, d.name) for d in
                                                   Directory.query.order_by(Directory.name)]

    def validate_use_mx(self, field):
        if field.data and self.destination_host.data and v.is_ip_address(self.destination_host.data):
            raise ValidationError("MX lookup is not possible for an IP address")


class RecipientsForm(FlaskForm):
    addresses = TextAreaField("Addresses (one per line)", validators=[InputRequired()])


class ListEntryForm(FlaskForm):
    list_type = SelectField("List", choices=list(LIST_TYPES.items()))
    kind = SelectField("Type", choices=list(LIST_KINDS.items()))
    value = StringField("Value", validators=[InputRequired(), Length(max=255)])
    comment = StringField("Comment", validators=[Optional(), Length(max=255)])

    def validate_value(self, field):
        try:
            if self.kind.data == "ip":
                field.data = v.normalize_network(field.data)
            else:
                field.data = v.normalize_sender_pattern(field.data)
        except v.ValidationError as exc:
            raise ValidationError(str(exc))


class RelayNetworkForm(FlaskForm):
    cidr = StringField("Network", validators=[InputRequired(), _normalizer(v.normalize_network)])
    comment = StringField("Comment", validators=[Optional(), Length(max=255)])


_PERIOD_CHOICES = [(key, f"per {key}") for key in LIMIT_PERIODS]


class OutboundDefaultForm(FlaskForm):
    outbound_limit = IntegerField("Recipients", validators=[InputRequired(), NumberRange(0, MAX_OUTBOUND_LIMIT)])
    outbound_limit_period = SelectField("Period", choices=_PERIOD_CHOICES)


class RateLimitsForm(FlaskForm):
    """Rate limits page (services/ratelimits.py)."""
    smtp_connection_count_limit = IntegerField("Simultaneous connections",
                                               validators=[InputRequired(), NumberRange(0, 1000)])
    smtp_connection_rate_limit = IntegerField("Connections per minute",
                                              validators=[InputRequired(), NumberRange(0, 100_000)])
    smtp_message_rate_limit = IntegerField("Messages per minute", validators=[InputRequired(), NumberRange(0, 100_000)])
    smtp_recipient_rate_limit = IntegerField("Recipients per minute",
                                             validators=[InputRequired(), NumberRange(0, 100_000)])
    inbound_ip_limit = IntegerField("Messages from one IP address",
                                    validators=[InputRequired(), NumberRange(0, MAX_OUTBOUND_LIMIT)])
    inbound_ip_period = SelectField("Per", choices=_PERIOD_CHOICES)
    inbound_rcpt_limit = IntegerField("Messages to one recipient",
                                      validators=[InputRequired(), NumberRange(0, MAX_OUTBOUND_LIMIT)])
    inbound_rcpt_period = SelectField("Per", choices=_PERIOD_CHOICES)
    inbound_bounce_limit = IntegerField("Bounces to one recipient",
                                        validators=[InputRequired(), NumberRange(0, MAX_OUTBOUND_LIMIT)])
    inbound_bounce_period = SelectField("Per", choices=_PERIOD_CHOICES)
    rate_limit_exempt = TextAreaField("Exempt networks", validators=[Optional(), Length(max=20000)])


class OutboundLimitForm(FlaskForm):
    sender = StringField("Sender address or domain", validators=[InputRequired(), Length(max=255)])
    max_recipients = IntegerField("Recipients", validators=[InputRequired(), NumberRange(0, MAX_OUTBOUND_LIMIT)])
    period = SelectField("Period", choices=_PERIOD_CHOICES, default="hour")
    comment = StringField("Comment", validators=[Optional(), Length(max=255)])


class DlpRuleForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired(), Length(max=64)])
    detector = SelectField("Finds", choices=list(DLP_DETECTORS.items()))
    pattern = TextAreaField("Keywords or expression", validators=[Optional(), Length(max=20000)])
    min_matches = IntegerField("Different matches needed", default=1,
                               validators=[InputRequired(), NumberRange(1, 1000)])
    sender = StringField("Only for sender", validators=[Optional(), Length(max=255)])
    action = SelectField("Then", choices=list(DLP_ACTIONS.items()), default="quarantine")
    active = BooleanField("Active", default=True)
    comment = StringField("Comment", validators=[Optional(), Length(max=255)])


class DirectoryForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired(), Length(max=64)])
    kind = SelectField("Kind", choices=list(DIRECTORY_KINDS.items()), default="ldap")
    ldap_urls = StringField("Servers", validators=[Optional(), Length(max=1000)])
    ldap_starttls = BooleanField("STARTTLS (ldap:// URLs)")
    ldap_verify = BooleanField("Check the server certificate", default=True)
    bind_dn = StringField("Bind DN", validators=[Optional(), Length(max=500)])
    bind_password = PasswordField("Bind password", validators=[Optional(), Length(max=500)])
    base_dn = StringField("Base DN", validators=[Optional(), Length(max=500)])
    ldap_filter = StringField("Filter", validators=[Optional(), Length(max=1000)])
    ldap_attributes = StringField("Address attributes", validators=[Optional(), Length(max=500)])
    tenant_id = StringField("Tenant ID or domain", validators=[Optional(), Length(max=253)])
    client_id = StringField("Application (client) ID", validators=[Optional(), Length(max=64)])
    client_secret = PasswordField("Client secret", validators=[Optional(), Length(max=500)])


class AttachmentPolicyForm(FlaskForm):
    attachment_blocked_extensions = TextAreaField("Blocked file extensions", validators=[Length(max=20000)])
    attachment_scan_archives = BooleanField("Also files inside archives (zip, rar, 7z, ...)")
    attachment_block_encrypted = BooleanField("Reject password-protected archives")
    attachment_outbound = BooleanField("Also outbound mail from the relay networks")
    attachment_exempt_senders = TextAreaField("Senders it does not apply to", validators=[Length(max=50000)])


class ImpersonationSettingsForm(FlaskForm):
    impersonation_name_score = FloatField("Name of a protected person",
                                          validators=[InputRequired(), NumberRange(0, 1000)])
    impersonation_lookalike_score = FloatField("Look-alike domain",
                                               validators=[InputRequired(), NumberRange(0, 1000)])
    impersonation_spoof_score = FloatField("Own domain without authentication",
                                           validators=[InputRequired(), NumberRange(0, 1000)])
    impersonation_extra_domains = TextAreaField("More domains to protect", validators=[Length(max=50000)])
    impersonation_exempt_domains = TextAreaField("Legitimate look-alikes", validators=[Length(max=50000)])


class ProtectedPersonForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired(), Length(max=128)])
    addresses = TextAreaField("Their addresses", validators=[Optional(), Length(max=10000)])


class ImpersonationTestForm(FlaskForm):
    display_name = StringField("Name", validators=[Optional(), Length(max=500)])
    address = StringField("Address", validators=[InputRequired(), Length(max=320)])


class LinkProtectionForm(FlaskForm):
    link_protection_exempt_hosts = TextAreaField("Hosts whose links stay as they are", validators=[Length(max=50000)])
    link_protection_block_domains = TextAreaField("Blocked sites", validators=[Length(max=50000)])
    link_protection_allow_continue = BooleanField("Let recipients open a blocked link anyway")
    link_protection_days = IntegerField("Rewritten links work for (days)",
                                        validators=[InputRequired(), NumberRange(1, 3650)])


class LinkCheckForm(FlaskForm):
    url = StringField("Address", validators=[InputRequired(), Length(max=2000)])


class HashLookupForm(FlaskForm):
    hashcheck_mhr = BooleanField("Team Cymru Malware Hash Registry")
    hashcheck_mhr_percent = IntegerField("Known malware from (% of engines)",
                                         validators=[InputRequired(), NumberRange(1, 100)])
    hashcheck_mhr_score = FloatField("Score", validators=[InputRequired(), NumberRange(0, 1000)])
    hashcheck_mb_key = PasswordField("MalwareBazaar Auth-Key", validators=[Optional(), Length(max=200)])
    hashcheck_mb_remove = BooleanField("Remove the key")
    hashcheck_mb_score = FloatField("Score", validators=[InputRequired(), NumberRange(0, 1000)])
    hashcheck_vt_key = PasswordField("VirusTotal API key", validators=[Optional(), Length(max=200)])
    hashcheck_vt_remove = BooleanField("Remove the key")
    hashcheck_vt_engines = IntegerField("Malware from (engines)", validators=[InputRequired(), NumberRange(1, 100)])
    hashcheck_vt_score = FloatField("Score", validators=[InputRequired(), NumberRange(0, 1000)])
    hashcheck_vt_per_minute = IntegerField("Requests per minute", validators=[InputRequired(), NumberRange(1, 1000)])


class HashCheckForm(FlaskForm):
    hash = StringField("Hash", validators=[InputRequired(), Length(max=64)])


class ContentRuleForm(FlaskForm):
    name = StringField("Name", validators=[InputRequired(), Length(max=64)])
    field = SelectField("When", choices=list(CONTENT_FIELDS.items()))
    header = StringField("Header", validators=[Optional(), Length(max=128)])
    match = SelectField("Match", choices=list(CONTENT_MATCHES.items()))
    value = StringField("Value", validators=[InputRequired(), Length(max=1000)])
    direction = SelectField("Mail", choices=list(CONTENT_DIRECTIONS.items()))
    action = SelectField("Then", choices=list(CONTENT_ACTIONS.items()))
    score = FloatField("Score", default=0.0, validators=[Optional(), NumberRange(-1000, 1000)])
    message = StringField("Rejection message", validators=[Optional(), Length(max=255)])
    active = BooleanField("Active", default=True)
    comment = StringField("Comment", validators=[Optional(), Length(max=255)])


class ContentTestForm(FlaskForm):
    source = TextAreaField("Message source", validators=[InputRequired(), Length(max=2_000_000)])
    envelope_from = StringField("Envelope sender", validators=[Optional(), Length(max=320)])
    recipients = StringField("Recipients", validators=[Optional(), Length(max=5000)])
    direction = SelectField("Mail", choices=[("inbound", "Inbound"), ("outbound", "Outbound")])


class ReportSettingsForm(FlaskForm):
    report_retention_days = IntegerField("Keep reports (days)", validators=[InputRequired(), NumberRange(7, 3650)])
    dmarc_send_reports = BooleanField("Send DMARC reports about the mail this gateway receives")


class SiemForm(FlaskForm):
    siem_host = StringField("Host", validators=[Optional(), Length(max=255)])
    siem_port = IntegerField("Port", validators=[InputRequired(), NumberRange(1, 65535)])
    siem_protocol = SelectField("Protocol", choices=[("tcp", "TCP"), ("tls", "TCP with TLS"), ("udp", "UDP")])
    siem_format = SelectField("Format", choices=[("json", "JSON, one object per line"),
                                                 ("rfc5424", "Syslog (RFC 5424) with JSON")])
    siem_verify_tls = BooleanField("Check the certificate (TLS)")
    siem_mail_log = BooleanField("Every scanned message (mail log)")
    siem_audit = BooleanField("Changes and logins (audit log)")


class AlertForm(FlaskForm):
    alert_recipients = TextAreaField("Recipients", validators=[Optional(), Length(max=5000)])
    alert_deferred_count = IntegerField("Deferred messages",
                                        validators=[InputRequired(), NumberRange(1, 1_000_000)])
    alert_deferred_hours = IntegerField("Oldest deferred (hours)", validators=[InputRequired(), NumberRange(1, 240)])
    alert_cert_days = IntegerField("Certificate expires within (days)",
                                   validators=[InputRequired(), NumberRange(1, 90)])
    alert_backup_hours = IntegerField("No backup for (hours)", validators=[InputRequired(), NumberRange(1, 720)])


class WatchdogForm(FlaskForm):
    watchdog_notify_email = TextAreaField("Recipients", validators=[Optional(), Length(max=5000)])
    watchdog_notify_webhook = StringField("Webhook URL", validators=[Optional(), Length(max=500)])
    watchdog_notify_webhook_body = TextAreaField("Webhook body (JSON)", validators=[Optional(), Length(max=2000)])
    watchdog_subject = StringField("Subject", validators=[InputRequired(), Length(max=100)])
    watchdog_notify_start = BooleanField("When the watchdog starts")
    watchdog_notify_ban = BooleanField("When netfilter bans an address (with whois)")


class UpdateChannelForm(FlaskForm):
    update_channel = SelectField("update.sh moves to", choices=[
        ("release", "The newest release"), ("main", "The newest commit of a branch")])
    update_branch = StringField("Branch", validators=[InputRequired(), Length(max=100)])


class JournalForm(FlaskForm):
    journal_address = StringField("Archive address", validators=[Optional(), Length(max=320)])
    journal_inbound = BooleanField("Inbound mail")
    journal_outbound = BooleanField("Outbound mail")
    journal_rejected = BooleanField("Also rejected and greylisted mail")
    journal_format = SelectField("Format", choices=[
        ("envelope", "Journal report: envelope and the original attached"), ("copy", "Copy of the message")])


class UserReportSettingsForm(FlaskForm):
    user_reports_enabled = BooleanField("Learn the messages users report")
    user_reports_confirm = BooleanField("Confirm to the reporter")
    user_reports_per_hour = IntegerField("Messages per reporter and hour",
                                         validators=[InputRequired(), NumberRange(1, 10000)])


class DlpTestForm(FlaskForm):
    text = TextAreaField("Text", validators=[InputRequired(), Length(max=1_000_000)])
    sender = StringField("Sender", validators=[Optional(), Length(max=255)])


class HostnameForm(FlaskForm):
    hostname = StringField("New hostname", validators=[InputRequired(), Length(max=253)])


class GlobalSettingsForm(FlaskForm):
    greylisting = BooleanField("Greylisting")
    greylist_score = FloatField("Greylist", validators=[InputRequired(), NumberRange(-100, 10000)])
    add_header_score = FloatField("Mark as spam", validators=[InputRequired(), NumberRange(-100, 10000)])
    reject_score = FloatField("Reject", validators=[InputRequired(), NumberRange(-100, 10000)])
    quarantine_retention_days = IntegerField("Keep quarantined mail (days)",
                                             validators=[InputRequired(), NumberRange(1, 3650)])
    quarantine_max_size_mb = IntegerField("Maximum size of quarantined mail (MiB)",
                                          validators=[InputRequired(), NumberRange(1, 100)])
    quarantine_outbound = BooleanField("Quarantine rejected outbound mail from relay networks")
    require_admin_2fa = BooleanField("Require two-factor login for every administrator")
    audit_retention_days = IntegerField("Keep the audit log (days)",
                                        validators=[InputRequired(), NumberRange(30, 3650)])
    maillog_retention_days = IntegerField("Keep logged mail (days)",
                                          validators=[InputRequired(), NumberRange(1, MAX_MAILLOG_DAYS)])
    max_message_size_mb = IntegerField("Maximum message size (MiB)",
                                       validators=[InputRequired(), NumberRange(1, MAX_MESSAGE_MB)])
    max_attachment_size_mb = IntegerField("Maximum attachment size (MiB)",
                                          validators=[InputRequired(), NumberRange(0, MAX_MESSAGE_MB)])
    digest_interval = SelectField("Default digest interval", choices=list(DIGEST_INTERVALS.items()))
    digest_sender = StringField("Digest sender address", validators=[Optional(), _normalizer(v.normalize_email)])
    digest_token_days = IntegerField("Digest links valid for (days)", validators=[InputRequired(), NumberRange(1, 30)])
    mailbox_auto_create = BooleanField("Create accounts for recipients of quarantined mail")
    mailbox_invite_days = IntegerField("Password links valid for (days)",
                                       validators=[InputRequired(), NumberRange(1, 30)])
    virus_scanning = BooleanField("Scan mail for viruses (ClamAV)")
    ptr_check = SelectField("Hosts without a reverse DNS name (PTR)", default="off", choices=[
        ("off", "Accept"), ("defer", "Defer (450, the host may retry)"), ("reject", "Reject (550)")])
    admin_allowed_networks = TextAreaField("Administrator access from", validators=[Optional(), Length(max=20000)])
    timezone = SelectField("Time zone", validate_choice=False)
    session_lifetime_minutes = IntegerField("Logins last (minutes)",
                                            validators=[InputRequired(), NumberRange(5, 7 * 24 * 60)])
    login_max_failures = IntegerField("Failed logins per address", validators=[InputRequired(), NumberRange(1, 1000)])
    login_max_account_failures = IntegerField("Failed logins per account",
                                              validators=[InputRequired(), NumberRange(1, 10000)])
    login_failure_window_minutes = IntegerField("Counted for (minutes)",
                                                validators=[InputRequired(), NumberRange(1, 24 * 60)])
    http_redirect = BooleanField("Redirect HTTP to HTTPS")
    rspamd_ui_networks = TextAreaField("Rspamd UI access from", validators=[Optional(), Length(max=20000)])
    trusted_proxies = TextAreaField("Reverse proxies in front of the gateway",
                                    validators=[Optional(), Length(max=20000)])
    spamhaus_dqs_key = PasswordField("Spamhaus DQS key", validators=[Optional(), Length(max=64)])
    spamhaus_dqs_remove = BooleanField("Remove the key")
    postfix_log_lines = IntegerField("Postfix log lines kept", validators=[InputRequired(), NumberRange(100, 1_000_000)])

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        from .services.filters import timezones
        self.timezone.choices = [("", "System default (shown as UTC)")] + [(name, name) for name in timezones()]

    def validate_reject_score(self, field):
        check_threshold_order(self.greylist_score.data, self.add_header_score.data, field.data)


class BackupSettingsForm(FlaskForm):
    backup_keep = IntegerField("Scheduled backups to keep", validators=[InputRequired(), NumberRange(1, 90)])
    backup_include_quarantine = BooleanField("Include quarantined mail")
    backup_include_mail_log = BooleanField("Include the mail log's messages")


def check_threshold_order(greylist, add_header, reject):
    if None in (greylist, add_header, reject):
        return
    if not greylist <= add_header < reject:
        raise ValidationError("Thresholds must satisfy: greylist ≤ mark as spam < reject")


class AdminAccessForm(FlaskForm):
    role = SelectField("Role", choices=list(ADMIN_ROLES.items()), default="admin")
    domains = SelectMultipleField("Domains (domain administrators)", coerce=str, validate_choice=False)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.domains.choices = [(d.name, d.name) for d in Domain.query.order_by(Domain.name)]


class AdminForm(AdminAccessForm):
    username = StringField("Username", validators=[InputRequired(), Length(min=3, max=64)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=10)])
    confirm = PasswordField("Repeat password", validators=[EqualTo("password", "Passwords do not match")])

    def validate_username(self, field):
        # No "@": addresses are reserved for mailbox user logins
        if not all(c.isalnum() or c in "._-" for c in field.data):
            raise ValidationError("Only letters, digits and . _ - are allowed")


class MailboxUserForm(FlaskForm):
    email = StringField("E-mail address", validators=[InputRequired(), _normalizer(v.normalize_email)])
    password = PasswordField("Password", validators=[InputRequired(), Length(min=10)])
    confirm = PasswordField("Repeat password", validators=[EqualTo("password", "Passwords do not match")])


class MailboxSettingsForm(FlaskForm):
    """Personal filter settings, used by mailbox users and administrators."""
    greylist_score = FloatField("Greylist", validators=[Optional()])
    add_header_score = FloatField("Mark as spam", validators=[Optional()])
    reject_score = FloatField("Reject", validators=[Optional()])
    digest_interval = OverrideSelectField("Quarantine digest",
                                          choices=[("", "Use default")] + list(DIGEST_INTERVALS.items()))


class UserListEntryForm(FlaskForm):
    list_type = SelectField("List", choices=list(LIST_TYPES.items()))
    value = StringField("Sender", validators=[InputRequired(), Length(max=255), _normalizer(v.normalize_sender_pattern)])
    comment = StringField("Comment", validators=[Optional(), Length(max=255)])


class SetPasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[InputRequired(), Length(min=10)])


class DkimGenerateForm(FlaskForm):
    selector = StringField("Selector", validators=[InputRequired(), Length(max=63)])
    key_size = SelectField("Key size", choices=[("2048", "2048 bit (recommended)"), ("4096", "4096 bit")],
                           default="2048")


class DkimImportForm(FlaskForm):
    selector = StringField("Selector", validators=[InputRequired(), Length(max=63)])
    private_key = TextAreaField("Private key (PEM)", validators=[InputRequired()])


class PasswordForm(FlaskForm):
    current = PasswordField("Current password", validators=[InputRequired()])
    password = PasswordField("New password", validators=[InputRequired(), Length(min=10)])
    confirm = PasswordField("Repeat new password", validators=[EqualTo("password", "Passwords do not match")])


class ChoosePasswordForm(FlaskForm):
    password = PasswordField("New password", validators=[InputRequired(), Length(min=10)])
    confirm = PasswordField("Repeat new password", validators=[EqualTo("password", "Passwords do not match")])


class BrandingForm(FlaskForm):
    brand_name = StringField("Company / product name", validators=[InputRequired(), Length(max=64)])
    brand_accent = StringField("Accent color", render_kw={"type": "color"})
    default_accent = BooleanField("Use the default color")
    brand_footer = StringField("Footer text", validators=[Optional(), Length(max=200)],
                               description="Shown on the login page, all pages and the quarantine link pages, "
                                           "e.g. support contact details.")
    brand_theme = SelectField("Default appearance", choices=[("system", "Follow the system setting"),
                                                             ("light", "Light"), ("dark", "Dark")])
    logo = FileField("Logo")
    remove_logo = BooleanField("Remove the logo")
    favicon = FileField("Favicon")
    remove_favicon = BooleanField("Remove the favicon")

    def validate_brand_accent(self, field):
        if not self.default_accent.data and not re.match(r"^#[0-9a-fA-F]{6}$", field.data or ""):
            raise ValidationError("Use a color in #rrggbb notation")


class LearnForm(FlaskForm):
    kind = SelectField("Learn as", choices=[("spam", "Spam"), ("ham", "Ham (not spam)")])
    message_file = FileField("Message file (.eml)")
    message_text = TextAreaField("…or paste the raw message including headers")
