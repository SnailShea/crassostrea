"""Business rules for administrators and mailbox users.

Used by the web UI and the REST API so both enforce the same constraints.
Functions raise AccountError with a user facing message; callers commit.
"""
import re

from ..extensions import db
from ..models import (ADMIN_ROLES, DIGEST_INTERVALS, AccountToken, Admin, DigestToken, Domain, ListEntry,
                      MailboxUser, get_setting, touch_config)
from .. import validators as v
from .errors import ServiceError

MIN_PASSWORD_LENGTH = 10
USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")
SCORE_FIELDS = ("greylist_score", "add_header_score", "reject_score")
# Limits for thresholds set by mailbox users themselves
USER_SCORE_RANGE = (1.0, 50.0)


class AccountError(ServiceError):
    pass


def check_password(password):
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise AccountError(f"The password must have at least {MIN_PASSWORD_LENGTH} characters", "password")


# ---------------------------------------------------------------------------
# Spam thresholds
# ---------------------------------------------------------------------------

def global_scores():
    return {f: get_setting(f) for f in SCORE_FIELDS}


def domain_scores(domain):
    base = global_scores()
    return {f: getattr(domain, f) if getattr(domain, f) is not None else base[f] for f in SCORE_FIELDS}


def effective_scores(domain, overrides):
    """Effective thresholds for overrides {field: value or None} below ``domain``."""
    base = domain_scores(domain)
    return {f: overrides.get(f) if overrides.get(f) is not None else base[f] for f in SCORE_FIELDS}


def check_score_order(scores):
    if not scores["greylist_score"] <= scores["add_header_score"] < scores["reject_score"]:
        raise AccountError("Thresholds must satisfy: greylist ≤ mark as spam < reject "
                           "(empty values use the domain/global defaults)", "reject_score")


def validate_user_scores(domain, overrides, limited=False):
    """``limited``: values set by the mailbox user themselves must stay in a sane range."""
    for field in SCORE_FIELDS:
        value = overrides.get(field)
        if value is None:
            continue
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise AccountError("Thresholds must be numbers", field)
        low, high = USER_SCORE_RANGE if limited else (-100.0, 10000.0)
        if not low <= value <= high:
            raise AccountError(f"Thresholds must be between {low:g} and {high:g}", field)
    check_score_order(effective_scores(domain, overrides))


def check_digest_interval(value):
    if value is not None and value not in DIGEST_INTERVALS:
        raise AccountError(f"digest_interval must be one of {', '.join(DIGEST_INTERVALS)} or null",
                           "digest_interval")


# ---------------------------------------------------------------------------
# Mailbox users
# ---------------------------------------------------------------------------

def create_mailbox_user(email, password=None, active=True, password_hash=None, **settings):
    """With ``password`` (hashed here) or ``password_hash``, the hash of
    another system (passwords.py)."""
    try:
        email = v.normalize_email(email)
    except v.ValidationError as exc:
        raise AccountError(str(exc), "email")
    domain = Domain.query.filter_by(name=email.split("@", 1)[1]).first()
    if domain is None:
        raise AccountError("The domain of this address is not protected by the gateway", "email")
    if MailboxUser.query.filter_by(email=email).first():
        raise AccountError("A mailbox user with this address already exists", "email", status=409)
    if (password is None) == (password_hash is None):
        raise AccountError("Give either password or password_hash", "password")
    if password is not None:
        check_password(password)
    stored = _imported_hash(password_hash) if password_hash is not None else None
    user = MailboxUser(email=email, domain=domain, active=bool(active))
    if stored is not None:
        user.password_hash = stored
    else:
        user.set_password(password)
    db.session.add(user)  # callers roll back on AccountError
    update_mailbox_user(user, **settings)
    return user


def update_mailbox_user(user, limited=False, **changes):
    """Apply changes (password, active, thresholds, digest_interval). ``limited``
    restricts threshold values for changes made by the user themselves."""
    if changes.get("password") is not None and changes.get("password_hash") is not None:
        raise AccountError("Give either password or password_hash", "password")
    if "password" in changes and changes["password"] is not None:
        check_password(changes["password"])
        user.set_password(changes["password"])
    if changes.get("password_hash") is not None:
        user.password_hash = _imported_hash(changes["password_hash"])
    if "active" in changes:
        user.active = bool(changes["active"])
    if "digest_interval" in changes:
        check_digest_interval(changes["digest_interval"])
        user.digest_interval = changes["digest_interval"]
    score_changes = {f: changes[f] for f in SCORE_FIELDS if f in changes}
    if score_changes:
        overrides = {f: getattr(user, f) for f in SCORE_FIELDS}
        overrides.update(score_changes)
        validate_user_scores(user.domain, overrides, limited=limited)
        for field, value in score_changes.items():
            setattr(user, field, None if value is None else float(value))
    touch_config()
    return user


def _imported_hash(value):
    from ..passwords import HashError, normalize
    try:
        return normalize(value)
    except HashError as exc:
        raise AccountError(str(exc), "password_hash") from None


def delete_mailbox_user(user):
    # Digest links sent to the address must not outlive the account
    DigestToken.query.filter_by(rcpt=user.email).delete(synchronize_session=False)
    AccountToken.query.filter_by(user_id=user.id).delete(synchronize_session=False)
    db.session.delete(user)
    touch_config()


# ---------------------------------------------------------------------------
# Administrators
# ---------------------------------------------------------------------------

def check_username(username):
    # No "@": addresses are reserved for mailbox user logins
    if not isinstance(username, str) or not USERNAME_RE.match(username):
        raise AccountError("Usernames have 3-64 characters: letters, digits and . _ -", "username")


def _domains(names):
    """Domains by name, for a domain administrator."""
    if not isinstance(names, (list, tuple, set)) or not all(isinstance(n, str) for n in names):
        raise AccountError("domains must be a list of domain names", "domains")
    wanted = {n.strip().lower() for n in names if n.strip()}
    found = Domain.query.filter(Domain.name.in_(sorted(wanted))).all() if wanted else []
    missing = wanted - {d.name for d in found}
    if missing:
        raise AccountError(f"There is no domain {sorted(missing)[0]}", "domains")
    return found


def _set_access(admin, role, domains):
    if role not in ADMIN_ROLES:
        raise AccountError(f"role must be one of {', '.join(ADMIN_ROLES)}", "role")
    admin.role = role
    if domains is not None:
        admin.domains = _domains(domains)
    if role == "domain" and not admin.domains:
        raise AccountError("Choose the domains of the domain administrator", "domains")


def create_admin(username, password, active=True, role="admin", domains=None):
    check_username(username)
    if Admin.query.filter_by(username=username).first():
        raise AccountError("This username is already taken", "username", status=409)
    check_password(password)
    admin = Admin(username=username, active=bool(active))
    admin.set_password(password)
    _set_access(admin, role or "admin", domains or [])
    db.session.add(admin)
    return admin


def _other_active_admins(admin):
    """Active full administrators besides ``admin``: one must remain."""
    return Admin.query.filter(Admin.active.is_(True), Admin.id != admin.id, Admin.role != "domain").count()


def update_admin(admin, acting=None, **changes):
    if "username" in changes and changes["username"] != admin.username:
        check_username(changes["username"])
        if Admin.query.filter_by(username=changes["username"]).first():
            raise AccountError("This username is already taken", "username", status=409)
        admin.username = changes["username"]
    if "password" in changes and changes["password"] is not None:
        check_password(changes["password"])
        admin.set_password(changes["password"])
    if "role" in changes or "domains" in changes:
        role = changes.get("role", admin.role)
        if role != admin.role:
            if acting is not None and acting.id == admin.id:
                raise AccountError("You cannot change your own role", "role", status=409)
            if admin.is_full_admin and admin.active and not _other_active_admins(admin):
                raise AccountError("At least one active administrator is required", "role", status=409)
        _set_access(admin, role, changes.get("domains"))
    if "active" in changes and not changes["active"] and admin.active:
        if acting is not None and acting.id == admin.id:
            raise AccountError("You cannot disable your own account", "active", status=409)
        if admin.is_full_admin and not _other_active_admins(admin):
            raise AccountError("At least one active administrator is required", "active", status=409)
        admin.active = False
    elif "active" in changes and changes["active"]:
        admin.active = True
    return admin


def delete_admin(admin, acting=None):
    if acting is not None and acting.id == admin.id:
        raise AccountError("You cannot delete your own account", status=409)
    if admin.active and admin.is_full_admin and not _other_active_admins(admin):
        raise AccountError("At least one active administrator is required", status=409)
    db.session.delete(admin)


# ---------------------------------------------------------------------------
# Personal allow/block lists (sender patterns only)
# ---------------------------------------------------------------------------

def add_user_list_entry(user, list_type, value, comment=""):
    if list_type not in ("allow", "block"):
        raise AccountError("list_type must be allow or block", "list_type")
    try:
        value = v.normalize_sender_pattern(value)
    except v.ValidationError as exc:
        raise AccountError(str(exc), "value")
    if any(e.list_type == list_type and e.value == value for e in user.list_entries):
        raise AccountError("This entry already exists", "value", status=409)
    entry = ListEntry(list_type=list_type, kind="sender", value=value, comment=(comment or "")[:255])
    user.list_entries.append(entry)
    touch_config()
    return entry


def delete_user_list_entry(user, entry_id):
    entry = next((e for e in user.list_entries if e.id == entry_id), None)
    if entry is None:
        raise AccountError("Entry not found", status=404)
    user.list_entries.remove(entry)
    touch_config()
