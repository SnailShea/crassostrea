"""REST API: administrators, mailbox users and their personal lists."""
from flask import jsonify, request, url_for

from ..extensions import db
from .. import passwords
from ..models import Admin, Domain, MailboxUser, get_setting
from ..services import accounts, invites, twofactor
from . import ApiError, _body, _check_types, _created, _get, _iso, _paginated, bp


# ---------------------------------------------------------------------------
# Administrators
# ---------------------------------------------------------------------------

ADMIN_TYPES = {"username": ["string"], "password": ["string"], "active": ["boolean"], "role": ["string"]}
ADMIN_FIELDS = (*ADMIN_TYPES, "domains")


def admin_json(admin):
    return {"id": admin.id, "username": admin.username, "active": admin.active, "role": admin.role,
            "domains": [d.name for d in admin.domains],
            "two_factor": twofactor.enabled(admin),
            "created_at": _iso(admin.created_at), "last_login_at": _iso(admin.last_login_at)}


@bp.get("/admins")
def list_admins():
    query = Admin.query
    if request.args.get("q"):
        query = query.filter(Admin.username.contains(request.args["q"]))
    return _paginated(query.order_by(Admin.username), admin_json)


@bp.post("/admins")
def create_admin():
    data = _body(ADMIN_FIELDS, required=("username", "password"))
    _check_types(data, ADMIN_TYPES)
    admin = accounts.create_admin(data["username"], data["password"], data.get("active", True),
                                  role=data.get("role", "admin"), domains=data.get("domains", []))
    db.session.commit()
    return _created(admin_json(admin), url_for("api.get_admin", admin_id=admin.id))


@bp.get("/admins/<int:admin_id>")
def get_admin(admin_id):
    return jsonify(admin_json(_get(Admin, admin_id, "Administrator")))


@bp.patch("/admins/<int:admin_id>")
def update_admin(admin_id):
    admin = _get(Admin, admin_id, "Administrator")
    data = _body(ADMIN_FIELDS)
    _check_types(data, ADMIN_TYPES)
    accounts.update_admin(admin, acting=None, **data)
    db.session.commit()
    return jsonify(admin_json(admin))


@bp.delete("/admins/<int:admin_id>")
def delete_admin(admin_id):
    accounts.delete_admin(_get(Admin, admin_id, "Administrator"))
    db.session.commit()
    return "", 204


@bp.post("/admins/<int:admin_id>/reset-2fa")
def reset_admin_two_factor(admin_id):
    admin = _get(Admin, admin_id, "Administrator")
    twofactor.disable(admin)
    db.session.commit()
    return jsonify(admin_json(admin))


# ---------------------------------------------------------------------------
# Mailbox users
# ---------------------------------------------------------------------------

USER_TYPES = {
    "email": ["string"], "password": ["string"], "password_hash": ["string"], "active": ["boolean"],
    "greylist_score": ["number", "null"], "add_header_score": ["number", "null"],
    "reject_score": ["number", "null"], "digest_interval": ["string", "null"],
}
USER_UPDATE_TYPES = {k: v for k, v in USER_TYPES.items() if k != "email"}


def user_json(user):
    return {
        "id": user.id, "email": user.email, "domain": user.domain.name, "active": user.active,
        "greylist_score": user.greylist_score, "add_header_score": user.add_header_score,
        "reject_score": user.reject_score, "digest_interval": user.digest_interval,
        "created_at": _iso(user.created_at), "last_login_at": _iso(user.last_login_at),
        "invited_at": _iso(user.invited_at),
        # an imported hash until the user's first login replaces it with scrypt
        "password_format": passwords.scheme(user.password_hash),
    }


@bp.get("/mailbox-users")
def list_mailbox_users():
    query = MailboxUser.query
    if request.args.get("domain"):
        query = query.join(Domain).filter(Domain.name == request.args["domain"].strip().lower())
    if request.args.get("q"):
        query = query.filter(MailboxUser.email.contains(request.args["q"].strip().lower()))
    return _paginated(query.order_by(MailboxUser.email), user_json)


@bp.post("/mailbox-users")
def create_mailbox_user():
    data = _body(USER_TYPES, required=("email",))
    _check_types(data, USER_TYPES)
    email = data.pop("email")
    user = accounts.create_mailbox_user(email, data.pop("password", None), active=data.pop("active", True),
                                        password_hash=data.pop("password_hash", None), **data)
    db.session.commit()
    return _created(user_json(user), url_for("api.get_mailbox_user", user_id=user.id))


@bp.get("/mailbox-users/<int:user_id>")
def get_mailbox_user(user_id):
    return jsonify(user_json(_get(MailboxUser, user_id, "Mailbox user")))


@bp.patch("/mailbox-users/<int:user_id>")
def update_mailbox_user(user_id):
    user = _get(MailboxUser, user_id, "Mailbox user")
    data = _body(USER_UPDATE_TYPES)
    _check_types(data, USER_UPDATE_TYPES)
    accounts.update_mailbox_user(user, **data)
    db.session.commit()
    return jsonify(user_json(user))


@bp.post("/mailbox-users/<int:user_id>/password-link")
def send_mailbox_user_password_link(user_id):
    user = _get(MailboxUser, user_id, "Mailbox user")
    try:
        invites.send_link(user)
    except invites.InviteError as exc:
        db.session.rollback()
        raise ApiError(409 if not user.active else 502, f"The link could not be sent: {exc}")
    db.session.commit()
    return jsonify({"sent_to": user.email, "valid_days": get_setting("mailbox_invite_days")})


@bp.delete("/mailbox-users/<int:user_id>")
def delete_mailbox_user(user_id):
    accounts.delete_mailbox_user(_get(MailboxUser, user_id, "Mailbox user"))
    db.session.commit()
    return "", 204


# ---------------------------------------------------------------------------
# Personal allow/block lists of mailbox users
# ---------------------------------------------------------------------------

ENTRY_TYPES = {"list_type": ["string"], "value": ["string"], "comment": ["string"]}


def entry_json(entry):
    return {"id": entry.id, "list_type": entry.list_type, "value": entry.value, "comment": entry.comment,
            "created_at": _iso(entry.created_at)}


@bp.get("/mailbox-users/<int:user_id>/list-entries")
def list_user_entries(user_id):
    user = _get(MailboxUser, user_id, "Mailbox user")
    entries = sorted(user.list_entries, key=lambda e: (e.list_type, e.value))
    return jsonify({"items": [entry_json(e) for e in entries], "total": len(entries)})


@bp.post("/mailbox-users/<int:user_id>/list-entries")
def create_user_entry(user_id):
    user = _get(MailboxUser, user_id, "Mailbox user")
    data = _body(ENTRY_TYPES, required=("list_type", "value"))
    _check_types(data, ENTRY_TYPES)
    entry = accounts.add_user_list_entry(user, data["list_type"], data["value"], data.get("comment", ""))
    db.session.commit()
    return jsonify(entry_json(entry)), 201


@bp.delete("/mailbox-users/<int:user_id>/list-entries/<int:entry_id>")
def delete_user_entry(user_id, entry_id):
    accounts.delete_user_list_entry(_get(MailboxUser, user_id, "Mailbox user"), entry_id)
    db.session.commit()
    return "", 204
