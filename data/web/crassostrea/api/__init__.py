"""REST API (v1): everything the web UI manages.

Authentication: ``X-API-Key: <key>`` (or ``Authorization: Bearer <key>``).
Keys are created by administrators in the UI (API keys page). Browser
sessions are ignored, so the API is not affected by CSRF.
The OpenAPI document is served at /api/v1/openapi.json, Swagger UI at /api/docs.

The routes are in accounts.py (administrators, mailbox users),
configuration.py (domains, lists, relay networks, settings, DKIM) and
operations.py (quarantine, mail queue, bans, training). They use the same
service functions as the web UI, so both enforce the same rules.
"""
import ipaddress

import redis
from flask import Blueprint, current_app, g, jsonify, request

from ..extensions import csrf, db
from ..models import ApiKey, hash_token, utcnow
from ..services import mailer, store
from ..services.errors import ServiceError
from ..services.maps import sync_all
from ..services.postfix_control import PostfixControlError
from ..services.rspamd import RspamdError
from .spec import build_spec

bp = Blueprint("api", __name__, url_prefix="/api/v1")
csrf.exempt(bp)

READ_METHODS = ("GET", "HEAD", "OPTIONS")


class ApiError(Exception):
    def __init__(self, status, message, field=None):
        super().__init__(message)
        self.status = status
        self.message = message
        self.field = field


@bp.errorhandler(ApiError)
def handle_api_error(exc):
    body = {"error": exc.message}
    if exc.field:
        body["field"] = exc.field
    return jsonify(body), exc.status


@bp.errorhandler(ServiceError)
def handle_service_error(exc):
    db.session.rollback()
    body = {"error": str(exc)}
    if exc.field:
        body["field"] = exc.field
    return jsonify(body), exc.status


@bp.errorhandler(PostfixControlError)
@bp.errorhandler(RspamdError)
@bp.errorhandler(mailer.ReleaseError)
@bp.errorhandler(redis.RedisError)
def handle_backend_error(exc):
    """A service of the gateway (Postfix, Rspamd, Valkey) failed."""
    db.session.rollback()
    current_app.logger.warning("API request failed in a backend: %s", exc)
    return jsonify({"error": str(exc) or exc.__class__.__name__}), 503


def json_error_for_api_paths(app):
    """JSON instead of HTML for unknown API URLs and methods."""
    for code, message in ((404, "Not found"), (405, "Method not allowed")):
        def handler(exc, code=code, message=message):
            if request.path.startswith("/api/v1/"):
                return jsonify({"error": message}), code
            return exc
        app.register_error_handler(code, handler)


# ---------------------------------------------------------------------------
# Authentication
# ---------------------------------------------------------------------------

def _presented_key():
    key = request.headers.get("X-API-Key", "")
    auth = request.headers.get("Authorization", "")
    if not key and auth.lower().startswith("bearer "):
        key = auth[7:]
    return key.strip()


def _allowed(api_key, ip):
    if not api_key.allow_from.strip():
        return True
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    for network in api_key.allow_from.split(","):
        try:
            if address in ipaddress.ip_network(network.strip(), strict=False):
                return True
        except ValueError:
            continue
    return False


@bp.before_request
def authenticate():
    if request.endpoint == "api.openapi":
        return None
    ip = request.remote_addr or "unknown"
    if store.login_blocked(ip):
        raise ApiError(429, "Too many failed authentication attempts, try again later")
    key = _presented_key()
    api_key = ApiKey.query.filter_by(key_hash=hash_token(key)).first() if key else None
    if api_key is None:
        if key:
            store.report_auth_failure(f"Crassostrea API: Invalid API key by {ip}", ip)
        raise ApiError(401, "A valid API key is required (X-API-Key header)")
    if not _allowed(api_key, ip):
        raise ApiError(403, "This API key may not be used from your address")
    if api_key.read_only and request.method not in READ_METHODS:
        raise ApiError(403, "This API key is read-only")
    api_key.last_used_at = utcnow()
    db.session.commit()
    g.api_key = api_key
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _iso(value):
    return value.isoformat(timespec="seconds") + "Z" if value else None


def _body(allowed, required=()):
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "The request body must be a JSON object (Content-Type: application/json)")
    unknown = sorted(set(data) - set(allowed))
    if unknown:
        raise ApiError(422, f"Unknown field(s): {', '.join(unknown)}", unknown[0])
    for field in required:
        if data.get(field) in (None, ""):
            raise ApiError(422, f"{field} is required", field)
    return data


def _check_types(data, types):
    for field, expected in types.items():
        if field not in data:
            continue
        value = data[field]
        if value is None and "null" in expected:
            continue
        ok = ((("string" in expected) and isinstance(value, str))
              or (("boolean" in expected) and isinstance(value, bool))
              or (("number" in expected) and isinstance(value, (int, float)) and not isinstance(value, bool)))
        if not ok:
            raise ApiError(422, f"{field} must be {' or '.join(expected)}", field)


def _pagination():
    try:
        page = max(int(request.args.get("page", 1)), 1)
        per_page = min(max(int(request.args.get("per_page", 50)), 1), 500)
    except ValueError:
        raise ApiError(400, "page and per_page must be integers")
    return page, per_page


def _paginated(query, serializer):
    page, per_page = _pagination()
    result = query.paginate(page=page, per_page=per_page, error_out=False)
    return jsonify({"items": [serializer(x) for x in result.items], "total": result.total,
                    "page": page, "per_page": per_page})


def _get(model, object_id, name):
    obj = db.session.get(model, object_id)
    if obj is None:
        raise ApiError(404, f"{name} not found")
    return obj


def _bool_arg(name):
    """Optional true/false query parameter."""
    value = request.args.get(name)
    if value is None or value == "":
        return None
    if value.lower() in ("true", "1", "yes"):
        return True
    if value.lower() in ("false", "0", "no"):
        return False
    raise ApiError(400, f"{name} must be true or false")


def _created(body, location):
    response = jsonify(body)
    response.status_code = 201
    response.headers["Location"] = location
    return response


def _commit_config():
    """Commit a change of the filter configuration and write the maps. A map
    that cannot be written is logged and retried by the sync timer."""
    db.session.commit()
    sync_all()


# ---------------------------------------------------------------------------
# Spec
# ---------------------------------------------------------------------------

@bp.get("/openapi.json")
def openapi():
    return jsonify(build_spec())


# Routes (registered on bp when imported)
from . import accounts, configuration, operations  # noqa: E402,F401
