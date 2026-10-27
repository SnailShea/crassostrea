"""REST API, API keys and Swagger UI."""
import re

import pytest

from crassostrea.extensions import db
from crassostrea.models import Admin, ApiKey, Domain, MailboxUser, set_setting

from conftest import make_api_key


@pytest.fixture
def domain(app):
    d = Domain(name="example.com", destination_host="mx.internal")
    db.session.add(d)
    db.session.commit()
    return d


def _key(read_only=False, allow_from=""):
    return make_api_key(read_only=read_only, allow_from=allow_from)


# --- documentation ----------------------------------------------------------

def test_every_api_route_is_documented(app):
    spec = app.test_client().get("/api/v1/openapi.json").get_json()
    assert spec["openapi"].startswith("3.")
    for rule in app.url_map.iter_rules():
        if not rule.endpoint.startswith("api.") or rule.endpoint == "api.openapi":
            continue
        path = re.sub(r"<(?:\w+:)?(\w+)>", r"{\1}", rule.rule)[len("/api/v1"):]
        assert path in spec["paths"], path
        for method in rule.methods - {"HEAD", "OPTIONS"}:
            assert method.lower() in spec["paths"][path], f"{method} {path}"


def test_swagger_ui_page(logged_in):
    page = logged_in.get("/api/docs/")
    assert page.status_code == 200
    assert b'id="swagger-ui"' in page.data and b"swagger-init.js" in page.data
    assert "'unsafe-eval'" not in page.headers["Content-Security-Policy"]
    assert logged_in.get("/api/docs/assets/swagger-ui-bundle.js").status_code == 200
    # Swagger UI in the colours of the theme, after its own stylesheet
    html = page.get_data(as_text=True)
    assert html.index("swagger-ui.css") < html.index("/static/swagger-theme.css")
    theme = logged_in.get("/static/swagger-theme.css")
    assert theme.status_code == 200 and b"var(--surface)" in theme.data
    assert logged_in.get("/api/docs/assets/swagger-ui-bundle.js.map").status_code == 404
    assert logged_in.get("/api/docs/assets/../index.html").status_code == 404


def test_swagger_ui_requires_admin(client):
    assert client.get("/api/docs/").status_code == 302


# --- authentication ---------------------------------------------------------

def test_requires_key(app, client):
    response = client.get("/api/v1/admins")
    assert response.status_code == 401 and "API key" in response.get_json()["error"]


def test_session_does_not_authenticate_api(logged_in):
    assert logged_in.get("/api/v1/admins").status_code == 401


def test_invalid_key_reported_and_throttled(app, client, fake_redis):
    pubsub = fake_redis.pubsub()
    pubsub.subscribe("F2B_CHANNEL")
    pubsub.get_message()
    set_setting("login_max_failures", 2)
    db.session.commit()
    for _ in range(2):
        assert client.get("/api/v1/admins", headers={"X-API-Key": "sfk_wrong"},
                          environ_base={"REMOTE_ADDR": "198.51.100.9"}).status_code == 401
    assert pubsub.get_message()["data"] == "Crassostrea API: Invalid API key by 198.51.100.9"
    token = _key()
    response = client.get("/api/v1/admins", headers={"X-API-Key": token}, environ_base={"REMOTE_ADDR": "198.51.100.9"})
    assert response.status_code == 429


def test_bearer_header_and_last_used(app, client):
    token = _key()
    assert client.get("/api/v1/admins", headers={"Authorization": f"Bearer {token}"}).status_code == 200
    assert ApiKey.query.one().last_used_at is not None


def test_read_only_key(app, client):
    token = _key(read_only=True)
    assert client.get("/api/v1/admins", headers={"X-API-Key": token}).status_code == 200
    response = client.post("/api/v1/admins", headers={"X-API-Key": token},
                           json={"username": "x" * 5, "password": "y" * 12})
    assert response.status_code == 403


def test_allow_from(app, client):
    token = _key(allow_from="10.0.0.0/8,2001:db8::/32")
    ok = client.get("/api/v1/admins", headers={"X-API-Key": token}, environ_base={"REMOTE_ADDR": "10.1.2.3"})
    denied = client.get("/api/v1/admins", headers={"X-API-Key": token}, environ_base={"REMOTE_ADDR": "192.0.2.1"})
    assert ok.status_code == 200 and denied.status_code == 403


def test_json_errors(api):
    assert api("GET", "/nope").get_json() == {"error": "Not found"}
    assert api("PUT", "/admins").status_code == 405
    response = api("POST", "/admins", data="username=x", content_type="application/x-www-form-urlencoded")
    assert response.status_code == 400


# --- administrators ---------------------------------------------------------

def test_admin_crud(api, app):
    response = api("POST", "/admins", json={"username": "ops", "password": "long-password"})
    assert response.status_code == 201
    created = response.get_json()
    assert created["username"] == "ops" and created["active"] is True and "password" not in created
    assert response.headers["Location"].endswith(f"/api/v1/admins/{created['id']}")

    assert api("POST", "/admins", json={"username": "ops", "password": "long-password"}).status_code == 409
    bad = api("POST", "/admins", json={"username": "a@b.c", "password": "long-password"})
    assert bad.status_code == 422 and bad.get_json()["field"] == "username"
    assert api("POST", "/admins", json={"username": "ops2", "password": "short"}).status_code == 422
    assert api("POST", "/admins", json={"username": "ops2", "password": "long-password", "role": "x"}).status_code == 422
    assert api("POST", "/admins", json={"username": "ops2", "password": "long-password", "active": "yes"}).status_code == 422

    items = api("GET", "/admins").get_json()
    assert items["total"] == 2 and {a["username"] for a in items["items"]} == {"admin", "ops"}
    assert api("GET", "/admins?q=op").get_json()["total"] == 1

    updated = api("PATCH", f"/admins/{created['id']}", json={"username": "operator", "password": "new-password1"})
    assert updated.get_json()["username"] == "operator"
    login = app.test_client().post("/login", data={"username": "operator", "password": "new-password1"})
    assert login.status_code == 302

    assert api("DELETE", f"/admins/{created['id']}").status_code == 204
    assert api("GET", f"/admins/{created['id']}").status_code == 404


def test_last_active_admin_is_protected(api):
    admin_id = Admin.query.filter_by(username="admin").one().id
    response = api("PATCH", f"/admins/{admin_id}", json={"active": False})
    assert response.status_code == 409
    assert api("DELETE", f"/admins/{admin_id}").status_code == 409
    assert db.session.get(Admin, admin_id).active


# --- mailbox users ----------------------------------------------------------

def test_mailbox_user_crud(api, app, domain):
    response = api("POST", "/mailbox-users", json={
        "email": "Alice@Example.com", "password": "alice-password", "reject_score": 20, "digest_interval": "weekly"})
    assert response.status_code == 201, response.get_json()
    user = response.get_json()
    assert user["email"] == "alice@example.com" and user["domain"] == "example.com"
    assert user["reject_score"] == 20 and user["digest_interval"] == "weekly"

    assert api("POST", "/mailbox-users", json={"email": "alice@example.com", "password": "x" * 12}).status_code == 409
    other = api("POST", "/mailbox-users", json={"email": "bob@elsewhere.org", "password": "x" * 12})
    assert other.status_code == 422 and other.get_json()["field"] == "email"
    order = api("POST", "/mailbox-users", json={"email": "c@example.com", "password": "x" * 12, "reject_score": 3})
    assert order.status_code == 422 and "Thresholds" in order.get_json()["error"]
    digest = api("POST", "/mailbox-users", json={"email": "c@example.com", "password": "x" * 12, "digest_interval": "monthly"})
    assert digest.status_code == 422
    assert api("POST", "/mailbox-users", json={"email": "c@example.com", "password": "x" * 12,
                                               "reject_score": "high"}).status_code == 422

    patched = api("PATCH", f"/mailbox-users/{user['id']}", json={"reject_score": None, "digest_interval": None,
                                                                 "active": False})
    body = patched.get_json()
    assert body["reject_score"] is None and body["digest_interval"] is None and body["active"] is False
    assert api("PATCH", f"/mailbox-users/{user['id']}", json={"email": "x@example.com"}).status_code == 422

    for i in range(3):
        api("POST", "/mailbox-users", json={"email": f"user{i}@example.com", "password": "x" * 12})
    page = api("GET", "/mailbox-users?domain=example.com&per_page=2&page=2").get_json()
    assert page["total"] == 4 and len(page["items"]) == 2 and page["page"] == 2
    assert api("GET", "/mailbox-users?q=user1").get_json()["total"] == 1

    assert api("DELETE", f"/mailbox-users/{user['id']}").status_code == 204
    assert api("GET", f"/mailbox-users/{user['id']}").status_code == 404


def test_mailbox_user_list_entries(api, domain):
    user_id = api("POST", "/mailbox-users", json={"email": "alice@example.com", "password": "x" * 12}).get_json()["id"]
    created = api("POST", f"/mailbox-users/{user_id}/list-entries", json={"list_type": "allow", "value": "@Partner.org"})
    assert created.status_code == 201 and created.get_json()["value"] == "*@partner.org"
    assert api("POST", f"/mailbox-users/{user_id}/list-entries",
               json={"list_type": "allow", "value": "partner.org"}).status_code == 409
    assert api("POST", f"/mailbox-users/{user_id}/list-entries", json={"list_type": "allow", "value": "*"}).status_code == 422
    assert api("POST", f"/mailbox-users/{user_id}/list-entries", json={"list_type": "maybe", "value": "a@b.org"}).status_code == 422
    listed = api("GET", f"/mailbox-users/{user_id}/list-entries").get_json()
    assert listed["total"] == 1
    entry_id = listed["items"][0]["id"]
    assert api("DELETE", f"/mailbox-users/{user_id}/list-entries/{entry_id}").status_code == 204
    assert api("DELETE", f"/mailbox-users/{user_id}/list-entries/{entry_id}").status_code == 404
    # deleting the user removes its entries
    api("POST", f"/mailbox-users/{user_id}/list-entries", json={"list_type": "block", "value": "spam@x.org"})
    api("DELETE", f"/mailbox-users/{user_id}")
    from crassostrea.models import ListEntry
    assert ListEntry.query.count() == 0 and MailboxUser.query.count() == 0


# --- API key management -----------------------------------------------------

def test_api_key_lifecycle_via_ui(logged_in):
    response = logged_in.post("/api-keys/", data={"name": "provisioning", "allow_from": "10.0.0.1, 2001:db8::1"})
    token = re.search(rb"(sfk_[A-Za-z0-9_-]+)", response.data).group(1).decode()
    key = ApiKey.query.one()
    assert key.allow_from == "10.0.0.1/32,2001:db8::1/128"
    assert token not in logged_in.get("/api-keys/").get_data(as_text=True)  # shown once only
    assert key.key_hash != token and token.startswith(key.prefix)

    client = logged_in.application.test_client()
    ok = client.get("/api/v1/admins", headers={"X-API-Key": token}, environ_base={"REMOTE_ADDR": "10.0.0.1"})
    assert ok.status_code == 200
    logged_in.post(f"/api-keys/{key.id}/delete")
    gone = client.get("/api/v1/admins", headers={"X-API-Key": token}, environ_base={"REMOTE_ADDR": "10.0.0.1"})
    assert gone.status_code == 401

    bad = logged_in.post("/api-keys/", data={"name": "x", "allow_from": "not-a-network"})
    assert bad.status_code == 400 and ApiKey.query.count() == 0
