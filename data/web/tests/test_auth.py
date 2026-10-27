import json

import pytest

from crassostrea import create_app
from crassostrea.extensions import db
from crassostrea.models import Admin, get_setting, set_setting


@pytest.mark.parametrize("path", ["/", "/domains/", "/quarantine/", "/lists/", "/settings/", "/admins/",
                                  "/queue/", "/mail-log/", "/logs", "/bans", "/training/"])
def test_pages_require_login(client, path):
    response = client.get(path)
    assert response.status_code == 302
    assert "/login" in response.headers["Location"]


def test_initial_admin_and_login(client):
    response = client.post("/login", data={"username": "admin", "password": "initial-password"})
    assert response.status_code == 302
    assert response.headers["Location"] == "/"


def _limit(key, value):
    set_setting(key, value)
    db.session.commit()


def test_failed_login_is_reported_to_netfilter_and_throttled(app, client, fake_redis):
    pubsub = fake_redis.pubsub()
    pubsub.subscribe("F2B_CHANNEL")
    pubsub.get_message()

    _limit("login_max_failures", 3)
    for _ in range(3):
        response = client.post("/login", data={"username": "admin", "password": "wrong"},
                               environ_base={"REMOTE_ADDR": "198.51.100.7"})
        assert b"Invalid username or password" in response.data

    message = pubsub.get_message()
    assert message["data"] == "Crassostrea UI: Invalid password for admin by 198.51.100.7"

    # Correct password is refused while the client is throttled
    response = client.post("/login", data={"username": "admin", "password": "initial-password"},
                           environ_base={"REMOTE_ADDR": "198.51.100.7"})
    assert response.status_code == 429


def test_failed_logins_are_throttled_per_account_across_ips(app, client):
    _limit("login_max_account_failures", 3)
    for i in range(3):
        client.post("/login", data={"username": "Admin", "password": "wrong"},
                    environ_base={"REMOTE_ADDR": f"198.51.100.{i}"})
    # Refused from a fresh address too, even with the right password
    response = client.post("/login", data={"username": "admin", "password": "initial-password"},
                           environ_base={"REMOTE_ADDR": "203.0.113.9"})
    assert response.status_code == 429
    # Other accounts are not affected
    response = client.post("/login", data={"username": "nobody@example.com", "password": "wrong"},
                           environ_base={"REMOTE_ADDR": "203.0.113.9"})
    assert response.status_code == 200 and b"Invalid username or password" in response.data


def test_successful_login_resets_account_failures(app, client, fake_redis):
    _limit("login_max_account_failures", 3)
    for i in range(2):
        client.post("/login", data={"username": "admin", "password": "wrong"},
                    environ_base={"REMOTE_ADDR": f"198.51.100.{i}"})
    response = client.post("/login", data={"username": "admin", "password": "initial-password"},
                           environ_base={"REMOTE_ADDR": "198.51.100.1"})
    assert response.status_code == 302
    assert fake_redis.get("WEB_LOGIN_FAILURES_ACCOUNT:admin") is None


def test_netfilter_rules(fake_redis, app):
    from crassostrea.services import store
    assert json.loads(fake_redis.get("F2B_REGEX")) == store.F2B_REGEX
    # rules of the administrator (without the web UI's) are kept
    fake_redis.set("F2B_REGEX", json.dumps({"1": "custom"}))
    store.seed_f2b_regex()
    assert json.loads(fake_redis.get("F2B_REGEX")) == {"1": "custom"}


def test_open_redirect_is_blocked(client):
    for target in ("https://evil.example/", "//evil.example/", "/\\evil.example"):
        response = client.post(f"/login?next={target}",
                               data={"username": "admin", "password": "initial-password"})
        assert response.headers["Location"] == "/"
        client.post("/logout")


def test_disabled_admin_loses_session(app, client, make_admin):
    admin = make_admin("other")
    client.post("/login", data={"username": "other", "password": "secret-password"})
    assert client.get("/").status_code == 200
    admin.active = False
    db.session.commit()
    assert client.get("/").status_code == 302


def test_cannot_disable_last_active_admin_or_self(logged_in):
    me = Admin.query.filter_by(username="admin").one()
    response = logged_in.post(f"/admins/{me.id}/delete", follow_redirects=True)
    assert b"You cannot delete your own account" in response.data
    assert db.session.get(Admin, me.id) is not None


def test_csrf_is_enforced(config, fake_redis):
    config = dict(config, WTF_CSRF_ENABLED=True)
    app = create_app("ui", config)
    with app.app_context():
        app.test_cli_runner().invoke(args=["init-db"])
        response = app.test_client().post("/login", data={"username": "admin", "password": "initial-password"})
        assert response.status_code == 400


def test_security_headers(client):
    response = client.get("/login")
    assert "default-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"] == "DENY"


# --- login lifetime ---------------------------------------------------------

def _age_login(client, seconds):
    with client.session_transaction() as sess:
        sess["login_at"] -= int(seconds)


def test_login_ends_after_its_lifetime(app, logged_in):
    lifetime = get_setting("session_lifetime_minutes") * 60
    _age_login(logged_in, lifetime - 60)
    assert logged_in.get("/").status_code == 200
    _age_login(logged_in, 120)
    response = logged_in.get("/")
    assert response.status_code == 302 and "/login" in response.headers["Location"]
    assert b"Your session has expired" in logged_in.get(response.headers["Location"]).data
    # really logged out, not just redirected once
    assert logged_in.get("/domains/").status_code == 302


def test_activity_does_not_extend_a_login(app, logged_in):
    """Live pages request updates all the time; the login still ends."""
    lifetime = get_setting("session_lifetime_minutes") * 60
    # a margin: a slow request must not end the login before the second step
    _age_login(logged_in, lifetime - 30)
    logged_in.get("/queue/", headers={"X-Live-Fragment": "1"})
    _age_login(logged_in, 31)
    assert logged_in.get("/queue/", headers={"X-Live-Fragment": "1"}).status_code == 302


def test_session_without_login_time_is_ended(logged_in):
    with logged_in.session_transaction() as sess:
        del sess["login_at"]
    assert logged_in.get("/").status_code == 302


def test_a_new_login_starts_a_new_lifetime(app, client, logged_in):
    _age_login(logged_in, get_setting("session_lifetime_minutes") * 60 + 1)
    assert logged_in.get("/").status_code == 302
    logged_in.post("/login", data={"username": "admin", "password": "initial-password"})
    assert logged_in.get("/").status_code == 200
