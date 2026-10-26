"""The documentation at /docs/: nginx asks auth.docs_access (auth_request)."""
from crassostrea.extensions import db
from crassostrea.models import set_setting

from test_pages import data  # noqa: F401 - fixture


def test_docs_access_for_administrators_only(client, logged_in):
    assert logged_in.get("/auth/docs").status_code == 204
    logged_in.post("/logout")
    assert client.get("/auth/docs").status_code == 401


def test_docs_access_never_redirects(app, logged_in):
    # an administrator who still has to set up two-factor login: 401, as
    # nginx treats anything but 2xx, 401 and 403 as an error
    set_setting("require_admin_2fa", 1)
    db.session.commit()
    assert logged_in.get("/auth/docs").status_code == 401
    assert logged_in.get("/").status_code == 302


def test_docs_access_not_for_mailbox_users(client, data):  # noqa: F811
    client.post("/login", data={"username": "alice@example.com", "password": "alice-password"})
    assert client.get("/my/").status_code == 200
    assert client.get("/auth/docs").status_code == 401


def test_docs_link(app, logged_in):
    assert b'href="/docs/"' not in logged_in.get("/settings/").data
    app.config["DOCS_ENABLED"] = True
    assert b'href="/docs/"' in logged_in.get("/settings/").data
