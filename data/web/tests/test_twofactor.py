"""Two-factor login of administrators (TOTP and recovery codes)."""
import base64
import re
import time

import pytest

from crassostrea.extensions import db
from crassostrea.models import Admin, set_setting
from crassostrea.services import twofactor

from conftest import make_api_key

PASSWORD = "initial-password"


def _codes(page):
    """The recovery codes shown on a page."""
    block = page[page.index('<pre class="recovery-codes">'):]
    return re.findall(r"\b[a-z2-9]{4}-[a-z2-9]{4}\b", block[:block.index("</pre>")])


def _now_code(secret, offset=0):
    return twofactor.code_at(secret, int(time.time() // twofactor.PERIOD) + offset)


@pytest.mark.parametrize("unix_time, code", [
    # RFC 6238 appendix B (SHA-1), last 6 of the 8 digits
    (59, "287082"), (1111111109, "081804"), (1111111111, "050471"), (1234567890, "005924"),
    (2000000000, "279037"), (20000000000, "353130"),
])
def test_rfc6238_vectors(unix_time, code):
    secret = base64.b32encode(b"12345678901234567890").decode()
    assert twofactor.code_at(secret, unix_time // 30) == code


def test_matching_step_drift_and_replay():
    secret = twofactor.new_secret()
    now = 1_700_000_000
    step = now // 30
    for offset in (-1, 0, 1):
        assert twofactor.matching_step(secret, twofactor.code_at(secret, step + offset), now=now) == step + offset
    assert twofactor.matching_step(secret, twofactor.code_at(secret, step + 2), now=now) is None
    assert twofactor.matching_step(secret, twofactor.code_at(secret, step), after=step, now=now) is None
    assert twofactor.matching_step(secret, " 12 34 5x ", now=now) is None


def _setup(client):
    """Set up two-factor login for the logged in admin; returns (secret, recovery codes)."""
    page = client.get("/account/two-factor").get_data(as_text=True)
    assert "data:image/svg+xml" in page
    with client.session_transaction() as session:
        secret = session["2fa_setup_secret"]
    assert "".join(re.search(r'<dd class="mono">([A-Z2-7 ]+)</dd>', page).group(1).split()) == secret
    response = client.post("/account/two-factor", data={"code": "000000" if _now_code(secret) != "000000" else "1"})
    assert "does not match" in response.get_data(as_text=True)
    page = client.post("/account/two-factor", data={"code": _now_code(secret)}).get_data(as_text=True)
    codes = _codes(page)
    assert len(codes) == 10
    return secret, codes


def _login(client, password=PASSWORD):
    return client.post("/login", data={"username": "admin", "password": password})


def test_setup_and_login(logged_in, app):
    secret, codes = _setup(logged_in)
    admin = Admin.query.filter_by(username="admin").one()
    assert twofactor.enabled(admin) and twofactor.recovery_codes_left(admin) == 10
    logged_in.post("/logout")

    # the password alone does not log in
    response = _login(logged_in)
    assert response.status_code == 302 and response.headers["Location"].endswith("/login/code")
    assert logged_in.get("/").status_code == 302
    response = logged_in.post("/login/code", data={"code": "999999" if _now_code(secret, 1) != "999999" else "1"})
    assert "Invalid code" in response.get_data(as_text=True)
    # the code of the last setup step was used: the next one logs in
    used = _now_code(secret, 1)
    response = logged_in.post("/login/code", data={"code": used})
    assert response.status_code == 302 and response.headers["Location"] == "/"
    assert logged_in.get("/account").status_code == 200
    logged_in.post("/logout")

    # a code is accepted once (the same code: a later step's would be new)
    _login(logged_in)
    assert "Invalid code" in logged_in.post("/login/code", data={"code": used}).get_data(as_text=True)
    # recovery codes work once each
    response = logged_in.post("/login/code", data={"code": codes[0].upper()}, follow_redirects=True)
    assert "You used a recovery code; 9 left" in response.get_data(as_text=True)
    logged_in.post("/logout")
    _login(logged_in)
    assert "Invalid code" in logged_in.post("/login/code", data={"code": codes[0]}).get_data(as_text=True)


def test_code_step_expires(client, app, logged_in):
    secret, _ = _setup(logged_in)
    logged_in.post("/logout")
    _login(logged_in)
    with logged_in.session_transaction() as session:
        session["2fa_pending"] = {**session["2fa_pending"], "at": session["2fa_pending"]["at"] - 3600}
    response = logged_in.post("/login/code", data={"code": _now_code(secret, 1)})
    assert response.status_code == 302 and response.headers["Location"].endswith("/login")


def test_wrong_codes_are_throttled(logged_in, app):
    secret, _ = _setup(logged_in)
    logged_in.post("/logout")
    _login(logged_in)
    for _ in range(app.config["LOGIN_MAX_FAILURES"]):
        logged_in.post("/login/code", data={"code": "abcdef"})
    assert logged_in.post("/login/code", data={"code": _now_code(secret, 1)}).status_code == 429


def test_requirement_forces_setup(logged_in, app):
    set_setting("require_admin_2fa", 1)
    db.session.commit()
    response = logged_in.get("/quarantine/")
    assert response.status_code == 302 and response.headers["Location"].endswith("/account/two-factor")
    # live page updates are redirected as well, the API is not affected
    assert logged_in.get("/", headers={"X-Live-Fragment": "1"}).status_code == 302
    token = make_api_key()
    assert logged_in.get("/api/v1/settings", headers={"X-API-Key": token}).status_code == 200
    _setup(logged_in)
    assert logged_in.get("/quarantine/").status_code == 200
    # cannot be turned off while required
    response = logged_in.post("/account/two-factor/disable", data={"off-password": PASSWORD, "off-code": "1"},
                              follow_redirects=True)
    assert "required for administrators" in response.get_data(as_text=True)
    assert twofactor.enabled(Admin.query.filter_by(username="admin").one())


def test_recovery_codes_and_turning_off(logged_in, app):
    secret, old = _setup(logged_in)
    response = logged_in.post("/account/two-factor/recovery-codes", data={"codes-code": "12"})
    assert response.status_code == 400 and "Invalid code from your app" in response.get_data(as_text=True)
    page = logged_in.post("/account/two-factor/recovery-codes",
                          data={"codes-code": _now_code(secret, 1)}).get_data(as_text=True)
    new = _codes(page)
    assert len(new) == 10 and not set(new) & set(old)
    admin = Admin.query.filter_by(username="admin").one()
    assert twofactor.verify(admin, old[0]) is None
    # turning off needs the password and a code
    response = logged_in.post("/account/two-factor/disable", data={"off-password": "wrong", "off-code": "1"})
    assert response.status_code == 400 and "Wrong password" in response.get_data(as_text=True)
    admin.totp_last_step = None
    db.session.commit()
    response = logged_in.post("/account/two-factor/disable",
                              data={"off-password": PASSWORD, "off-code": _now_code(secret)}, follow_redirects=True)
    assert "Two-factor login is off" in response.get_data(as_text=True)
    assert not twofactor.enabled(Admin.query.filter_by(username="admin").one())


def test_reset_by_another_admin_cli_and_api(logged_in, app, make_admin, api):
    _setup(logged_in)
    other = make_admin("helper")
    other.totp_secret, other.totp_enabled_at = twofactor.new_secret(), other.created_at
    db.session.commit()
    page = logged_in.get("/admins/").get_data(as_text=True)
    assert page.count('<span class="badge good">on</span>') >= 2
    response = logged_in.post(f"/admins/{other.id}/reset-2fa", follow_redirects=True)
    assert "Two-factor login of helper was reset" in response.get_data(as_text=True)
    assert not twofactor.enabled(db.session.get(Admin, other.id))
    me = Admin.query.filter_by(username="admin").one()
    response = logged_in.post(f"/admins/{me.id}/reset-2fa", follow_redirects=True)
    assert "on your account page" in response.get_data(as_text=True) and twofactor.enabled(me)

    assert api("GET", f"/admins/{me.id}").get_json()["two_factor"] is True
    assert api("POST", f"/admins/{me.id}/reset-2fa").get_json()["two_factor"] is False
    me.totp_secret, me.totp_enabled_at = twofactor.new_secret(), me.created_at
    db.session.commit()
    result = app.test_cli_runner().invoke(args=["reset-2fa", "admin"])
    assert result.exit_code == 0 and not twofactor.enabled(Admin.query.filter_by(username="admin").one())
    assert app.test_cli_runner().invoke(args=["reset-2fa", "nobody"]).exit_code != 0
    assert api("PATCH", "/settings", json={"require_admin_2fa": True}).get_json()["require_admin_2fa"] is True


def test_mailbox_users_have_no_two_factor_pages(app, client):
    from crassostrea.models import Domain, MailboxUser
    domain = Domain(name="example.com", destination_host="mx.internal")
    user = MailboxUser(email="alice@example.com", domain=domain)
    user.set_password("alice-password")
    db.session.add_all([domain, user])
    set_setting("require_admin_2fa", 1)
    db.session.commit()
    client.post("/login", data={"username": "alice@example.com", "password": "alice-password"})
    assert client.get("/my/").status_code == 200  # the requirement is for administrators
    assert client.get("/account/two-factor").status_code == 403
    assert "Two-factor login" not in client.get("/account").get_data(as_text=True)
