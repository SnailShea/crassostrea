"""Settings of the gateway: virus scanning, the PTR check, administrator
networks, the time zone; the quarantine of one mailbox; accounts created for
recipients of quarantined mail and the links to set a password."""
import email
import email.policy
import json
import os
import re
import socket
import subprocess
import threading
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from crassostrea.extensions import db
from crassostrea.models import (AccountToken, Domain, MailboxUser, QuarantineItem, Recipient, get_setting,
                               set_setting, utcnow)
from crassostrea.services import adminaccess, filters, invites, mailer
from crassostrea.services.errors import ServiceError
from crassostrea.services.maps import sync_all
from crassostrea.template_helpers import _datetime

REPO = Path(__file__).resolve().parents[3]
POSTFIX_APPLY = REPO / "system" / "libexec" / "postfix-apply"
SET_TIMEZONE = REPO / "system" / "libexec" / "set-timezone"
LUA = REPO / "data" / "conf" / "rspamd" / "lua" / "rspamd.local.lua"
MAIN_CF = REPO / "data" / "conf" / "postfix" / "main.cf"

SETTINGS_FORM = {"greylist_score": "5", "add_header_score": "6", "reject_score": "12",
                 "quarantine_retention_days": "14", "quarantine_max_size_mb": "10", "maillog_retention_days": "14",
                 "max_message_size_mb": "25", "max_attachment_size_mb": "0", "audit_retention_days": "365",
                 "digest_interval": "daily", "digest_token_days": "7", "mailbox_invite_days": "7",
                 "ptr_check": "off", "session_lifetime_minutes": "480", "login_max_failures": "10",
                 "login_max_account_failures": "30", "login_failure_window_minutes": "15",
                 "postfix_log_lines": "9999", "http_redirect": "y", "virus_scanning": "y"}


@pytest.fixture
def domain(app):
    d = Domain(name="example.com", destination_host="127.0.0.1", destination_port=25)
    db.session.add(d)
    db.session.commit()
    return d


@pytest.fixture
def outbox(monkeypatch):
    sent = []
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, msg: sent.append((sender, rcpt, msg)))
    return sent


def _item(rcpt, age=timedelta(0), direction="inbound"):
    item = QuarantineItem(rcpt=rcpt, domain=rcpt.split("@")[1], subject=f"for {rcpt}", sender="spam@bad.example",
                          symbols="[]", message=b"Subject: x\r\n\r\nbody\r\n", created_at=utcnow() - age,
                          direction=direction)
    db.session.add(item)
    db.session.commit()
    return item


def _stubs(tmp_path, scripts):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    for name, body in scripts.items():
        (bin_dir / name).write_text("#!/bin/bash\n" + body)
        (bin_dir / name).chmod(0o755)
    return bin_dir


# ---------------------------------------------------------------------------
# Virus scanning
# ---------------------------------------------------------------------------

def test_virus_scanning_map(app, config):
    assert get_setting("virus_scanning") == 1
    assert sync_all()
    path = Path(config["RSPAMD_MAP_DIR"]) / "scanning.map"
    assert path.read_text().splitlines()[-1] == "virus_scanning 1"
    filters.update_settings(virus_scanning=False)
    db.session.commit()
    sync_all()
    assert path.read_text().splitlines()[-1] == "virus_scanning 0"
    with pytest.raises(ServiceError):
        filters.update_settings(virus_scanning="maybe")
    # rspamd.local.lua skips the ClamAV check with the map's 0
    lua = LUA.read_text()
    assert "add_condition('CLAM_VIRUS'" in lua and "/custom/scanning.map" in lua


def test_virus_scanning_page(logged_in, config):
    page = logged_in.get("/settings/").get_data(as_text=True)
    assert 'name="virus_scanning"' in page and "ClamAV is not installed" not in page
    override = Path(config["RSPAMD_MAP_DIR"]).parent / "override.d"
    override.mkdir()
    (override / "antivirus.conf").write_text("enabled = false;\n")
    assert "ClamAV is not installed" in logged_in.get("/settings/").get_data(as_text=True)
    assert logged_in.post("/settings/", data={**SETTINGS_FORM, "virus_scanning": ""}).status_code == 302
    assert get_setting("virus_scanning") == 0


# ---------------------------------------------------------------------------
# Hosts without a PTR record
# ---------------------------------------------------------------------------

def test_ptr_check_files(logged_in, config):
    from crassostrea.services.filters import add_list_entry
    add_list_entry("allow", "ip", "198.51.100.7")
    add_list_entry("allow", "ip", "2001:db8::/48")
    add_list_entry("allow", "sender", "friend@example.org")
    db.session.commit()
    assert logged_in.post("/settings/", data={**SETTINGS_FORM, "ptr_check": "reject"}).status_code == 302
    postfix = Path(config["POSTFIX_DYNAMIC_DIR"])
    assert (postfix / "ptr_check").read_text() == "reject\n"
    assert (postfix / "client_exempt.cidr").read_text().splitlines()[1:] == ["198.51.100.7/32\tOK",
                                                                              "2001:db8::/48\tOK"]
    response = logged_in.post("/settings/", data={**SETTINGS_FORM, "ptr_check": "sometimes"})
    assert response.status_code == 400
    with pytest.raises(ServiceError, match="ptr_check must be one of"):
        filters.update_settings(ptr_check="always")
    restrictions = re.search(r"^smtpd_client_restrictions = (.*?)\n(?=\S)", MAIN_CF.read_text(), re.M | re.S)
    assert "permit_mynetworks" in restrictions.group(1) and restrictions.group(1).rstrip().endswith("$sf_ptr_check")


@pytest.mark.parametrize("mode, check, code", [("reject", "reject_unknown_reverse_client_hostname", "550"),
                                               ("defer", "reject_unknown_reverse_client_hostname", "450"),
                                               ("off", "", None)])
def test_postfix_apply_ptr_check(tmp_path, mode, check, code):
    calls = tmp_path / "calls"
    bin_dir = _stubs(tmp_path, {
        "postconf": f'echo "postconf $*" >> {calls}\n[[ $2 == sf_ptr_check ]] && echo "OLD"\n'
                    '[[ $2 == unknown_client_reject_code ]] && echo 450\nexit 0\n',
        "systemctl": "exit 3\n"})
    dynamic = tmp_path / "postfix"
    dynamic.mkdir()
    (dynamic / "ptr_check").write_text(f"{mode}\n")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "POSTFIX_DYNAMIC_DIR": str(dynamic)}
    result = subprocess.run(["bash", str(POSTFIX_APPLY)], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    applied = [line for line in calls.read_text().splitlines() if line.startswith("postconf -e")]
    expected = [f"postconf -e sf_ptr_check={check}"]
    if code and code != "450":
        expected.append(f"postconf -e unknown_client_reject_code={code}")
    assert applied == expected


def test_postfix_apply_refuses_other_values(tmp_path):
    calls = tmp_path / "calls"
    bin_dir = _stubs(tmp_path, {"postconf": f'echo "postconf $*" >> {calls}\nexit 0\n', "systemctl": "exit 3\n"})
    dynamic = tmp_path / "postfix"
    dynamic.mkdir()
    (dynamic / "ptr_check").write_text("permit_inet_interfaces\n")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "POSTFIX_DYNAMIC_DIR": str(dynamic)}
    result = subprocess.run(["bash", str(POSTFIX_APPLY)], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == 0 and "Ignoring" in result.stderr
    assert not calls.exists() or "postconf -e" not in calls.read_text()


# ---------------------------------------------------------------------------
# Administrator networks
# ---------------------------------------------------------------------------

def test_allowed_networks():
    assert adminaccess.allowed("203.0.113.5", "")
    value = "192.0.2.0/24\n2001:db8::/48"
    assert adminaccess.allowed("192.0.2.77", value) and adminaccess.allowed("::ffff:192.0.2.77", value)
    assert adminaccess.allowed("2001:db8::1", value)
    assert not adminaccess.allowed("203.0.113.5", value) and not adminaccess.allowed("bogus", value)


def test_admin_networks_validation(app):
    values = filters.update_settings(admin_allowed_networks="192.0.2.5, 10.0.0.0/8\n10.0.0.0/8")
    assert values["admin_allowed_networks"] == "10.0.0.0/8\n192.0.2.5/32"
    # any address is a valid (if pointless) list here
    assert filters.update_settings(admin_allowed_networks="0.0.0.0/0")["admin_allowed_networks"] == "0.0.0.0/0"
    with pytest.raises(ServiceError, match="not a network"):
        filters.update_settings(admin_allowed_networks="office")


def test_admin_login_restricted(app, client):
    set_setting("admin_allowed_networks", "192.0.2.0/24")
    db.session.commit()
    outside = {"REMOTE_ADDR": "203.0.113.5"}
    response = client.post("/login", data={"username": "admin", "password": "initial-password"},
                           environ_base=outside)
    assert response.status_code == 403 and "cannot log in from your address" in response.get_data(as_text=True)
    # the same answer for a wrong password and a username that does not exist
    for username, password in (("admin", "wrong-password"), ("nobody", "x")):
        response = client.post("/login", data={"username": username, "password": password}, environ_base=outside)
        assert response.status_code == 403
    response = client.post("/login", data={"username": "admin", "password": "initial-password"},
                           environ_base={"REMOTE_ADDR": "192.0.2.10"})
    assert response.status_code == 302
    assert client.get("/settings/", environ_base={"REMOTE_ADDR": "192.0.2.10"}).status_code == 200
    # the session ends when it comes from elsewhere
    response = client.get("/settings/", environ_base=outside)
    assert response.status_code == 302 and "/login" in response.headers["Location"]
    assert client.get("/settings/", environ_base={"REMOTE_ADDR": "192.0.2.10"}).status_code == 302


def test_mailbox_users_not_restricted(app, client, domain):
    from crassostrea.services.accounts import create_mailbox_user
    create_mailbox_user("alice@example.com", "alice-password")
    set_setting("admin_allowed_networks", "192.0.2.0/24")
    db.session.commit()
    response = client.post("/login", data={"username": "alice@example.com", "password": "alice-password"},
                           environ_base={"REMOTE_ADDR": "203.0.113.5"})
    assert response.status_code == 302


def test_saving_cannot_lock_out(logged_in):
    response = logged_in.post("/settings/", data={**SETTINGS_FORM, "admin_allowed_networks": "192.0.2.0/24"})
    assert response.status_code == 400 and "would lock you out" in response.get_data(as_text=True)
    assert get_setting("admin_allowed_networks") == ""
    # the test client's address is 127.0.0.1
    response = logged_in.post("/settings/", data={**SETTINGS_FORM, "admin_allowed_networks": "127.0.0.0/8"})
    assert response.status_code == 302 and get_setting("admin_allowed_networks") == "127.0.0.0/8"


def test_admin_networks_cli(app):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["admin-networks", "--add", "192.0.2.0/24", "--add", "198.51.100.1"])
    assert result.exit_code == 0 and get_setting("admin_allowed_networks") == "192.0.2.0/24\n198.51.100.1/32"
    assert runner.invoke(args=["admin-networks", "--add", "nope"]).exit_code != 0
    result = runner.invoke(args=["admin-networks", "--clear"])
    assert result.exit_code == 0 and "any address" in result.output
    assert get_setting("admin_allowed_networks") == ""


def test_api_keys_not_restricted(app, api):
    set_setting("admin_allowed_networks", "192.0.2.0/24")
    db.session.commit()
    assert api("GET", "/settings").get_json()["admin_allowed_networks"] == "192.0.2.0/24"


# ---------------------------------------------------------------------------
# Time zone
# ---------------------------------------------------------------------------

def test_timezone_setting(app, config):
    with pytest.raises(ServiceError, match="not a time zone"):
        filters.update_settings(timezone="Mars/Olympus_Mons")
    filters.update_settings(timezone="Europe/Berlin")
    db.session.commit()
    sync_all()
    assert Path(config["TIMEZONE_REQUEST"]).read_text() == "Europe/Berlin\n"
    summer = datetime(2026, 7, 1, 12, 0, 0)
    assert _datetime(summer) == "2026-07-01 14:00:00 CEST"
    filters.update_settings(timezone="")
    db.session.commit()
    sync_all()
    assert not Path(config["TIMEZONE_REQUEST"]).exists()
    assert _datetime(summer) == "2026-07-01 12:00:00 UTC"


def test_timezone_page(logged_in, config):
    os.symlink("/usr/share/zoneinfo/America/New_York", config["LOCALTIME"])
    page = logged_in.get("/settings/").get_data(as_text=True)
    assert 'name="timezone"' in page and '<option value="Europe/Berlin">' in page
    assert "<strong>America/New_York</strong>" in page
    response = logged_in.post("/settings/", data={**SETTINGS_FORM, "timezone": "Asia/Tokyo"}, follow_redirects=True)
    assert "switch to the time zone Asia/Tokyo" in response.get_data(as_text=True)
    assert get_setting("timezone") == "Asia/Tokyo"
    Path(config["TIMEZONE_STATUS"]).write_text(json.dumps({"state": "failed", "message": "timedatectl failed"}))
    assert "The last change failed: timedatectl failed" in logged_in.get("/settings/").get_data(as_text=True)


def _set_timezone(tmp_path, zone, current="UTC"):
    calls = tmp_path / "calls"
    zoneinfo = tmp_path / "zoneinfo"
    (zoneinfo / "Europe").mkdir(parents=True, exist_ok=True)
    (zoneinfo / "Europe" / "Berlin").write_text("TZif")
    bin_dir = _stubs(tmp_path, {
        "timedatectl": f'echo "timedatectl $*" >> {calls}\n[[ $1 == show ]] && echo {current}\nexit 0\n',
        "systemctl": f'echo "systemctl $*" >> {calls}\nexit 0\n'})
    request = tmp_path / "timezone"
    request.write_text(zone + "\n")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "TIMEZONE_REQUEST": str(request),
           "TIMEZONE_STATUS": str(tmp_path / "status.json"), "ZONEINFO_DIR": str(zoneinfo)}
    result = subprocess.run(["bash", str(SET_TIMEZONE)], env=env, capture_output=True, text=True, timeout=30)
    lines = calls.read_text().splitlines() if calls.exists() else []
    status = json.loads((tmp_path / "status.json").read_text())
    return result, lines, status


def test_set_timezone_script(tmp_path):
    result, calls, status = _set_timezone(tmp_path, "Europe/Berlin")
    assert result.returncode == 0, result.stderr
    assert "timedatectl set-timezone Europe/Berlin" in calls
    restart = [line for line in calls if line.startswith("systemctl try-restart")]
    assert restart and "rspamd.service" in restart[0] and "mariadb" not in restart[0]
    assert status["state"] == "ok" and status["timezone"] == "Europe/Berlin"


def test_set_timezone_unchanged_and_refused(tmp_path):
    result, calls, status = _set_timezone(tmp_path, "Europe/Berlin", current="Europe/Berlin")
    assert result.returncode == 0 and not [c for c in calls if "set-timezone" in c or "try-restart" in c]
    for bad in ("../../etc/passwd", "Europe/Paris", "Europe;reboot"):
        result, calls, status = _set_timezone(tmp_path, bad)
        assert result.returncode == 1 and status["state"] == "failed"
        assert not [c for c in calls if "set-timezone" in c]


# ---------------------------------------------------------------------------
# One mailbox's quarantine
# ---------------------------------------------------------------------------

def test_quarantine_of_a_mailbox(logged_in, domain):
    from crassostrea.services.accounts import create_mailbox_user
    user = create_mailbox_user("alice@example.com", "alice-password")
    db.session.commit()
    _item("alice@example.com")
    _item("alice+news@example.com")
    _item("bob@example.com")
    _item("alice@example.com", direction="outbound")
    page = logged_in.get("/quarantine/?user=Alice@example.com").get_data(as_text=True)
    assert "for alice+news@example.com" in page and "for bob@example.com" not in page
    assert page.count("for alice@example.com") == 1  # inbound only
    assert f"/mailboxes/{user.id}" in page and "Show all recipients" in page
    users = logged_in.get("/mailboxes/").get_data(as_text=True)
    assert 'href="/quarantine/?user=alice@example.com"' in users
    assert re.search(r'title="Inbound quarantined mail">2</a>', users)
    edit = logged_in.get(f"/mailboxes/{user.id}").get_data(as_text=True)
    assert "Quarantine (2)" in edit and "for alice+news@example.com" in edit


def test_quarantine_of_a_mailbox_api(api, domain):
    _item("alice@example.com")
    _item("alice+x@example.com")
    _item("bob@example.com")
    items = api("GET", "/quarantine?mailbox=alice@example.com").get_json()["items"]
    assert sorted(i["rcpt"] for i in items) == ["alice+x@example.com", "alice@example.com"]
    assert api("GET", "/quarantine?mailbox=alice").status_code == 400


def test_domain_admin_sees_only_own_mailboxes(app, client, make_admin, domain):
    other = Domain(name="other.org", destination_host="127.0.0.1")
    db.session.add(other)
    admin = make_admin("dom", password="dom-password-1")
    admin.role = "domain"
    admin.domains = [domain]
    db.session.commit()
    _item("carol@other.org")
    client.post("/login", data={"username": "dom", "password": "dom-password-1"})
    page = client.get("/quarantine/?user=carol@other.org").get_data(as_text=True)
    assert "for carol@other.org" not in page


# ---------------------------------------------------------------------------
# Accounts for recipients of quarantined mail
# ---------------------------------------------------------------------------

class FakeSmtp:
    """A destination server that knows some addresses (or all of them)."""

    def __init__(self, known, accept_all=False):
        self.known, self.accept_all = {a.lower() for a in known}, accept_all
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.rcpts = []
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            with conn, conn.makefile("rwb") as f:
                f.write(b"220 fake ESMTP\r\n")
                f.flush()
                for raw in f:
                    line = raw.decode().strip()
                    verb = line[:4].upper()
                    if verb in ("EHLO", "HELO"):
                        f.write(b"250 fake\r\n")
                    elif verb == "MAIL":
                        f.write(b"250 ok\r\n")
                    elif verb == "RCPT":
                        address = re.search(r"<(.*)>", line).group(1).lower()
                        self.rcpts.append(address)
                        f.write(b"250 ok\r\n" if self.accept_all or address in self.known
                                else b"550 5.1.1 unknown user\r\n")
                    elif verb == "QUIT":
                        f.write(b"221 bye\r\n")
                        f.flush()
                        break
                    else:
                        f.write(b"250 ok\r\n")
                    f.flush()

    def close(self):
        self.sock.close()


@pytest.fixture
def smtp():
    servers = []

    def start(known, accept_all=False):
        server = FakeSmtp(known, accept_all)
        servers.append(server)
        return server
    yield start
    for server in servers:
        server.close()


def _token(message_bytes):
    message = email.message_from_bytes(message_bytes, policy=email.policy.default)
    text = message.get_body(("plain",)).get_content()
    return re.search(r"/account/set-password/([A-Za-z0-9_-]{20,})", text).group(1)


def test_callout(app, domain, smtp):
    server = smtp(["alice@example.com"])
    domain.destination_port = server.port
    assert invites.callout(domain, "alice@example.com") is True
    assert invites.callout(domain, "nobody@example.com") is False
    assert server.rcpts[1].startswith("sf-probe-")  # a made-up address after a known one
    server = smtp([], accept_all=True)
    domain.destination_port = server.port
    assert invites.callout(domain, "anyone@example.com") is None
    server.close()
    assert invites.callout(domain, "alice@example.com") is None  # no answer


def test_mailbox_exists_by_recipient_check(app, domain):
    domain.recipient_check = "list"
    db.session.add(Recipient(domain=domain, address="alice@example.com"))
    db.session.commit()
    assert invites.mailbox_exists(domain, "alice@example.com")
    assert not invites.mailbox_exists(domain, "bob@example.com")
    domain.recipient_check = "verify"
    assert invites.mailbox_exists(domain, "bob@example.com")


def test_provision_off_by_default(app, domain, outbox):
    _item("alice@example.com")
    assert invites.provision() == ([], {})
    assert MailboxUser.query.count() == 0 and outbox == []


def test_provision(app, domain, outbox, smtp, fake_redis):
    server = smtp(["alice@example.com"])
    domain.destination_port = server.port
    set_setting("mailbox_auto_create", 1)
    other = Domain(name="inactive.org", destination_host="127.0.0.1", active=False)
    db.session.add(other)
    db.session.commit()
    from crassostrea.services.accounts import create_mailbox_user
    create_mailbox_user("carol@example.com", "carol-password")
    db.session.commit()
    _item("Alice+news@example.com")
    _item("nobody@example.com")
    _item("carol@example.com")            # has an account
    _item("dave@inactive.org")            # not an active domain
    _item("erin@example.com", age=timedelta(days=2))  # too old
    created, failed = invites.provision()
    assert created == ["alice@example.com"] and failed == {}
    user = MailboxUser.query.filter_by(email="alice@example.com").one()
    assert user.invited_at is not None and user.active
    (sender, rcpt, message), = outbox
    assert rcpt == "alice@example.com" and "An account was" in message.decode()
    assert AccountToken.query.filter_by(user_id=user.id).count() == 1
    # the unknown address is not asked again for a day
    assert fake_redis.get(invites.CHECKED_PREFIX + "nobody@example.com") == "0"
    asked = len(server.rcpts)
    assert invites.provision() == ([], {})
    assert len(server.rcpts) == asked and len(outbox) == 1


def test_provision_keeps_no_account_when_the_mail_fails(app, domain, monkeypatch):
    domain.recipient_check = "verify"
    set_setting("mailbox_auto_create", 1)
    db.session.commit()
    _item("alice@example.com")

    def broken(*args):
        raise mailer.ReleaseError("Postfix is down")
    monkeypatch.setattr(mailer, "reinject", broken)
    created, failed = invites.provision()
    assert created == [] and "Postfix is down" in failed["alice@example.com"]
    assert MailboxUser.query.count() == 0 and AccountToken.query.count() == 0


def test_provision_cli(app, domain, outbox):
    domain.recipient_check = "verify"
    set_setting("mailbox_auto_create", 1)
    db.session.commit()
    _item("alice@example.com")
    result = app.test_cli_runner().invoke(args=["provision-accounts"])
    assert result.exit_code == 0 and "Created alice@example.com" in result.output


def test_set_password_link(app, client, domain, outbox):
    domain.recipient_check = "verify"
    set_setting("mailbox_auto_create", 1)
    db.session.commit()
    _item("alice@example.com")
    invites.provision()
    token = _token(outbox[0][2])
    page = client.get(f"/account/set-password/{token}")
    assert page.status_code == 200 and "alice@example.com" in page.get_data(as_text=True)
    assert page.headers["Referrer-Policy"] == "no-referrer"
    response = client.post(f"/account/set-password/{token}", data={"password": "short", "confirm": "short"})
    assert response.status_code == 200 and MailboxUser.query.one().invited_at is not None
    response = client.post(f"/account/set-password/{token}",
                           data={"password": "alice-new-password", "confirm": "alice-new-password"})
    assert response.status_code == 302 and response.headers["Location"].endswith("/my/")
    user = MailboxUser.query.one()
    assert user.check_password("alice-new-password") and user.invited_at is None
    # once only
    client.post("/logout")
    assert client.get(f"/account/set-password/{token}").status_code == 404
    assert client.get("/account/set-password/not-a-token").status_code == 404


def test_expired_link(app, client, domain, outbox):
    from crassostrea.services.accounts import create_mailbox_user
    user = create_mailbox_user("alice@example.com", "alice-password")
    db.session.flush()
    token = invites.send_link(user, now=utcnow() - timedelta(days=8))
    db.session.commit()
    assert client.get(f"/account/set-password/{token}").status_code == 404


def test_admin_sends_link(logged_in, domain, outbox):
    from crassostrea.services.accounts import create_mailbox_user
    user = create_mailbox_user("alice@example.com", "alice-password")
    db.session.commit()
    response = logged_in.post(f"/mailboxes/{user.id}/password-link", follow_redirects=True)
    assert "A link to set a password was sent to alice@example.com" in response.get_data(as_text=True)
    first = _token(outbox[0][2])
    assert "Subject: Set a new password" in outbox[0][2].decode()
    logged_in.post(f"/mailboxes/{user.id}/password-link")
    # the newer link replaces the first
    assert invites.resolve(first) == (None, None) and invites.resolve(_token(outbox[1][2]))[1] == user
    assert MailboxUser.query.one().invited_at is None


def test_api_password_link(api, domain, outbox):
    from crassostrea.services.accounts import create_mailbox_user
    user = create_mailbox_user("alice@example.com", "alice-password")
    db.session.commit()
    body = api("POST", f"/mailbox-users/{user.id}/password-link").get_json()
    assert body == {"sent_to": "alice@example.com", "valid_days": 7} and len(outbox) == 1
    assert api("GET", f"/mailbox-users/{user.id}").get_json()["invited_at"] is None
    user.active = False
    db.session.commit()
    assert api("POST", f"/mailbox-users/{user.id}/password-link").status_code == 409
    assert api("POST", "/mailbox-users/999/password-link").status_code == 404


def test_auto_create_settings(app):
    values = filters.update_settings(mailbox_auto_create=True, mailbox_invite_days=14)
    assert values["mailbox_auto_create"] is True and values["mailbox_invite_days"] == 14
    with pytest.raises(ServiceError):
        filters.update_settings(mailbox_invite_days=0)


def test_token_path_not_logged():
    configure = (REPO / "system" / "configure.sh").read_text()
    assert "account/set-password" in configure


def test_cleanup_removes_spent_links(app, domain, outbox):
    from crassostrea.services.accounts import create_mailbox_user, delete_mailbox_user
    from crassostrea.services.digest import cleanup_tokens
    alice = create_mailbox_user("alice@example.com", "alice-password")
    bob = create_mailbox_user("bob@example.com", "bob-password")
    db.session.flush()
    invites.send_link(alice, now=utcnow() - timedelta(days=30))   # expired
    token = invites.send_link(bob)
    db.session.commit()
    assert cleanup_tokens() == 1
    row, user = invites.resolve(token)
    invites.use(row, user, "bob-new-password")
    db.session.commit()
    assert cleanup_tokens() == 1 and AccountToken.query.count() == 0
    invites.send_link(alice)
    delete_mailbox_user(alice)
    db.session.commit()
    assert AccountToken.query.count() == 0
