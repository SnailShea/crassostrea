"""Settings that moved from crassostrea.conf to the web UI: sign-in, the web
server, the Spamhaus DQS key, the Postfix log lines, the watchdog's notices
and the update channel. The web UI hands the ones of other services over
(services/serverconf.py); system/lib/nginx.sh and spamhaus.sh render them."""
import json
import subprocess
import time
from pathlib import Path

import pytest

from crassostrea.extensions import db
from crassostrea.models import get_setting, set_setting
from crassostrea.services import serverconf, store
from test_refused_recipients import logship

REPO = Path(__file__).resolve().parents[3]
LIB = REPO / "system" / "lib"

GENERAL = {"greylist_score": "7", "add_header_score": "8", "reject_score": "15", "quarantine_retention_days": "14",
           "quarantine_max_size_mb": "10", "audit_retention_days": "365", "maillog_retention_days": "7",
           "max_message_size_mb": "50", "max_attachment_size_mb": "0", "digest_interval": "daily",
           "digest_token_days": "7", "mailbox_invite_days": "7", "ptr_check": "off", "timezone": "",
           "session_lifetime_minutes": "480", "login_max_failures": "10", "login_max_account_failures": "30",
           "login_failure_window_minutes": "15", "postfix_log_lines": "9999", "http_redirect": "y",
           "virus_scanning": "y", "greylisting": "y"}


def _save(client, **changes):
    return client.post("/settings/", data={**GENERAL, **changes})


def test_defaults_are_handed_over(app, config, fake_redis):
    assert serverconf.sync()
    assert Path(config["WEB_ACCESS_REQUEST"]).read_text() == ("http_redirect=1\nrspamd_ui_networks=\n"
                                                              "trusted_proxies=\n")
    assert Path(config["SPAMHAUS_REQUEST"]).read_text() == "\n"
    assert fake_redis.get("POSTFIX_LOG_LINES") == "9999"
    notify = fake_redis.hgetall("WATCHDOG_NOTIFY")
    assert notify["subject"] == "Watchdog ALERT" and notify["notify_start"] == "y" and notify["email"] == ""
    assert json.loads(notify["webhook_body"].replace("${SUBJECT}", "s").replace("${BODY}", "b")) == {
        "username": "Crassostrea Watchdog", "content": "**s**\nb"}


def test_settings_page_saves_web_server_and_sign_in(logged_in, config):
    page = logged_in.get("/settings/").get_data(as_text=True)
    assert 'id="webserver"' in page and "Logins last (minutes)" in page
    response = _save(logged_in, http_redirect="", rspamd_ui_networks="192.0.2.7\n2001:db8::/48, 10.1.2.0/24",
                     trusted_proxies="198.51.100.10", session_lifetime_minutes="60", login_max_failures="5",
                     postfix_log_lines="5000")
    assert response.status_code == 302
    assert (get_setting("http_redirect"), get_setting("session_lifetime_minutes"),
            get_setting("login_max_failures"), get_setting("postfix_log_lines")) == (0, 60, 5, 5000)
    assert get_setting("rspamd_ui_networks") == "10.1.2.0/24\n192.0.2.7/32\n2001:db8::/48"
    assert Path(config["WEB_ACCESS_REQUEST"]).read_text() == (
        "http_redirect=0\nrspamd_ui_networks=10.1.2.0/24 192.0.2.7/32 2001:db8::/48\n"
        "trusted_proxies=198.51.100.10/32\n")
    page = logged_in.get("/settings/").get_data(as_text=True)
    assert "nginx applies the web server settings" in page


@pytest.mark.parametrize("changes, message", [
    ({"trusted_proxies": "proxy.example.com"}, "proxy.example.com is not a network or an address"),
    ({"session_lifetime_minutes": "1"}, "Number must be between 5 and 10080"),
    ({"spamhaus_dqs_key": "abc-123"}, "must be a key of letters and digits"),
    ({"postfix_log_lines": "10"}, "Number must be between 100 and 1000000"),
])
def test_settings_page_refuses_invalid_values(logged_in, changes, message):
    response = _save(logged_in, **changes)
    assert response.status_code == 400 and message in response.get_data(as_text=True)


def test_spamhaus_key_is_kept_replaced_and_removed(logged_in, config, api):
    assert _save(logged_in, spamhaus_dqs_key="abc123").status_code == 302
    assert get_setting("spamhaus_dqs_key") == "abc123"
    assert Path(config["SPAMHAUS_REQUEST"]).read_text() == "abc123\n"
    page = logged_in.get("/settings/").get_data(as_text=True)
    assert "abc123" not in page and 'placeholder="stored"' in page and "Remove the key" in page
    # an empty field keeps it
    _save(logged_in)
    assert get_setting("spamhaus_dqs_key") == "abc123"
    body = api("GET", "/settings").get_json()
    assert body["spamhaus_dqs_key_set"] is True and "spamhaus_dqs_key" not in body
    _save(logged_in, spamhaus_dqs_remove="y")
    assert get_setting("spamhaus_dqs_key") == "" and Path(config["SPAMHAUS_REQUEST"]).read_text() == "\n"
    assert api("PATCH", "/settings", json={"spamhaus_dqs_key": "Key42"}).get_json()["spamhaus_dqs_key_set"]
    assert Path(config["SPAMHAUS_REQUEST"]).read_text() == "Key42\n"
    assert api("PATCH", "/settings", json={"spamhaus_dqs_key": "a b"}).status_code == 422


def test_session_lifetime(logged_in, monkeypatch):
    set_setting("session_lifetime_minutes", 30)
    db.session.commit()
    assert logged_in.get("/settings/").status_code == 200
    later = time.time() + 31 * 60
    monkeypatch.setattr(time, "time", lambda: later)
    response = logged_in.get("/settings/")
    assert response.status_code == 302 and "/login" in response.headers["Location"]


def test_failure_window(app, fake_redis):
    set_setting("login_failure_window_minutes", 2)
    db.session.commit()
    store.report_auth_failure("test", "198.51.100.3", account="someone")
    assert 0 < fake_redis.ttl("WEB_LOGIN_FAILURES:198.51.100.3") <= 120
    assert 0 < fake_redis.ttl("WEB_LOGIN_FAILURES_ACCOUNT:someone") <= 120


def test_cleanup_trims_the_postfix_log(app, fake_redis):
    from crassostrea.cli import cleanup
    set_setting("postfix_log_lines", 100)
    db.session.commit()
    for i in range(150):
        fake_redis.lpush("POSTFIX_MAILLOG", json.dumps({"n": i}))
    assert app.test_cli_runner().invoke(cleanup).exit_code == 0
    assert fake_redis.llen("POSTFIX_MAILLOG") == 100


def test_logship_reads_the_line_limit(fake_redis):
    assert logship.log_lines(fake_redis) == logship.DEFAULT_LOG_LINES
    fake_redis.set("POSTFIX_LOG_LINES", "2500")
    assert logship.log_lines(fake_redis) == 2500
    fake_redis.set("POSTFIX_LOG_LINES", "lots")
    assert logship.log_lines(fake_redis) == logship.DEFAULT_LOG_LINES


def test_watchdog_notices(logged_in, fake_redis):
    page = logged_in.get("/monitoring/settings").get_data(as_text=True)
    assert 'id="watchdog"' in page and "Watchdog ALERT" in page
    response = logged_in.post("/monitoring/watchdog", data={
        "watchdog-watchdog_notify_email": "Ops@Example.com\nnoc@example.net",
        "watchdog-watchdog_notify_webhook": "https://chat.example.com/hooks/abc",
        "watchdog-watchdog_notify_webhook_body": '{"text": "${SUBJECT}: ${BODY}"}',
        "watchdog-watchdog_subject": "Gateway", "watchdog-watchdog_notify_ban": "y"})
    assert response.status_code == 302
    assert fake_redis.hgetall("WATCHDOG_NOTIFY") == {
        "email": "noc@example.net,ops@example.com", "webhook": "https://chat.example.com/hooks/abc",
        "webhook_body": '{"text": "${SUBJECT}: ${BODY}"}', "subject": "Gateway", "notify_start": "n",
        "notify_ban": "y"}


@pytest.mark.parametrize("field, value, message", [
    ("watchdog_notify_webhook", "ftp://x.example/", "must be an http(s) URL"),
    ("watchdog_notify_webhook", "https://x.example/a b", "must be an http(s) URL"),
    ("watchdog_notify_webhook_body", "{not json", "must be JSON"),
    ("watchdog_notify_email", "not an address", "watchdog_notify_email"),
])
def test_watchdog_notices_are_validated(api, field, value, message):
    response = api("PATCH", "/settings", json={field: value})
    assert response.status_code == 422 and message in response.get_data(as_text=True)


def _bash(script, **env):
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                            env={"PATH": "/usr/bin:/bin", **env})
    assert result.returncode == 0, result.stderr
    return result.stdout, result.stderr


def test_nginx_files(tmp_path):
    settings = tmp_path / "web-access"
    settings.write_text("http_redirect=0\nrspamd_ui_networks=192.0.2.0/24 2001:db8::/48 bad;name\n"
                        "trusted_proxies=198.51.100.10/32\n")
    out, err = _bash(f'source "{LIB}/nginx.sh"; nginx_redirect_conf; nginx_rspamd_access_conf; nginx_real_ip_conf',
                     NGINX_ACCESS_SETTINGS=str(settings))
    lines = [line for line in out.splitlines() if not line.startswith("#")]
    assert lines == ["default 0;", "allow 192.0.2.0/24;", "allow 2001:db8::/48;", "deny all;",
                     "set_real_ip_from 198.51.100.10/32;", "real_ip_header X-Forwarded-For;",
                     "real_ip_recursive on;"]
    assert "Ignoring bad;name" in err
    # no settings yet (a new gateway): redirect, no restrictions
    out, _ = _bash(f'source "{LIB}/nginx.sh"; nginx_redirect_conf; nginx_rspamd_access_conf; nginx_real_ip_conf',
                   NGINX_ACCESS_SETTINGS=str(tmp_path / "missing"))
    assert [line for line in out.splitlines() if not line.startswith("#")] == ["default 1;"]


@pytest.mark.parametrize("accepted", [True, False])
def test_nginx_update_access(tmp_path, accepted):
    settings = tmp_path / "web-access"
    settings.write_text("http_redirect=1\nrspamd_ui_networks=192.0.2.0/24\ntrusted_proxies=\n")
    for name in ("redirect", "rspamd", "realip"):
        (tmp_path / f"{name}.conf").write_text("# old\n")
    script = f'''
source "{LIB}/nginx.sh"
NGINX_REDIRECT_CONF={tmp_path}/redirect.conf NGINX_RSPAMD_ACCESS_CONF={tmp_path}/rspamd.conf
NGINX_REAL_IP_CONF={tmp_path}/realip.conf
nginx() {{ {"true" if accepted else "false"}; }}
systemctl() {{ echo "systemctl $*"; }}
restorecon() {{ :; }}
nginx_update_access; echo "rc=$?"
nginx_update_access; echo "rc=$?"
'''
    out, err = _bash(script, NGINX_ACCESS_SETTINGS=str(settings))
    rspamd = (tmp_path / "rspamd.conf").read_text()
    if accepted:
        assert out.splitlines() == ["systemctl reload nginx.service", "Applied the web server settings", "rc=0",
                                    "rc=0"]
        assert "allow 192.0.2.0/24;\ndeny all;" in rspamd
        assert (tmp_path / "realip.conf").read_text().startswith("# Generated")
    else:
        assert out.splitlines() == ["rc=1", "rc=1"] and "previous ones stay" in err
        assert rspamd == "# old\n" and (tmp_path / "redirect.conf").read_text() == "# old\n"
    assert not list(tmp_path.glob("*.previous")) and not list(tmp_path.glob("*.conf.*"))


def test_spamhaus_rendering(tmp_path):
    settings = tmp_path / "spamhaus"
    settings.write_text("Abc123\n")
    template = REPO / "data" / "conf" / "rspamd" / "dqs-rbl.conf.template"
    script = f'''
source "{LIB}/spamhaus.sh"
key=$(spamhaus_key)
echo "key=$key"
echo "dqs=$(spamhaus_postscreen "$key")"
echo "public=$(spamhaus_postscreen "" 200)"
echo "refused=$(spamhaus_postscreen "" 503)"
spamhaus_reply_map "$key" | grep -c spamhaus.org
spamhaus_rspamd "{template}" "$key" | grep -c 'Abc123\\.'
spamhaus_rspamd "{template}" "" | grep -c spamhaus.net
'''
    result = subprocess.run(["bash", "-c", script], capture_output=True, text=True, timeout=30,
                            env={"PATH": "/usr/bin:/bin", "SPAMHAUS_SETTINGS": str(settings)})
    lines = result.stdout.splitlines()
    assert lines[0] == "key=Abc123"
    assert lines[1] == ("dqs=Abc123.zen.dq.spamhaus.net=127.0.0.[4..7]*6 Abc123.zen.dq.spamhaus.net=127.0.0.[10;11]*8 "
                        "Abc123.zen.dq.spamhaus.net=127.0.0.3*4 Abc123.zen.dq.spamhaus.net=127.0.0.2*3")
    assert lines[2].startswith("public=zen.spamhaus.org=") and lines[3] == "refused="
    rules = sum("${SPAMHAUS_DQS_KEY}." in line for line in template.read_text().splitlines())
    assert lines[4:] == ["6", str(rules), "0"] and rules > 10
    # not a key: none
    settings.write_text("abc;rm -rf /\n")
    out, _ = _bash(f'source "{LIB}/spamhaus.sh"; echo "[$(spamhaus_key)]"', SPAMHAUS_SETTINGS=str(settings))
    assert out == "[]\n"


@pytest.mark.parametrize("configtest_ok", [True, False])
def test_spamhaus_apply(tmp_path, configtest_ok):
    """spamhaus-apply: Postfix's sf_spamhaus_dnsbl and reply map, Rspamd's
    rules if Rspamd accepts them, and reloads."""
    lib = tmp_path / "lib"
    (lib / "lib").mkdir(parents=True)
    (lib / "rspamd").mkdir()
    (lib / "lib" / "spamhaus.sh").symlink_to(LIB / "spamhaus.sh")
    (lib / "rspamd" / "dqs-rbl.conf.template").symlink_to(REPO / "data" / "conf" / "rspamd" /
                                                           "dqs-rbl.conf.template")
    bin_dir, calls = tmp_path / "bin", tmp_path / "calls"
    bin_dir.mkdir()
    # main.cf has sf_spamhaus_dnsbl (empty: no key, the public mirrors refused)
    (bin_dir / "postconf").write_text(f'#!/bin/bash\necho "postconf $*" >> {calls}\n'
                                      '[[ $1 == -n ]] && echo "sf_spamhaus_dnsbl ="\nexit 0\n')
    (bin_dir / "postfix").write_text(f'#!/bin/bash\necho "postfix $*" >> {calls}\n')
    (bin_dir / "systemctl").write_text(f'#!/bin/bash\necho "systemctl $*" >> {calls}\nexit 0\n')
    (bin_dir / "rspamadm").write_text(f'#!/bin/bash\nexit {0 if configtest_ok else 1}\n')
    (bin_dir / "curl").write_text("#!/bin/bash\necho -n 503\n")
    for f in bin_dir.iterdir():
        f.chmod(0o755)
    rules = tmp_path / "dqs-rbl.conf"
    rules.write_text("# No Spamhaus DQS key\n")
    (tmp_path / "spamhaus").write_text("Key42\n")
    env = {"PATH": f"{bin_dir}:/usr/bin:/bin", "SF_LIB": str(lib), "SPAMHAUS_SETTINGS": str(tmp_path / "spamhaus"),
           "SPAMHAUS_REPLY_MAP": str(tmp_path / "reply.map"), "SPAMHAUS_RSPAMD_CONF": str(rules)}
    script = REPO / "system" / "libexec" / "spamhaus-apply"
    result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert result.returncode == (0 if configtest_ok else 1), result.stderr
    log = calls.read_text().splitlines()
    assert ("postconf -e sf_spamhaus_dnsbl=Key42.zen.dq.spamhaus.net=127.0.0.[4..7]*6 Key42.zen.dq.spamhaus.net="
            "127.0.0.[10;11]*8 Key42.zen.dq.spamhaus.net=127.0.0.3*4 Key42.zen.dq.spamhaus.net=127.0.0.2*3") in log
    assert "postfix reload" in log
    assert "Key42.zen.dq.spamhaus.net     zen.spamhaus.org" in (tmp_path / "reply.map").read_text()
    if configtest_ok:
        assert "Key42.dbl.dq.spamhaus.net" in rules.read_text() and "systemctl reload rspamd.service" in log
    else:
        assert rules.read_text() == "# No Spamhaus DQS key\n" and "systemctl reload rspamd.service" not in log
        assert "Rspamd refused" in result.stderr
    assert not list(tmp_path.glob("*.previous")) and not list(tmp_path.glob("*.conf.*"))

    # the key removed, and the public mirrors refuse this network: no Spamhaus lists
    (tmp_path / "spamhaus").write_text("\n")
    calls.unlink()
    result = subprocess.run(["bash", str(script)], env=env, capture_output=True, text=True, timeout=30)
    assert "public mirrors refuse this server's network" in result.stderr
    # (the stub's sf_spamhaus_dnsbl already is empty)
    assert "spamhaus.org" not in (tmp_path / "reply.map").read_text() and "postfix reload" in calls.read_text()
