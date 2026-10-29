"""netfilter's ban rules (services/store.py F2B_REGEX) on real log lines, the
same rules in services/netfilter/main.py, the web UI's exploit detection
(services/exploits.py) and logship's nginx lines."""
import ast
import importlib.machinery
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest

from crassostrea.services import store

REPO = Path(__file__).resolve().parents[3]

# The React Server Components exploit (CVE-2025-55182) as scanners send it
RSC_BODY = {"0": '{"then": "$1:__proto__:then", "status": "resolved_model", "reason": -1, '
                 '"value": "{\\"then\\":\\"$B1337\\"}", "_response": {"_formData": {"get": '
                 '"$1:constructor:constructor"}}}',
            "1": '"$@0"', "2": "[]"}


def _netfilter_rules():
    tree = ast.parse((REPO / "services" / "netfilter" / "main.py").read_text())
    return next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                and getattr(node.targets[0], "id", "") == "DEFAULT_F2B_REGEX")


def match(line):
    """(rule id, address, attempts) of the first rule that matches, as netfilter matches."""
    for rule_id, rule in store.F2B_REGEX.items():
        found = re.search(rule["regex"], line)
        if found:
            return rule_id, found.group(1), rule.get("attempts")
    return None


def test_netfilter_has_the_same_rules():
    assert _netfilter_rules() == store.F2B_REGEX
    for rule in store.F2B_REGEX.values():
        assert re.compile(rule["regex"]).groups >= 1


@pytest.mark.parametrize("line, expected", [
    # postscreen (lines of the gateway's Postfix log)
    ("NON-SMTP COMMAND from [172.234.207.202]:13894 after CONNECT: GET / HTTP/1.0", ("6", "172.234.207.202", 1)),
    ("PREGREET 11 after 0.16 from [178.16.52.197]:54965: EHLO User\\r\\n", ("7", "178.16.52.197", 3)),
    ("BARE NEWLINE from [4.249.17.190]:60312 after MGLNDD_69.2.160.252_25", ("7", "4.249.17.190", 3)),
    ("COMMAND PIPELINING from [2001:db8::5]:42410 after : \\r\\n", ("7", "2001:db8::5", 3)),
    ("NOQUEUE: reject: RCPT from unknown[203.0.113.9]: 554 5.7.1 <x@outlook.com>: Relay access denied; "
     "from=<admin@gw.example.com> to=<x@outlook.com> proto=ESMTP helo=<x>", ("8", "203.0.113.9", 3)),
    # nginx access log
    ('34.85.18.1 - - [28/Oct/2026:13:43:39 -0400] "GET /.git/config HTTP/1.1" 404 207 "-" "Mozilla/5.0"',
     ("9", "34.85.18.1", 1)),
    ('45.138.12.24 - - [27/Oct/2026:01:02:03 +0000] "GET /.env.production HTTP/1.1" 404 0 "-" "-"',
     ("9", "45.138.12.24", 1)),
    ('195.178.110.94 - - [27/Oct/2026:01:02:03 +0000] "GET /backend/.ENV HTTP/1.1" 404 0 "-" "-"',
     ("9", "195.178.110.94", 1)),
    ('44.251.103.50 - - [27/Oct/2026:01:02:03 +0000] "GET /wp-login.php HTTP/1.1" 404 0 "-" "-"',
     ("9", "44.251.103.50", 1)),
    ('129.213.151.234 - - [27/Oct/2026:01:02:03 +0000] "GET /phpinfo.php?x=1 HTTP/1.1" 404 0 "-" "-"',
     ("9", "129.213.151.234", 1)),
    ('2001:db8::7 - - [27/Oct/2026:01:02:03 +0000] "POST /cgi-bin/luci HTTP/1.1" 404 0 "-" "-"',
     ("9", "2001:db8::7", 1)),
    ('34.78.64.142 - - [27/Oct/2026:01:02:03 +0000] "GET /.aws/credentials HTTP/1.1" 404 0 "-" "-"',
     ("9", "34.78.64.142", 1)),
    ('34.78.64.142 - - [27/Oct/2026:01:02:03 +0000] "GET /config.json HTTP/1.1" 404 0 "-" "-"',
     ("9", "34.78.64.142", 1)),
    # the web UI
    ("Crassostrea UI: Exploit attempt by 34.85.18.1", ("5", "34.85.18.1", 1)),
    ("Crassostrea UI: Invalid password for admin by 198.51.100.7", ("1", "198.51.100.7", None)),
])
def test_rules_match(line, expected):
    assert match(line) == expected


@pytest.mark.parametrize("line", [
    '198.51.100.4 - - [27/Oct/2026:01:02:03 +0000] "GET /login?next=%2F HTTP/1.1" 200 3000 "-" "Mozilla/5.0"',
    '198.51.100.4 - - [27/Oct/2026:01:02:03 +0000] "POST /login HTTP/1.1" 400 117 "-" "Mozilla/5.0"',
    '198.51.100.4 - - [27/Oct/2026:01:02:03 +0000] "GET /static/app.js?v=3 HTTP/1.1" 200 9000 "-" "-"',
    '198.51.100.4 - - [27/Oct/2026:01:02:03 +0000] "GET /docs/admin/configuration/ HTTP/1.1" 200 9 "-" "-"',
    '198.51.100.4 - - [27/Oct/2026:01:02:03 +0000] "GET /.well-known/acme-challenge/abc HTTP/1.1" 200 9 "-" "-"',
    '198.51.100.4 - - [27/Oct/2026:01:02:03 +0000] "GET /favicon.ico HTTP/1.1" 404 0 "-" "-"',
    '198.51.100.4 - - [27/Oct/2026:01:02:03 +0000] "GET /robots.txt HTTP/1.1" 404 0 "-" "-"',
    # a probe only in the referrer or the user agent: not the client's request
    '198.51.100.4 - - [27/Oct/2026:01:02:03 +0000] "GET / HTTP/1.1" 302 0 "https://x/.env" "wp-login.php"',
    "HANGUP after 0.03 from [85.217.149.30]:51634 in tests after SMTP handshake",
    "DNSBL rank 18 for [178.16.52.197]:54965",
    "lost connection after EHLO from unknown[192.0.2.9]",
])
def test_rules_leave_alone(line):
    assert match(line) is None


def test_rules_are_seeded(fake_redis, app):
    assert json.loads(fake_redis.get("F2B_REGEX")) == store.F2B_REGEX


def _channel(fake_redis):
    pubsub = fake_redis.pubsub()
    pubsub.subscribe("F2B_CHANNEL")
    pubsub.get_message()
    return pubsub


def test_exploit_is_refused_and_reported(client, fake_redis):
    pubsub = _channel(fake_redis)
    response = client.post("/login", data=RSC_BODY, environ_base={"REMOTE_ADDR": "34.85.18.1"})
    assert response.status_code == 400
    message = pubsub.get_message()
    assert message["data"] == "Crassostrea UI: Exploit attempt by 34.85.18.1"
    assert match(message["data"]) == ("5", "34.85.18.1", 1)
    # the header of a Next.js server action, on any path
    response = client.get("/", headers={"Next-Action": "x"}, environ_base={"REMOTE_ADDR": "34.85.18.2"})
    assert response.status_code == 400
    assert pubsub.get_message()["data"] == "Crassostrea UI: Exploit attempt by 34.85.18.2"
    # an ordinary failed login is not an exploit
    client.post("/login", data={"username": "admin", "password": "wrong"}, environ_base={"REMOTE_ADDR": "34.85.18.3"})
    assert "Invalid password" in pubsub.get_message()["data"]


def test_exploit_attempt_is_audited(client, fake_redis):
    from crassostrea.models import AuditEntry
    client.post("/login", data=RSC_BODY, environ_base={"REMOTE_ADDR": "34.85.18.1"})
    entry = AuditEntry.query.order_by(AuditEntry.id.desc()).first()
    assert (entry.ip, entry.outcome, entry.action) == ("34.85.18.1", "failed", "auth.login")


def test_administrators_input_is_not_checked(logged_in, api, fake_redis):
    from crassostrea.models import ListEntry, Recipient
    pubsub = _channel(fake_redis)
    # a logged-in administrator may save anything
    response = logged_in.post("/lists/", data={"list_type": "block", "kind": "sender",
                                               "value": "__proto__@example.com"})
    assert response.status_code == 302 and ListEntry.query.filter_by(value="__proto__@example.com").count() == 1
    # the REST API authenticates by key, its bodies are not checked either
    domain = api("POST", "/domains", json={"name": "example.com", "destination_host": "mail.internal",
                                           "recipient_check": "list"}).get_json()
    response = api("POST", f"/domains/{domain['id']}/recipients", json={"addresses": ["__proto__"]})
    assert response.status_code < 300 and Recipient.query.filter_by(address="__proto__@example.com").count() == 1
    assert pubsub.get_message() is None


def _load_logship():
    loader = importlib.machinery.SourceFileLoader("logship", str(REPO / "system" / "libexec" / "logship"))
    spec = importlib.util.spec_from_loader("logship", loader)
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


def test_logship_publishes_nginx_lines():
    logship = _load_logship()
    assert "SYSLOG_IDENTIFIER=crassostrea_access" in logship.journal_command("/tmp/x")
    line = '34.85.18.1 - - [28/Oct/2026:13:43:39 -0400] "GET /.git/config HTTP/1.1" 404 207 "-" "a\x07b"'
    published = logship.access_line({"SYSLOG_IDENTIFIER": "crassostrea_access", "MESSAGE": line})
    # paths are kept (Postfix lines have "/" replaced), control characters are not
    assert published == line.replace("\x07", "_")
    assert match(published) == ("9", "34.85.18.1", 1)
    assert logship.access_line({"SYSLOG_IDENTIFIER": "postfix/smtpd", "MESSAGE": "x"}) is None
