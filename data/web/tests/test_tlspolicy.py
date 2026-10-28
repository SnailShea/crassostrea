"""The TLS policy check: a fake postconf and a socketmap server that answers
like postfix-tlspol, with and without the attributes of Postfix 3.10."""
import socket
import threading

import pytest

from crassostrea.services import monitoring, tlspolicy

TLSRPT = ("secure match=lists.example.org servername=hostname policy_type=sts policy_domain=lists.example.org "
          "mx_host_pattern=lists.example.org { policy_string = version: STSv1 } { policy_string = mode: enforce }")


@pytest.fixture
def policy_service():
    """A socketmap server on loopback: answers[name] is the reply body for
    requests of that map name; the requests are recorded."""
    server = socket.create_server(("127.0.0.1", 0))
    state = {"port": server.getsockname()[1], "answers": {}, "requests": [], "raw": None}

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                data = conn.recv(65536)
                length, _, rest = data.partition(b":")
                request = rest[:int(length)].decode()
                state["requests"].append(request)
                name = request.split(" ", 1)[0]
                if state["raw"] is not None:
                    conn.sendall(state["raw"])
                    continue
                body = state["answers"].get(name, "NOTFOUND ").encode()
                # in two parts, as a socket may deliver it
                reply = f"{len(body)}:".encode() + body + b","
                conn.sendall(reply[:5])
                conn.sendall(reply[5:])

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    yield state
    server.close()


@pytest.fixture
def postfix(app, tmp_path):
    """postconf of a Postfix whose version and policy maps the test sets."""
    script = tmp_path / "postconf"

    def configure(version, maps):
        script.write_text(f"#!/bin/sh\nprintf '%s\\n' '{version}' '{maps}'\n")
        script.chmod(0o755)
        app.config["POSTCONF"] = str(script)
    return configure


def test_no_postfix_no_check(app):
    assert tlspolicy.check() is None
    assert "tls_policy" not in monitoring.check()


def test_attributes():
    assert tlspolicy.attributes("secure match=a:b servername=hostname") == ("secure", ["match", "servername"])
    assert tlspolicy.attributes(TLSRPT)[1][-3:] == ["mx_host_pattern", "policy_string", "policy_string"]
    assert tlspolicy.allowed((3, 8)) >= {"match", "servername", "connection_reuse"}
    assert "policy_type" not in tlspolicy.allowed((3, 8)) and "policy_type" in tlspolicy.allowed((3, 10))


def test_tlsrpt_answer_on_postfix_3_8_fails(app, postfix, policy_service):
    port = policy_service["port"]
    policy_service["answers"] = {"QUERYwithTLSRPT": f"OK {TLSRPT}", "QUERY": "OK secure match=lists.example.org"}
    postfix("3.8.5", f"socketmap:inet:127.0.0.1:{port}:QUERYwithTLSRPT")
    result = tlspolicy.check()
    assert result["ok"] is False
    assert "Postfix 3.8.5 does not understand" in result["message"]
    assert "policy_type, policy_domain, mx_host_pattern, policy_string" in result["message"]
    assert policy_service["requests"] == ["QUERYwithTLSRPT gmail.com"]
    assert monitoring.check()["tls_policy"]["ok"] is False
    assert monitoring.label("tls_policy") == "TLS policy lookups"
    # Postfix 3.10 understands it
    postfix("3.10.1", f"socketmap:inet:127.0.0.1:{port}:QUERYwithTLSRPT")
    assert tlspolicy.check() == {"ok": True, "message": "TLS policies are looked up (gmail.com: secure)"}


def test_plain_answer_passes(app, postfix, policy_service):
    port = policy_service["port"]
    policy_service["answers"] = {"QUERY": "OK secure match=smtp.google.com:.gmail-smtp-in.l.google.com "
                                          "servername=hostname"}
    postfix("3.8.5", f"hash:/etc/postfix/tls_policy, socketmap:inet:127.0.0.1:{port}:QUERY")
    assert tlspolicy.check() == {"ok": True, "message": "TLS policies are looked up (gmail.com: secure)"}
    app.config["TLS_POLICY_CHECK_DOMAIN"] = "example.net"
    policy_service["answers"] = {}
    assert tlspolicy.check() == {"ok": True, "message": "TLS policies are looked up (example.net: no policy found)"}
    assert policy_service["requests"][-1] == "QUERY example.net"


def test_failures(app, postfix, policy_service):
    port = policy_service["port"]
    postfix("3.8.5", f"socketmap:inet:127.0.0.1:{port}:QUERY")
    policy_service["answers"] = {"QUERY": "TEMP DNS lookup failed"}
    result = tlspolicy.check()
    assert result == {"ok": False, "message": "The TLS policy lookup of gmail.com fails (TEMP DNS lookup failed): "
                                              "Postfix defers mail whose policy it cannot look up"}
    policy_service["answers"] = {"QUERY": "OK bogus match=x"}
    assert "(level bogus)" in tlspolicy.check()["message"]
    policy_service["raw"] = b"garbage"
    assert tlspolicy.check() == {"ok": False, "message": "TLS policies cannot be looked up: the policy service on "
                                                         f"127.0.0.1:{port} sent an invalid answer"}
    # nothing listens
    closed = socket.create_server(("127.0.0.1", 0))
    free = closed.getsockname()[1]
    closed.close()
    postfix("3.8.5", f"socketmap:inet:127.0.0.1:{free}:QUERY")
    result = tlspolicy.check()
    assert result["ok"] is False and f"the policy service on 127.0.0.1:{free} does not answer" in result["message"]


def test_without_policy_service(app, postfix):
    postfix("3.8.5", "")
    assert tlspolicy.check() == {"ok": True, "message": "Postfix uses no TLS policy service"}


def test_metric(app, postfix, policy_service, monkeypatch):
    policy_service["answers"] = {"QUERY": f"OK {TLSRPT}"}
    postfix("3.8.5", f"socketmap:inet:127.0.0.1:{policy_service['port']}:QUERY")
    text = monitoring.render(monitoring.collect())
    assert "sf_tls_policy_ok 0" in text and "# TYPE sf_tls_policy_ok gauge" in text


def test_shipped_main_cf_uses_plain_query():
    """EL10's Postfix (3.8) does not understand the answer of QUERYwithTLSRPT."""
    from pathlib import Path
    main_cf = Path(__file__).resolve().parents[2] / "conf" / "postfix" / "main.cf"
    line = next(line for line in main_cf.read_text().splitlines() if line.startswith("smtp_tls_policy_maps"))
    assert line.endswith(":QUERY")
