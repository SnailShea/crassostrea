"""The web UI's queue client against the real control service logic
(system/libexec/postfix-control) over a unix socket, with Postfix commands
replaced by a fake runner."""
import importlib.machinery
import importlib.util
import json
import socket
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from crassostrea.services import postfix_control

HELPER = Path(__file__).resolve().parents[3] / "system" / "libexec" / "postfix-control"


def _load_helper():
    # no __pycache__ next to the helper: system/configure.sh deploys that directory
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader("postfix_control_helper", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


helper = _load_helper()

QUEUE_LINE = json.dumps({"queue_name": "deferred", "queue_id": "4F3A2B1C", "arrival_time": 1,
                         "message_size": 10, "sender": "a@example.com", "recipients": []})


class FakePostfix:
    def __init__(self):
        self.calls = []
        self.fail = False

    def __call__(self, argv, input=None, **kwargs):
        self.calls.append((argv, input))
        if self.fail:
            return subprocess.CompletedProcess(argv, 1, "", "postsuper: fatal: not allowed")
        stdout = QUEUE_LINE + "\n" if argv[1] == "-j" else ("*** ENVELOPE ***" if argv[0].endswith("postcat") else "")
        return subprocess.CompletedProcess(argv, 0, stdout, "")


@pytest.fixture
def control(app, tmp_path):
    """A socket served like systemd's Accept=yes: one handle() per connection."""
    path = str(tmp_path / "control.sock")
    postfix = FakePostfix()
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(path)
    server.listen()

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            with conn:
                raw = b"".join(iter(lambda: conn.recv(65536), b""))
                conn.sendall(json.dumps(helper.handle(raw, run=postfix)).encode())

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    app.config["POSTFIX_CONTROL_SOCKET"] = path
    yield postfix
    server.close()


def test_list_and_cat(control):
    assert postfix_control.mail_queue()[0]["queue_id"] == "4F3A2B1C"
    assert postfix_control.queue_message("4F3A2B1C") == "*** ENVELOPE ***"
    assert control.calls == [(["/usr/sbin/postqueue", "-j"], None), (["/usr/sbin/postcat", "-q", "4F3A2B1C"], None)]


def test_postsuper_gets_ids_on_stdin(control):
    postfix_control.queue_action("hold", ["4F3A2B1C", "4Z3Y2X1W0vz"])
    postfix_control.queue_action("delete", ["4F3A2B1C"])
    assert control.calls == [(["/usr/sbin/postsuper", "-h", "-"], "4F3A2B1C\n4Z3Y2X1W0vz\n"),
                             (["/usr/sbin/postsuper", "-d", "-"], "4F3A2B1C\n")]


def test_flush_and_super_delete_ignore_ids(control):
    postfix_control.queue_action("flush", ["4F3A2B1C"])
    postfix_control.queue_action("super_delete")
    assert control.calls == [(["/usr/sbin/postqueue", "-f"], None), (["/usr/sbin/postsuper", "-d", "ALL"], None)]


def test_deliver_runs_one_command_per_id(control):
    postfix_control.queue_action("deliver", ["4F3A2B1C", "5A6B7C8D"])
    assert [c[0] for c in control.calls] == [["/usr/sbin/postqueue", "-i", "4F3A2B1C"],
                                             ["/usr/sbin/postqueue", "-i", "5A6B7C8D"]]


@pytest.mark.parametrize("ids", [["ALL"], ["-d"], ["4F3A2B1C; rm"], ["4F3A2B1C\nALL"], [""], [7]])
def test_invalid_ids_are_refused_by_the_service(control, ids):
    # bypasses the client and view checks: the service must refuse on its own
    with pytest.raises(postfix_control.PostfixControlError, match="invalid queue IDs"):
        postfix_control._call("delete", ids)
    assert control.calls == []


@pytest.mark.parametrize("request_body,error", [
    (b'{"action": "shutdown", "ids": ["4F3A2B1C"]}', "unknown action"),
    (b'{"action": "delete"}', "no queue IDs given"),
    (b'{"action": "cat", "ids": ["4F3A2B1C", "5A6B7C8D"]}', "exactly one"),
    (b"not json", "invalid request"),
    (b"[]", "request must be an object"),
])
def test_helper_rejects_bad_requests(request_body, error):
    response = helper.handle(request_body, run=FakePostfix())
    assert response["ok"] is False and error in response["error"]


def test_command_failure_is_reported(control):
    control.fail = True
    with pytest.raises(postfix_control.PostfixControlError, match="not allowed"):
        postfix_control.queue_action("hold", ["4F3A2B1C"])


def test_unreachable_service(app, tmp_path):
    app.config["POSTFIX_CONTROL_SOCKET"] = str(tmp_path / "missing.sock")
    with pytest.raises(postfix_control.PostfixControlError, match="not reachable"):
        postfix_control.mail_queue()
