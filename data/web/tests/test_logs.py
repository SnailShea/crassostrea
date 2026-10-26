"""Logs page: the Postfix log from Valkey and the journal of the other
services through the real log reader logic (system/libexec/log-reader) over a
unix socket, with journalctl replaced by a fake runner."""
import importlib.machinery
import importlib.util
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest

from crassostrea.services import logs

HELPER = Path(__file__).resolve().parents[3] / "system" / "libexec" / "log-reader"


def _load_helper():
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader("log_reader_helper", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


helper = _load_helper()


def record(message, unit="rspamd.service", priority=6, **extra):
    return json.dumps({"__REALTIME_TIMESTAMP": "1792670779158217", "MESSAGE": message, "PRIORITY": str(priority),
                       "_SYSTEMD_UNIT": unit, "SYSLOG_IDENTIFIER": "rspamd", "_PID": "42", **extra})


class FakeJournal:
    def __init__(self):
        self.calls = []
        self.lines = [record("lua; neural.lua: ANN trained"), record("cannot load map", priority=3),
                      record("Started rspamd.service", unit="init.scope", UNIT="rspamd.service")]

    def __call__(self, argv, **kwargs):
        self.calls.append(argv)
        return subprocess.CompletedProcess(argv, 0, "\n".join(self.lines) + "\n", "")


@pytest.fixture
def reader(app, tmp_path):
    """A socket served like systemd's Accept=yes: one handle() per connection."""
    path = str(tmp_path / "logs.sock")
    journal = FakeJournal()
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
                conn.sendall(json.dumps(helper.handle(raw, run=journal)).encode())

    threading.Thread(target=serve, daemon=True).start()
    app.config["LOG_READER_SOCKET"] = path
    yield journal
    server.close()


def test_journal_of_a_source(reader):
    entries = logs.journal("rspamd", lines=300, priority="warning")
    argv = reader.calls[0]
    assert argv[0] == "/usr/bin/journalctl" and "--lines=300" in argv and "--priority=warning" in argv
    assert "--unit=rspamd.service" in argv and "--reverse" in argv
    assert entries[0] == {"time": 1792670779.158217, "unit": "rspamd.service", "identifier": "rspamd", "pid": "42",
                          "priority": 6, "message": "lua; neural.lua: ANN trained"}
    # systemd's messages about the unit carry the unit, not init.scope
    assert entries[2]["unit"] == "rspamd.service"


def test_sources_are_the_helpers(reader):
    """Every source of the page but the Postfix log (Valkey) is one of the helper's."""
    assert {key for key, _, _ in logs.SOURCES} - {"postfix"} == set(helper.SOURCES)


@pytest.mark.parametrize("request_, error", [
    ({"source": "../etc/shadow"}, "unknown source"),
    ({"source": "rspamd", "unit": "sshd.service"}, None),  # extra keys are ignored, the units are the helper's
    ({"source": "rspamd", "lines": 5000}, "lines must be 1 to 2000"),
    ({"source": "rspamd", "lines": "10"}, "lines must be 1 to 2000"),
    ({"source": "rspamd", "priority": "--since=x"}, "unknown priority"),
    (["rspamd"], "request must be an object"),
])
def test_requests_are_validated(request_, error):
    journal = FakeJournal()
    response = helper.handle(json.dumps(request_).encode(), run=journal)
    if error:
        assert response == {"ok": False, "error": error} and journal.calls == []
    else:
        assert response["ok"] and [a for a in journal.calls[0] if a.startswith("--unit")] == ["--unit=rspamd.service"]


def test_message_bytes_and_bad_lines():
    entries = helper.parse(record([104, 105, 255]) + "\nnot json\n")
    assert entries[0]["message"] == "hi�" and len(entries) == 1


def test_logs_page_switches_service(logged_in, reader, fake_redis):
    fake_redis.lpush("POSTFIX_MAILLOG", json.dumps({"time": str(int(time.time())), "program": "postfix/smtpd",
                                                    "message": "connect from unknown[203.0.113.5]"}))
    page = logged_in.get("/logs").get_data(as_text=True)
    assert "connect from unknown" in page and 'aria-current="page">Postfix</a>' in page
    assert 'href="/logs?service=rspamd"' in page and 'service=cluster' not in page  # no cluster
    page = logged_in.get("/logs?service=rspamd&priority=err").get_data(as_text=True)
    assert "cannot load map" in page and 'aria-current="page">Rspamd</a>' in page
    assert '<span class="badge bad">err</span>' in page and "--priority=err" in reader.calls[-1]
    page = logged_in.get("/logs?service=rspamd&q=neural").get_data(as_text=True)
    assert "ANN trained" in page and "cannot load map" not in page
    # an unknown service shows the Postfix log
    assert 'aria-current="page">Postfix</a>' in logged_in.get("/logs?service=sshd").get_data(as_text=True)
    # Monitoring is the active group, Logs its tab
    assert 'class="active" aria-current="page">Logs</a>' in page


def test_logs_page_without_the_reader(logged_in, app, tmp_path):
    app.config["LOG_READER_SOCKET"] = str(tmp_path / "missing.sock")
    page = logged_in.get("/logs?service=nginx").get_data(as_text=True)
    assert "crassostrea-logs.socket" in page and "No log lines" in page
