"""The dashboard's statistics of the gateway itself: the mail queue by
direction, the use of CPU, memory and storage and how long scanning and
delivery took, hourly or daily."""
import io
import time
import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, MailLogEntry, StatBucket, utcnow
from crassostrea.services import deliveries, monitoring, postfix_control, rspamd, system
from crassostrea.template_helpers import _latency

def _item(qid, queue, rcpt, size=1000, waited=0):
    return {"queue_name": queue, "queue_id": qid, "arrival_time": int(time.time() - waited), "message_size": size,
            "sender": "a@sender.example", "recipients": [{"address": rcpt, "delay_reason": ""}]}


def queue_items():
    return [
        _item("AAAAAA1111", "deferred", "bob@example.com", waited=7200),  # outbound in the mail log
        _item("BBBBBB2222", "active", "alice@Example.com", size=3000),  # not logged, to a protected domain
        _item("CCCCCC3333", "hold", "x@partner.example"),
        _item("DDDDDD4444", "incoming", "a@sender.example"),  # a bounce to the sender
        _item("EEEEEE5555", "deferred", "carol@example.com", waited=600),
    ]

RESOURCES = {"cpu_percent": 37.5,
             "memory": {"total_bytes": 8 * 1024 ** 3, "used_bytes": 7 * 1024 ** 3, "percent": 87.5},
             "disks": [{"path": "/var", "used_percent": 93.0, "free_bytes": 3 * 1024 ** 3,
                        "total_bytes": 50 * 1024 ** 3}]}


@pytest.fixture
def gateway(app):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    db.session.add(MailLogEntry(qid="AAAAAA1111", direction="outbound", sender="dave@example.com",
                                rcpts="bob@example.com", action="no action", message=b"x"))
    db.session.add(MailLogEntry(qid="EEEEEE5555", direction="inbound", sender="a@sender.example",
                                rcpts="carol@example.com", action="no action", message=b"x"))
    db.session.commit()


def test_queue_by_direction(gateway):
    queue = monitoring.queue_directions(queue_items())
    assert {k: v for k, v in queue["inbound"].items() if v} == {"active": 1, "deferred": 1, "total": 2,
                                                                 "bytes": 4000}
    assert {k: v for k, v in queue["outbound"].items() if v} == {"deferred": 1, "hold": 1, "incoming": 1,
                                                                  "total": 3, "bytes": 3000}
    assert 7190 < queue["oldest_deferred"] < 7300
    assert monitoring.queue_directions([])["oldest_deferred"] == 0


def test_cpu_percent(monkeypatch):
    counters = iter([(100, 1000), (175, 1100), (175, 1100), (175, 1100)])
    monkeypatch.setattr(system, "_cpu_counters", lambda: next(counters))
    slept = []
    monkeypatch.setattr(system.time, "sleep", slept.append)
    assert system.cpu_percent() == 75.0 and slept == [0.25]
    assert system.cpu_percent() == 0.0  # no time passed: no division by zero


def test_memory_and_disks(monkeypatch):
    meminfo = "MemTotal:        8000000 kB\nMemFree:          500000 kB\nMemAvailable:    2000000 kB\n"
    monkeypatch.setattr(system, "open", lambda *a, **kw: io.StringIO(meminfo), raising=False)
    assert system.memory() == {"total_bytes": 8192000000, "used_bytes": 6144000000, "percent": 75.0}
    monkeypatch.undo()
    disks = system.disks()
    assert disks[0]["path"] == "/" and 0 <= disks[0]["used_percent"] <= 100
    assert 0 < disks[0]["free_bytes"] <= disks[0]["total_bytes"]
    assert len({d["path"] for d in disks}) == len(disks)


def test_resources_survive_a_part_that_fails(app, monkeypatch):
    def fail():
        raise OSError("no /proc")
    monkeypatch.setattr(system, "memory", fail)
    monkeypatch.setattr(system, "cpu_percent", lambda: 12.0)
    resources = system.resources()
    assert resources["memory"] is None and resources["cpu_percent"] == 12.0


@pytest.mark.parametrize("seconds, text", [(None, "–"), (0.32, "320 ms"), (4.25, "4.2 s"), (600, "10 min"),
                                           (7200, "2 h")])
def test_latency(seconds, text):
    assert _latency(seconds) == text


@pytest.fixture
def backends(monkeypatch, fake_redis):
    monkeypatch.setattr(rspamd.RspamdClient, "stat", lambda self: {"scanned": 10, "learned": 2})
    monkeypatch.setattr(postfix_control, "mail_queue", queue_items)
    monkeypatch.setattr(system, "resources", lambda: RESOURCES)


def test_dashboard(logged_in, gateway, backends):
    hour = utcnow().replace(minute=0, second=0, microsecond=0)
    db.session.add(StatBucket(hour=hour, domain="example.com", direction="inbound", category="clean", messages=4,
                              bytes=0, viruses=0, scan_ms=1000))
    db.session.commit()
    deliveries.record({"time": int(time.time()), "kind": "delivery", "qid": "EEEEEE5555", "rcpt": "carol@example.com",
                       "status": "sent", "dsn": "2.0.0", "relay": "mx.internal[10.0.0.5]:25", "detail": "250 Ok",
                       "delay": 4.2})
    db.session.commit()
    page = logged_in.get("/").get_data(as_text=True)
    assert "<dt>Scan</dt><dd>250 ms</dd>" in page and "<dt>Delivery</dt><dd>4.2 s" in page and "over 1 delivery" in page
    assert "Averages of the last 24 hours" in page
    queue = page.split("<h2>Mail queue</h2>")[1].split("</table>")[0]
    assert '<td>Being delivered</td><td class="num">1</td><td class="num">1</td>' in queue
    assert '<td>Deferred</td><td class="num">1</td><td class="num">1</td>' in queue
    assert "The oldest deferred message waits 2 h" in page
    system_card = page.split("<h2>System load</h2>")[1].split("</dl>")[0]
    assert "38%" in system_card and "load" not in system_card and "CPUs" not in system_card
    assert 'class="warn" width="87.5"' in system_card and "88% of 8.0 GiB" in system_card
    assert 'class="bad" width="93.0"' in system_card and "3.0 GiB free of 50.0 GiB" in system_card
    # hourly: the averages of the hour, a bar each
    graph = page.split("<h2>Over time</h2>")[1]
    assert '<option value="hourly" selected>' in graph and "data-autosubmit" in graph
    assert graph.count('<rect class="scan"') == 1 and graph.count('<rect class="delivery"') == 1
    assert "Average scan time <span class=\"muted small\">at most 250 ms" in graph
    assert "Average delivery time <span class=\"muted small\">at most 4.2 s" in graph
    # no filter, no refresh
    assert 'name="direction"' not in page and 'name="domain"' not in page and "data-live" not in page
    page = logged_in.get("/?view=daily").get_data(as_text=True)
    assert '<option value="daily" selected>' in page and "Averages of the last 30 days" in page
    assert "at most 4 per day" in page and "<dt>Scan</dt><dd>250 ms</dd>" in page
    assert '<option value="hourly" selected>' in logged_in.get("/?view=weekly").get_data(as_text=True)


def test_dashboard_without_the_queue(logged_in, backends, monkeypatch):
    def fail():
        raise postfix_control.PostfixControlError("Postfix control service is not reachable")
    monkeypatch.setattr(postfix_control, "mail_queue", fail)
    page = logged_in.get("/").get_data(as_text=True)
    assert "The mail queue cannot be read: Postfix control service is not reachable" in page
    assert "System load" in page

