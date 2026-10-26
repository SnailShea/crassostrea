"""Statistics over time: counting logged mail, buckets of a range, the
retention, the page and the API."""
import io
import json
from datetime import datetime, timedelta

from crassostrea.extensions import db
from crassostrea.models import Domain, MailLogEntry, StatBucket, set_setting, utcnow
from crassostrea.services import stats

RAW = b"From: a@sender.example\r\nTo: bob@example.com\r\nSubject: Hi\r\n\r\nHello\r\n"


def post(internal_app, action="no action", rcpt="bob@example.com", sender="a@sender.example", symbols=None):
    meta = {"qid": "Q1", "from": sender, "rcpt": [rcpt], "score": 1.0, "action": action, "ip": "203.0.113.5",
            "symbols": symbols or [{"name": "BAYES_HAM", "score": -1}]}
    return internal_app.test_client().post(
        "/internal/mail-log", data={"metadata": json.dumps(meta), "message": (io.BytesIO(RAW), "message")},
        environ_base={"REMOTE_ADDR": "172.22.1.5"})


def counts():
    return {(b.domain, b.direction, b.category): (b.messages, b.viruses) for b in StatBucket.query.all()}


def test_logged_mail_is_counted(internal_app, app):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    db.session.commit()
    for action in ("no action", "no action", "add header", "greylist", "soft reject", "reject"):
        assert post(internal_app, action).status_code == 200
    post(internal_app, "reject", symbols=[{"name": "CLAM_VIRUS", "score": 20}])
    post(internal_app, "no action", rcpt="x@partner.example", sender="alice@example.com",
         symbols=[{"name": "RELAY_NETWORK", "score": 0}])
    assert counts() == {("example.com", "inbound", "clean"): (2, 0), ("example.com", "inbound", "spam"): (1, 0),
                        ("example.com", "inbound", "deferred"): (2, 0), ("example.com", "inbound", "rejected"): (2, 1),
                        ("example.com", "outbound", "clean"): (1, 0)}
    assert StatBucket.query.first().hour.minute == 0


def test_series(app):
    now = datetime(2026, 10, 21, 10, 30)
    rows = [(now - timedelta(hours=1), "example.com", "inbound", "clean", 10),
            (now - timedelta(hours=1), "example.com", "inbound", "rejected", 3),
            (now - timedelta(hours=30), "other.example", "inbound", "spam", 4),
            (now - timedelta(days=20), "example.com", "outbound", "clean", 7),
            (now - timedelta(days=400), "example.com", "inbound", "clean", 99)]
    for hour, domain, direction, cat, messages in rows:
        db.session.add(StatBucket(hour=hour.replace(minute=0), domain=domain, direction=direction, category=cat,
                                  messages=messages, bytes=messages * 1000, viruses=0))
    db.session.commit()
    day = stats.series("24h", now=now)
    assert len(day["buckets"]) == 24 and day["totals"]["total"] == 13 and day["totals"]["rejected"] == 3
    assert day["buckets"][-2]["clean"] == 10 and day["buckets"][-1]["total"] == 0
    week = stats.series("7d", now=now)
    assert week["totals"]["total"] == 17 and week["top"] == [("example.com", 13), ("other.example", 4)]
    month = stats.series("30d", now=now)
    assert month["totals"]["total"] == 24 and month["buckets"][0]["start"].hour == 0
    assert stats.series("30d", direction="outbound", now=now)["totals"]["total"] == 7
    assert stats.series("12m", domain="other.example", now=now)["totals"]["total"] == 4
    chart = stats.chart(day)
    tall = chart["bars"][-2]
    assert chart["peak"] == 13 and [s[0] for s in tall["segments"]] == ["clean", "rejected"]
    assert round(sum(s[2] for s in tall["segments"])) == chart["height"]


def test_retention(app):
    db.session.add_all([StatBucket(hour=utcnow() - timedelta(days=800), domain="", direction="inbound",
                                   category="clean", messages=1, bytes=0, viruses=0),
                        StatBucket(hour=utcnow().replace(minute=0, second=0, microsecond=0), domain="",
                                   direction="inbound", category="clean", messages=1, bytes=0, viruses=0)])
    set_setting("stats_retention_days", 730)
    db.session.commit()
    result = app.test_cli_runner().invoke(args=["cleanup"])
    assert result.exit_code == 0 and "1 hourly statistic(s) older than 730 day(s)" in result.output
    assert StatBucket.query.count() == 1


def test_page_and_api(app, logged_in, api):
    db.session.add(StatBucket(hour=utcnow().replace(minute=0, second=0, microsecond=0), domain="example.com",
                              direction="inbound", category="rejected", messages=5, bytes=5000, viruses=2))
    db.session.commit()
    page = logged_in.get("/?range=24h").get_data(as_text=True)
    assert '<rect class="rejected"' in page and "example.com" in page and 'class="active">Dashboard</a>' in page
    body = api("GET", "/statistics?range=24h&domain=example.com").get_json()
    assert body["totals"]["rejected"] == 5 and body["totals"]["viruses"] == 2 and len(body["buckets"]) == 24
    assert body["top_domains"] == [{"domain": "example.com", "messages": 5}]
    assert api("GET", "/statistics?range=5y").status_code == 400
    assert api("PATCH", "/settings", json={"stats_retention_days": 10}).status_code == 422
