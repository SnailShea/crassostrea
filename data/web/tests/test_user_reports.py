"""Messages users report to spam@ and ham@<hostname>: who may report,
attached messages, learning, limits, confirmations, the page and the API."""
import base64
import email
import json
from email.message import EmailMessage

import dkim
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, UserReport, set_setting
from crassostrea.services import mailer, netcheck, user_reports
from crassostrea.services.maps import build_intake

SPAM = b"From: Winner <win@lottery.example>\r\nTo: bob@example.com\r\nSubject: You won\r\n\r\nClaim now\r\n"


def report(*attachments, sender="bob@example.com", inline=False):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = sender, "spam@mx.example.com", "FW: spam"
    msg.set_content("This is spam" + ("\n\n" + SPAM.decode() if inline else ""))
    for data in attachments:
        if isinstance(data, tuple):
            msg.add_attachment(data[1], maintype="application", subtype="octet-stream", filename=data[0])
        else:
            msg.add_attachment(email.message_from_bytes(data))
    return bytes(msg)


@pytest.fixture
def setup(app, monkeypatch):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    set_setting("user_reports_enabled", 1)
    db.session.commit()
    learned, sent = [], []
    monkeypatch.setattr(user_reports, "train", lambda message, spam: learned.append((message, spam)) or ["ok"])
    monkeypatch.setattr(mailer, "reinject", lambda sender, rcpt, message: sent.append((sender, rcpt, message)))
    monkeypatch.setattr(netcheck, "spf_evaluate", lambda ip, domain: "pass" if ip == "198.51.100.25" else "fail")
    return {"learned": learned, "sent": sent}


def post(internal_app, raw, kind="spam", sender="bob@example.com", ip="203.0.113.9", relay="no"):
    return internal_app.test_client().post(
        f"/internal/learn/{kind}", data=raw, content_type="message/rfc822", environ_base={"REMOTE_ADDR": "127.0.0.1"},
        headers={"X-Envelope-From": sender, "X-Client-IP": ip, "X-Relay-Network": relay})


def test_from_a_relay_network(internal_app, setup):
    response = post(internal_app, report(SPAM, ("other.eml", SPAM)), relay="yes")
    assert response.get_data(as_text=True) == "learned: 2 learned"
    assert [spam for _, spam in setup["learned"]] == [True, True] and b"You won" in setup["learned"][0][0]
    row = UserReport.query.one()
    assert (row.reporter, row.kind, row.status, row.learned) == ("bob@example.com", "spam", "learned", 2)
    assert row.subjects == "You won; You won" and row.detail == "Accepted (relay network)"
    sender, rcpt, message = setup["sent"][0]
    assert rcpt == "bob@example.com" and b"2 message(s) learned as spam" in message


def test_who_may_report(internal_app, setup):
    assert post(internal_app, report(SPAM), ip="198.51.100.25").get_data(as_text=True).startswith("learned")
    # an outsider, or a forged protected sender without SPF or DKIM, may not
    assert post(internal_app, report(SPAM, sender="x@outside.example"), sender="x@outside.example",
                relay="yes").get_data(as_text=True).startswith("refused")
    assert post(internal_app, report(SPAM)).get_data(as_text=True).startswith("refused")
    assert len(setup["learned"]) == 1
    # refused reporters get no reply (they may be forged)
    assert len(setup["sent"]) == 1


def test_dkim_signed_report(internal_app, setup, monkeypatch):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL,
                                serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.DER,
                                           serialization.PublicFormat.SubjectPublicKeyInfo)

    record = b"v=DKIM1; k=rsa; p=" + base64.b64encode(public)
    monkeypatch.setattr(user_reports, "_dkim_txt", lambda name, timeout=5: record
                        if name == b"s1._domainkey.example.com." else None)
    raw = report(SPAM)
    signed = dkim.sign(raw, b"s1", b"example.com", private, include_headers=[b"from", b"to", b"subject"]) + raw
    assert post(internal_app, signed).get_data(as_text=True) == "learned: 1 learned"
    assert UserReport.query.one().detail == "Accepted (DKIM)"
    # a signature of another domain does not count
    other = dkim.sign(raw, b"s1", b"other.example", private, include_headers=[b"from"]) + raw
    assert post(internal_app, other).get_data(as_text=True).startswith("refused")


def test_inline_and_limits(internal_app, setup):
    assert post(internal_app, report(inline=True), relay="yes", kind="ham").get_data(as_text=True).startswith("empty")
    assert b"as an attachment" in setup["sent"][-1][2]
    set_setting("user_reports_per_hour", 2)
    db.session.commit()
    post(internal_app, report(SPAM, SPAM), relay="yes")
    assert post(internal_app, report(SPAM), relay="yes").get_data(as_text=True).startswith("refused")
    assert "reports in an hour" in UserReport.query.order_by(UserReport.id.desc()).first().detail
    assert post(internal_app, b"x", kind="viruses").status_code == 404


def test_off(internal_app, setup):
    set_setting("user_reports_enabled", 0)
    db.session.commit()
    assert post(internal_app, report(SPAM), relay="yes").get_data(as_text=True).startswith("refused")
    assert setup["learned"] == [] and setup["sent"] == []


def test_intake_map(app, setup):
    hostname = app.config["HOSTNAME"]
    assert json.loads(build_intake())["addresses"] == {f"reports@{hostname}": "reports",
                                                       f"spam@{hostname}": "spam", f"ham@{hostname}": "ham"}


def test_page_and_api(app, logged_in, api, internal_app, setup):
    post(internal_app, report(SPAM), relay="yes")
    page = logged_in.get("/training/").get_data(as_text=True)
    assert f"spam@{app.config['HOSTNAME']}" in page and "1 learned" in page
    response = logged_in.post("/training/reports", data={"reports-user_reports_enabled": "y",
                                                         "reports-user_reports_per_hour": "10"},
                              follow_redirects=True)
    assert "Reporting saved" in response.get_data(as_text=True)
    body = api("GET", "/settings").get_json()
    assert (body["user_reports_enabled"], body["user_reports_confirm"], body["user_reports_per_hour"]) == (
        True, False, 10)
    items = api("GET", "/user-reports").get_json()["items"]
    assert items[0]["status"] == "learned" and items[0]["reporter"] == "bob@example.com"
