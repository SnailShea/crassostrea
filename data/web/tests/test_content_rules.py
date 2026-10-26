"""Content rules: validation, the JSON for rspamd, the test with a pasted
message, the pages and the API."""
import json
import os

import pytest

from crassostrea.extensions import db
from crassostrea.models import ContentRule
from crassostrea.services import content_rules
from crassostrea.services.errors import ServiceError

SOURCE = """From: "Sales Team" <sales@partner.example>
To: bob@example.com
Subject: Your INVOICE 42
X-Mailer: MassMailer 2.0
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b1"

--b1
Content-Type: text/html; charset=utf-8

<p>Please make the <b>wire transfer</b> today: <a href="https://pay.example/now">pay</a></p>
--b1
Content-Type: application/octet-stream; name="invoice.pdf.exe"
Content-Disposition: attachment; filename="invoice.pdf.exe"

TVo=
--b1--
"""


def test_validation(app):
    rule = content_rules.add_rule(name="Invoice", field="subject", value="invoice", score=4)
    db.session.commit()
    assert (rule.match, rule.action, rule.direction, rule.active) == ("contains", "score", "inbound", True)
    for data, field in [
        ({"name": "Invoice", "field": "subject", "value": "x", "score": 1}, "name"),
        ({"name": "A", "field": "colour", "value": "x", "score": 1}, "field"),
        ({"name": "A", "field": "header", "value": "x", "score": 1}, "header"),
        ({"name": "A", "field": "header", "header": "Bad Header:", "value": "x", "score": 1}, "header"),
        ({"name": "A", "field": "subject", "value": "  ", "score": 1}, "value"),
        ({"name": "A", "field": "subject", "match": "regex", "value": "(", "score": 1}, "value"),
        ({"name": "A", "field": "subject", "match": "regex", "value": "/x/i", "score": 1}, "value"),
        ({"name": "A", "field": "subject", "value": "x"}, "score"),
        ({"name": "A", "field": "subject", "value": "x", "action": "delete"}, "action"),
        ({"name": "A", "field": "subject", "value": "x", "action": "reject", "message": "two\nlines"}, "message"),
        ({"name": 'A "b"', "field": "subject", "value": "x", "score": 1}, "name"),
    ]:
        with pytest.raises(ServiceError) as exc:
            content_rules.add_rule(**data)
        assert exc.value.field == field, data
        db.session.rollback()
    # a header name is dropped for other fields
    other = content_rules.add_rule(name="Body", field="body", header="X-Ignored", value="x", action="tag")
    assert other.header == ""


def test_json(app):
    content_rules.add_rule(name="B score", field="subject", value="x", score=2)
    content_rules.add_rule(name="Z reject", field="body", value="wire transfer", action="reject",
                           message="Looks like fraud")
    content_rules.add_rule(name="Off", field="subject", value="y", score=1, active=False)
    db.session.commit()
    data = json.loads(content_rules.build_json())["rules"]
    assert [r["name"] for r in data] == ["Z reject", "B score"]
    assert data[0] == {"name": "Z reject", "field": "body", "header": "", "match": "contains",
                       "value": "wire transfer", "action": "reject", "score": 0.0, "message": "Looks like fraud",
                       "direction": "inbound"}


def test_message_values_and_test(app):
    values = content_rules.message_values(SOURCE, "sales@partner.example", ["bob@example.com", ""])
    assert values["subject"] == ["Your INVOICE 42"] and values["from"] == ["Sales Team <sales@partner.example>"]
    assert values["header:x-mailer"] == ["MassMailer 2.0"] and values["attachment"] == ["invoice.pdf.exe"]
    assert "https://pay.example/now" in values["url"] and "wire transfer" in values["body"][0]
    assert values["recipient"] == ["bob@example.com"]
    for data in [dict(name="Subject", field="subject", value="invoice", score=4),
                 dict(name="Mailer", field="header", header="X-Mailer", match="regex", value="(?i)^mass ?mailer",
                      score=-2, direction="both"),
                 dict(name="Exe", field="attachment", match="equals", value="INVOICE.PDF.EXE", score=9),
                 dict(name="Link", field="url", value="pay.example", action="tag"),
                 dict(name="Out", field="subject", value="invoice", score=1, direction="outbound"),
                 dict(name="Nope", field="from", value="@other.example", score=1)]:
        content_rules.add_rule(**data)
    db.session.commit()
    results = {r["rule"].name: r["matched"] for r in content_rules.test(values)}
    assert results == {"Exe": True, "Link": True, "Mailer": True, "Nope": False, "Subject": True}
    assert {r["rule"].name for r in content_rules.test(values, "outbound")} == {"Mailer", "Out"}
    with pytest.raises(ServiceError):
        content_rules.message_values("   ")


def test_pages(app, logged_in):
    response = logged_in.post("/content-rules/new", data={
        "name": "Fraud", "field": "body", "match": "contains", "value": "wire transfer", "direction": "inbound",
        "action": "reject", "message": "Looks like fraud", "active": "y"}, follow_redirects=True)
    assert "Rule Fraud added" in response.get_data(as_text=True)
    path = os.path.join(app.config["RSPAMD_MAP_DIR"], "content_rules.json")
    assert json.load(open(path))["rules"][0]["message"] == "Looks like fraud"
    response = logged_in.post("/content-rules/new", data={
        "name": "Bad", "field": "subject", "match": "regex", "value": "(", "direction": "inbound",
        "action": "score", "score": "1"})
    assert response.status_code == 400 and "Invalid regular expression" in response.get_data(as_text=True)
    rule = ContentRule.query.filter_by(name="Fraud").one()
    page = logged_in.post("/content-rules/test", data={"source": SOURCE, "direction": "inbound"})
    assert '<span class="badge bad">matches</span>' in page.get_data(as_text=True)
    assert 'href="/content-rules/" class="active"' in page.get_data(as_text=True)
    logged_in.post(f"/content-rules/{rule.id}", data={
        "name": "Fraud", "field": "body", "match": "contains", "value": "wire transfer", "direction": "inbound",
        "action": "tag"})
    assert json.load(open(path))["rules"] == []  # turned off (the checkbox was not sent)
    logged_in.post(f"/content-rules/{rule.id}/delete")
    assert ContentRule.query.count() == 0


def test_api(api):
    response = api("POST", "/content-rules", json={"name": "Mailer", "field": "header", "header": "X-Mailer",
                                                   "value": "massmailer", "score": -1.5})
    assert response.status_code == 201
    rule_id = response.get_json()["id"]
    assert api("POST", "/content-rules", json={"name": "Mailer", "field": "subject", "value": "x",
                                               "score": 1}).status_code == 409
    assert api("PATCH", f"/content-rules/{rule_id}", json={"direction": "both"}).get_json()["direction"] == "both"
    results = api("POST", "/content-rules/test", json={"source": SOURCE, "recipients": ["bob@example.com"]})
    assert results.get_json()["results"] == [{"id": rule_id, "name": "Mailer", "active": True, "matched": True,
                                              "value": "MassMailer 2.0"}]
    assert api("POST", "/content-rules/test", json={"source": SOURCE, "recipients": "bob"}).status_code == 422
    assert api("DELETE", f"/content-rules/{rule_id}").status_code == 204
