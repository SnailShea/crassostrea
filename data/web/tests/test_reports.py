"""DMARC and TLS reports: unpacking, parsing, storing once, summaries, the
DNS records to publish, the intake of the internal API, the page and the API."""
import gzip
import io
import json
import zipfile
from datetime import timedelta
from email.message import EmailMessage

import pytest

from crassostrea.extensions import db
from crassostrea.models import DmarcRecord, DmarcReport, Domain, TlsReport, set_setting, utcnow
from crassostrea.services import netcheck, reports

DMARC = b"""<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
  <report_metadata><org_name>google.com</org_name><email>noreply-dmarc-support@google.com</email>
    <report_id>%(id)s</report_id><date_range><begin>%(begin)d</begin><end>%(end)d</end></date_range></report_metadata>
  <policy_published><domain>example.com</domain><p>none</p></policy_published>
  <record><row><source_ip>192.0.2.10</source_ip><count>40</count>
      <policy_evaluated><disposition>none</disposition><dkim>pass</dkim><spf>pass</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from></identifiers></record>
  <record><row><source_ip>203.0.113.66</source_ip><count>7</count>
      <policy_evaluated><disposition>none</disposition><dkim>fail</dkim><spf>fail</spf></policy_evaluated></row>
    <identifiers><header_from>example.com</header_from><envelope_from>bad.example</envelope_from></identifiers></record>
</feedback>"""


def dmarc(report_id="r1", days_ago=1):
    end = int((utcnow() - timedelta(days=days_ago)).timestamp())
    return DMARC % {b"id": report_id.encode(), b"begin": end - 86400, b"end": end}


def tls(report_id="t1", domain="example.com"):
    end = utcnow() - timedelta(days=1)
    return json.dumps({
        "organization-name": "Google Inc.", "report-id": report_id,
        "date-range": {"start-datetime": (end - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                       "end-datetime": end.strftime("%Y-%m-%dT%H:%M:%SZ")},
        "policies": [{"policy": {"policy-type": "sts", "policy-domain": domain},
                      "summary": {"total-successful-session-count": 90, "total-failure-session-count": 3},
                      "failure-details": [{"result-type": "certificate-expired", "sending-mta-ip": "198.51.100.1",
                                           "receiving-mx-hostname": "mx.example.com", "failed-session-count": 3}]}],
    }).encode()


def message(*attachments):
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = "noreply@google.com", "reports@mx.example.com", "Report"
    msg.set_content("Report attached")
    for name, data, mtype in attachments:
        maintype, subtype = mtype.split("/")
        msg.add_attachment(data, maintype=maintype, subtype=subtype, filename=name)
    return bytes(msg)


def zipped(name, data):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr(name, data)
    return buf.getvalue()


@pytest.fixture
def domain(app):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    db.session.commit()


def test_ingest(app, domain):
    raw = message(("google.com!example.com!1!2.xml.zip", zipped("report.xml", dmarc()), "application/zip"),
                  ("tls.json.gz", gzip.compress(tls()), "application/tlsrpt+gzip"))
    assert reports.ingest(raw) == {"dmarc": 1, "tls": 1, "skipped": []}
    report = DmarcReport.query.one()
    assert (report.org, report.domain, report.policy, report.messages, report.passed) == (
        "google.com", "example.com", "none", 47, 40)
    bad = DmarcRecord.query.filter_by(source_ip="203.0.113.66").one()
    assert (bad.dkim, bad.spf, bad.envelope_from) == ("fail", "fail", "bad.example")
    tls_report = TlsReport.query.one()
    assert (tls_report.successful, tls_report.failed, json.loads(tls_report.failures)[0]["result"]) == (
        90, 3, "certificate-expired")
    # sent again: stored once
    assert reports.ingest(raw) == {"dmarc": 0, "tls": 0, "skipped": ["already stored", "already stored"]}


def test_refused_and_foreign(app, domain):
    foreign = dmarc("f1").replace(b"<domain>example.com</domain>", b"<domain>other.example</domain>")
    entity = b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">]><feedback>&lol;</feedback>'
    raw = message(("a.xml", foreign, "text/xml"), ("b.xml", entity, "text/xml"),
                  ("c.json", tls("t2", "other.example"), "application/json"),
                  ("d.xml", b"<feedback><broken", "text/xml"))
    result = reports.ingest(raw)
    assert (result["dmarc"], result["tls"]) == (0, 0)
    assert result["skipped"][:2] == ["not for a domain of this gateway", "XML with a DOCTYPE is refused"]
    assert result["skipped"][2] == "not for a domain of this gateway" and "invalid XML" in result["skipped"][3]
    # subdomains of a protected domain count
    sub = dmarc("s1").replace(b"<domain>example.com</domain>", b"<domain>news.example.com</domain>")
    assert reports.ingest(message(("s.xml", sub, "text/xml")))["dmarc"] == 1
    assert reports.ingest(message())["skipped"] == ["no report found"]


def test_unpack_limits(app, monkeypatch):
    monkeypatch.setattr(reports, "MAX_UNPACKED", 1000)
    with pytest.raises(reports.ReportError):
        reports.unpack(gzip.compress(b"x" * 5000))
    with pytest.raises(reports.ReportError):
        reports.unpack(zipped("big.xml", b"x" * 5000))
    assert reports.unpack(b"<feedback/>") == [b"<feedback/>"]


def test_summary_and_sources(app, domain):
    reports.ingest(message(("a.xml", dmarc("a"), "text/xml"), ("t.json", tls(), "application/json")))
    reports.ingest(message(("b.xml", dmarc("b", days_ago=60), "text/xml")))
    assert reports.summary(30) == {"example.com": {"dmarc_reports": 1, "messages": 47, "passed": 40,
                                                   "tls_reports": 1, "tls_ok": 90, "tls_failed": 3}}
    assert reports.summary(90)["example.com"]["messages"] == 94
    assert reports.failing_sources("example.com") == [("203.0.113.66", "example.com", 7)]
    assert reports.passing_sources("example.com", 90) == [("192.0.2.10", 80)]
    assert reports.tls_failures("example.com")[0]["mx"] == "mx.example.com"


def test_cleanup(app, domain):
    reports.ingest(message(("a.xml", dmarc("old", days_ago=400), "text/xml"), ("b.xml", dmarc("new"), "text/xml")))
    set_setting("report_retention_days", 180)
    db.session.commit()
    result = app.test_cli_runner().invoke(args=["cleanup"])
    assert result.exit_code == 0 and "1 DMARC/TLS report(s) older than 180 day(s)" in result.output
    assert [r.report_id for r in DmarcReport.query.all()] == ["new"] and DmarcRecord.query.count() == 2


def test_dns_records(app, monkeypatch):
    hostname = app.config["HOSTNAME"]
    records = {"_dmarc.example.com": ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"],
               f"_smtp._tls.example.com": [f"v=TLSRPTv1; rua=mailto:reports@{hostname}"]}

    def lookup(name, rdtype):
        if name in records:
            return records[name]
        raise netcheck.NoRecords(name)
    monkeypatch.setattr(netcheck, "lookup", lookup)
    checks = reports.dns_records("example.com")
    assert [c["name"] for c in checks] == ["_dmarc.example.com", f"example.com._report._dmarc.{hostname}",
                                           "_smtp._tls.example.com"]
    assert [c["ok"] for c in checks] == [False, False, True]
    assert checks[0]["found"] and "keeping its policy" in checks[0]["note"]
    assert checks[1]["expected"] == "v=DMARC1"


def test_internal_intake(internal_app, app, domain):
    client = internal_app.test_client()
    raw = message(("r.xml.gz", gzip.compress(dmarc()), "application/gzip"))
    response = client.post("/internal/reports", data=raw, content_type="message/rfc822",
                           environ_base={"REMOTE_ADDR": "127.0.0.1"})
    assert response.status_code == 200 and response.get_data(as_text=True) == "stored 1 DMARC and 0 TLS report(s)"
    assert client.post("/internal/reports", data=raw, environ_base={"REMOTE_ADDR": "198.51.100.7"}).status_code == 403
    assert client.post("/internal/reports", data=b"", environ_base={"REMOTE_ADDR": "127.0.0.1"}).status_code == 400


def test_map(app):
    from crassostrea.services.maps import build_intake
    assert json.loads(build_intake()) == {"addresses": {f"reports@{app.config['HOSTNAME']}": "reports"}}


def test_page_and_api(app, logged_in, api, domain, monkeypatch):
    monkeypatch.setattr(netcheck, "lookup", lambda name, rdtype: (_ for _ in ()).throw(netcheck.NoRecords(name)))
    reports.ingest(message(("a.xml", dmarc(), "text/xml"), ("t.json", tls(), "application/json")))
    page = logged_in.get("/reports/").get_data(as_text=True)
    assert "85.1%" in page and 'href="/reports/" class="active"' in page
    page = logged_in.get("/reports/?domain=example.com&days=7").get_data(as_text=True)
    assert "203.0.113.66" in page and "certificate-expired" in page and "missing" in page
    response = logged_in.post("/reports/settings", data={"report_retention_days": "90", "dmarc_send_reports": "y"},
                              follow_redirects=True)
    assert "Report settings saved" in response.get_data(as_text=True)
    body = api("GET", "/settings").get_json()
    assert (body["report_retention_days"], body["dmarc_send_reports"]) == (90, True)
    summary = api("GET", "/reports/summary?days=30").get_json()
    assert summary["domains"]["example.com"]["messages"] == 47 and summary["address"].startswith("reports@")
    dmarc_items = api("GET", "/reports/dmarc?domain=example.com").get_json()["items"]
    assert dmarc_items[0]["records"][1]["source_ip"] == "203.0.113.66"
    assert api("GET", "/reports/tls").get_json()["items"][0]["failures"][0]["count"] == 3
    assert api("GET", "/reports/summary?days=0").status_code == 400
