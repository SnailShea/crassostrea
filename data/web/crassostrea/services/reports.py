"""DMARC aggregate reports (RFC 7489) and TLS reports (RFC 8460) about the
protected domains.

Domains publish reports@<hostname> as their rua address. Postfix accepts
that address (inline tables on $myhostname in main.cf) and discards the
message after rspamd handed it to the internal API (intake.json,
data/conf/rspamd/lua/rspamd.local.lua), which calls ``ingest``: the
attachments (zip, gzip or plain) are unpacked within limits, DMARC XML and
TLS-RPT JSON are recognised by their content, and the reports about domains
of this gateway are stored once (a report sent twice counts once). Anyone
can send to the address, so nothing in a report is trusted beyond being
shown, and XML with a DOCTYPE is refused (entity expansion).

Because the address is not in the reporting domain, receivers check for
<domain>._report._dmarc.<hostname> TXT "v=DMARC1" (RFC 7489 7.1) before
sending DMARC reports: ``dns_records`` lists what to publish.
"""
import email
import gzip
import io
import json
import xml.etree.ElementTree as ET
import zipfile
from datetime import datetime, timedelta, timezone
from email import policy

from flask import current_app

from ..extensions import db
from ..models import DmarcRecord, DmarcReport, Domain, TlsReport, UserReport, get_setting, utcnow
from . import netcheck

ADDRESS_USER = "reports"
MAX_MESSAGE = 30 * 1024 * 1024
MAX_UNPACKED = 50 * 1024 * 1024
MAX_FILES = 20
MAX_RECORDS = 20000


class ReportError(ValueError):
    pass


def address(hostname=None):
    return f"{ADDRESS_USER}@{hostname or current_app.config['HOSTNAME']}"


# ---------------------------------------------------------------------------
# Unpacking
# ---------------------------------------------------------------------------

def _gunzip(data):
    with gzip.GzipFile(fileobj=io.BytesIO(data)) as handle:
        out = handle.read(MAX_UNPACKED + 1)
    if len(out) > MAX_UNPACKED:
        raise ReportError("gzip file too large")
    return out


def _unzip(data):
    files = []
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        members = [m for m in archive.infolist() if not m.is_dir()][:MAX_FILES]
        if sum(m.file_size for m in members) > MAX_UNPACKED:
            raise ReportError("zip file too large")
        for member in members:
            with archive.open(member) as handle:
                content = handle.read(MAX_UNPACKED + 1)
            if len(content) > MAX_UNPACKED:
                raise ReportError("zip file too large")
            files.append(content)
    return files


def unpack(data):
    """The report documents in an attachment (zip, gzip or plain)."""
    if data[:4] == b"PK\x03\x04":
        return _unzip(data)
    if data[:2] == b"\x1f\x8b":
        return [_gunzip(data)]
    return [data]


def documents(raw):
    """The DMARC (XML) and TLS (JSON) documents of a report message."""
    msg = email.message_from_bytes(raw, policy=policy.compat32)
    found = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        payload = part.get_payload(decode=True) or b""
        if not payload:
            continue
        try:
            for doc in unpack(payload):
                head = doc.lstrip()[:1]
                if head == b"<":
                    found.append(("dmarc", doc))
                elif head == b"{":
                    found.append(("tls", doc))
        except (zipfile.BadZipFile, OSError, EOFError, ReportError):
            continue
        if len(found) >= MAX_FILES:
            break
    return found


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------

def _ours(domain):
    """The protected domain a reported domain belongs to, or None."""
    domain = (domain or "").strip().lower().rstrip(".")
    for name, in db.session.query(Domain.name):
        if domain == name or domain.endswith("." + name):
            return domain
    return None


def _text(node, path, default=""):
    found = node.find(path)
    return (found.text or "").strip() if found is not None and found.text else default


def _timestamp(value):
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).replace(tzinfo=None)
    except (TypeError, ValueError, OverflowError, OSError):
        raise ReportError(f"invalid time {value!r}") from None


def parse_dmarc(doc):
    if b"<!DOCTYPE" in doc[:4096].upper() or b"<!ENTITY" in doc.upper():
        raise ReportError("XML with a DOCTYPE is refused")
    try:
        root = ET.fromstring(doc)
    except ET.ParseError as exc:
        raise ReportError(f"invalid XML: {exc}") from None
    if root.tag != "feedback":
        raise ReportError("not a DMARC report")
    report = {
        "org": _text(root, "report_metadata/org_name")[:255] or "unknown",
        "report_id": _text(root, "report_metadata/report_id")[:255],
        "begin": _timestamp(_text(root, "report_metadata/date_range/begin")),
        "end": _timestamp(_text(root, "report_metadata/date_range/end")),
        "domain": _text(root, "policy_published/domain").lower()[:253],
        "policy": _text(root, "policy_published/p")[:16],
        "records": [],
    }
    if not report["report_id"] or not report["domain"]:
        raise ReportError("report without id or domain")
    for record in root.findall("record")[:MAX_RECORDS]:
        try:
            count = int(_text(record, "row/count", "0"))
        except ValueError:
            continue
        report["records"].append({
            "source_ip": _text(record, "row/source_ip")[:64], "count": max(count, 0),
            "disposition": _text(record, "row/policy_evaluated/disposition", "none")[:16],
            "dkim": _text(record, "row/policy_evaluated/dkim")[:16],
            "spf": _text(record, "row/policy_evaluated/spf")[:16],
            "header_from": _text(record, "identifiers/header_from").lower()[:253],
            "envelope_from": _text(record, "identifiers/envelope_from").lower()[:253],
        })
    return report


def _rfc3339(value):
    try:
        parsed = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise ReportError(f"invalid time {value!r}") from None
    if parsed.tzinfo:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def parse_tls(doc):
    try:
        data = json.loads(doc)
    except ValueError as exc:
        raise ReportError(f"invalid JSON: {exc}") from None
    if not isinstance(data, dict) or "policies" not in data:
        raise ReportError("not a TLS report")
    dates = data.get("date-range") or {}
    report = {"org": str(data.get("organization-name") or "unknown")[:255],
              "report_id": str(data.get("report-id") or "")[:255],
              "begin": _rfc3339(dates.get("start-datetime")), "end": _rfc3339(dates.get("end-datetime")),
              "policies": []}
    if not report["report_id"]:
        raise ReportError("report without id")
    for item in (data.get("policies") or [])[:100]:
        if not isinstance(item, dict):
            continue
        pol, summary = item.get("policy") or {}, item.get("summary") or {}
        failures = [{"result": str(f.get("result-type", ""))[:64],
                     "mx": str(f.get("receiving-mx-hostname", ""))[:253],
                     "sender": str(f.get("sending-mta-ip", ""))[:64],
                     "count": int(f.get("failed-session-count") or 0)}
                    for f in (item.get("failure-details") or [])[:200] if isinstance(f, dict)]
        report["policies"].append({
            "domain": str(pol.get("policy-domain") or "").lower()[:253],
            "type": str(pol.get("policy-type") or "")[:16],
            "successful": int(summary.get("total-successful-session-count") or 0),
            "failed": int(summary.get("total-failure-session-count") or 0), "failures": failures})
    return report


# ---------------------------------------------------------------------------
# Storing
# ---------------------------------------------------------------------------

def _store_dmarc(report):
    if not _ours(report["domain"]):
        return "not for a domain of this gateway"
    if DmarcReport.query.filter_by(org=report["org"], report_id=report["report_id"]).first():
        return "already stored"
    records = [DmarcRecord(**r) for r in report["records"]]
    db.session.add(DmarcReport(
        org=report["org"], report_id=report["report_id"], domain=report["domain"], policy=report["policy"],
        begin=report["begin"], end=report["end"], messages=sum(r.count for r in records),
        passed=sum(r.count for r in records if "pass" in (r.dkim, r.spf)), records=records))
    return None


def _store_tls(report):
    stored, reasons = 0, []
    for item in report["policies"]:
        if not _ours(item["domain"]):
            reasons.append("not for a domain of this gateway")
            continue
        if TlsReport.query.filter_by(org=report["org"], report_id=report["report_id"],
                                     domain=item["domain"]).first():
            reasons.append("already stored")
            continue
        db.session.add(TlsReport(org=report["org"], report_id=report["report_id"], domain=item["domain"],
                                 policy_type=item["type"], begin=report["begin"], end=report["end"],
                                 successful=item["successful"], failed=item["failed"],
                                 failures=json.dumps(item["failures"])))
        stored += 1
    return stored, reasons


def ingest(raw):
    """Store the reports of a message: {"dmarc": n, "tls": n, "skipped": [reasons]}."""
    if len(raw) > MAX_MESSAGE:
        raise ReportError("message too large")
    result = {"dmarc": 0, "tls": 0, "skipped": []}
    for kind, doc in documents(raw):
        try:
            if kind == "dmarc":
                reason = _store_dmarc(parse_dmarc(doc))
                if reason:
                    result["skipped"].append(reason)
                else:
                    result["dmarc"] += 1
            else:
                stored, reasons = _store_tls(parse_tls(doc))
                result["tls"] += stored
                result["skipped"] += reasons
        except (ReportError, ValueError, TypeError) as exc:
            result["skipped"].append(str(exc)[:200])
    db.session.commit()
    if not result["dmarc"] and not result["tls"] and not result["skipped"]:
        result["skipped"].append("no report found")
    return result


def cleanup():
    """Delete reports older than report_retention_days. Returns (count, days)."""
    days = get_setting("report_retention_days")
    cutoff = utcnow() - timedelta(days=days)
    old = [r.id for r in DmarcReport.query.filter(DmarcReport.end < cutoff).with_entities(DmarcReport.id)]
    if old:
        DmarcRecord.query.filter(DmarcRecord.report_id.in_(old)).delete(synchronize_session=False)
        DmarcReport.query.filter(DmarcReport.id.in_(old)).delete(synchronize_session=False)
    tls = TlsReport.query.filter(TlsReport.end < cutoff).delete(synchronize_session=False)
    # reports of users are kept as long
    users = UserReport.query.filter(UserReport.at < cutoff).delete(synchronize_session=False)
    return len(old) + tls + users, days


# ---------------------------------------------------------------------------
# Summaries
# ---------------------------------------------------------------------------

def summary(days=30):
    """Per reported domain: DMARC messages and passes, TLS sessions."""
    since = utcnow() - timedelta(days=days)
    out = {}
    for domain, reports, messages, passed in (
            db.session.query(DmarcReport.domain, db.func.count(DmarcReport.id), db.func.sum(DmarcReport.messages),
                             db.func.sum(DmarcReport.passed))
            .filter(DmarcReport.end >= since).group_by(DmarcReport.domain)):
        out.setdefault(domain, {}).update(dmarc_reports=reports, messages=int(messages or 0),
                                          passed=int(passed or 0))
    for domain, reports, ok, failed in (
            db.session.query(TlsReport.domain, db.func.count(TlsReport.id), db.func.sum(TlsReport.successful),
                             db.func.sum(TlsReport.failed))
            .filter(TlsReport.end >= since).group_by(TlsReport.domain)):
        out.setdefault(domain, {}).update(tls_reports=reports, tls_ok=int(ok or 0), tls_failed=int(failed or 0))
    return dict(sorted(out.items()))


def failing_sources(domain, days=30, limit=20):
    """Sources whose mail failed DMARC for ``domain``: [(ip, header_from, messages)]."""
    since = utcnow() - timedelta(days=days)
    rows = (db.session.query(DmarcRecord.source_ip, DmarcRecord.header_from, db.func.sum(DmarcRecord.count))
            .join(DmarcReport).filter(DmarcReport.domain == domain, DmarcReport.end >= since,
                                      DmarcRecord.dkim != "pass", DmarcRecord.spf != "pass")
            .group_by(DmarcRecord.source_ip, DmarcRecord.header_from)
            .order_by(db.func.sum(DmarcRecord.count).desc()).limit(limit))
    return [(ip, header_from, int(count)) for ip, header_from, count in rows]


def passing_sources(domain, days=30, limit=20):
    since = utcnow() - timedelta(days=days)
    rows = (db.session.query(DmarcRecord.source_ip, db.func.sum(DmarcRecord.count))
            .join(DmarcReport).filter(DmarcReport.domain == domain, DmarcReport.end >= since,
                                      db.or_(DmarcRecord.dkim == "pass", DmarcRecord.spf == "pass"))
            .group_by(DmarcRecord.source_ip).order_by(db.func.sum(DmarcRecord.count).desc()).limit(limit))
    return [(ip, int(count)) for ip, count in rows]


def tls_failures(domain, days=30, limit=50):
    since = utcnow() - timedelta(days=days)
    failures = []
    for report in (TlsReport.query.filter(TlsReport.domain == domain, TlsReport.end >= since, TlsReport.failed > 0)
                   .order_by(TlsReport.end.desc()).limit(limit)):
        for failure in json.loads(report.failures or "[]"):
            failures.append({**failure, "org": report.org, "end": report.end})
    return failures


def recent(domain, limit=50):
    dmarc = DmarcReport.query.filter_by(domain=domain).order_by(DmarcReport.end.desc()).limit(limit).all()
    tls = TlsReport.query.filter_by(domain=domain).order_by(TlsReport.end.desc()).limit(limit).all()
    return dmarc, tls


# ---------------------------------------------------------------------------
# DNS
# ---------------------------------------------------------------------------

def _txt(name, prefix):
    try:
        return [t for t in netcheck.lookup(name, "TXT") if t.lower().startswith(prefix.lower())]
    except netcheck.NoRecords:
        return []
    except netcheck.LookupFailed:
        return None


def dns_records(domain, hostname=None):
    """What ``domain`` should publish to get its reports here, and what it
    publishes: [{name, expected, found (list, None if the lookup failed), ok}]."""
    hostname = hostname or current_app.config["HOSTNAME"]
    rua = f"mailto:{address(hostname)}"
    checks = []
    dmarc = _txt(f"_dmarc.{domain}", "v=DMARC1")
    checks.append({"name": f"_dmarc.{domain}", "expected": f"v=DMARC1; p=none; rua={rua}", "found": dmarc,
                   "ok": bool(dmarc) and any(rua.lower() in t.lower() for t in dmarc),
                   "note": "Add the rua address to the existing record, keeping its policy." if dmarc else ""})
    if not (domain == hostname or hostname.endswith("." + domain)):
        name = f"{domain}._report._dmarc.{hostname}"
        found = _txt(name, "v=DMARC1")
        checks.append({"name": name, "expected": "v=DMARC1", "found": found, "ok": bool(found),
                       "note": f"In the zone of {hostname}: allows reports for {domain} to go to this address."})
    tls = _txt(f"_smtp._tls.{domain}", "v=TLSRPTv1")
    checks.append({"name": f"_smtp._tls.{domain}", "expected": f"v=TLSRPTv1; rua={rua}", "found": tls,
                   "ok": bool(tls) and any(rua.lower() in t.lower() for t in tls), "note": ""})
    return checks
