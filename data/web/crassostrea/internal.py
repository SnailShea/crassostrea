"""Internal API used by rspamd. Served on a port that is not proxied by nginx."""
import ipaddress
import json
import socket
import time
from email.utils import formatdate, parsedate_to_datetime

from flask import Blueprint, Response, abort, current_app, request

from .extensions import db
from .models import Domain, QuarantineItem, get_setting
from .services import deliveries, journal, maillog, reports, siem, user_reports
from .services.maps import render_rspamd_settings

bp = Blueprint("internal", __name__, url_prefix="/internal")


@bp.before_request
def only_internal_clients():
    # Bound to loopback, where rspamd connects from; an rspamd on another
    # host must be listed in INTERNAL_CLIENTS
    try:
        addr = ipaddress.ip_address(request.remote_addr or "")
    except ValueError:
        abort(403)
    if not (addr.is_loopback or addr in _client_addresses(addr)):
        abort(403)


_RESOLVE_INTERVAL = 5


def _client_addresses(addr):
    """Addresses of INTERNAL_CLIENTS (host names or IPs).

    Resolved again when an unknown address asks (a host may get a new
    address), but at most every few seconds.
    """
    resolved = current_app.extensions.setdefault("internal_clients", {"at": None, "addresses": frozenset()})
    now = time.monotonic()
    if addr in resolved["addresses"] or (resolved["at"] is not None and now - resolved["at"] < _RESOLVE_INTERVAL):
        return resolved["addresses"]
    addresses = set()
    for host in current_app.config["INTERNAL_CLIENTS"]:
        try:
            infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        except OSError as exc:
            current_app.logger.warning("cannot resolve internal client %s: %s", host, exc)
            continue
        addresses.update(ipaddress.ip_address(info[4][0].split("%")[0]) for info in infos)
    resolved.update(at=now, addresses=frozenset(addresses))
    return resolved["addresses"]


@bp.get("/rspamd/settings")
def rspamd_settings():
    updated_at = get_setting("config_updated_at")
    since = request.headers.get("If-Modified-Since")
    if since and updated_at:
        try:
            if int(parsedate_to_datetime(since).timestamp()) >= updated_at:
                return Response(status=304)
        except (TypeError, ValueError):
            pass
    response = Response(render_rspamd_settings(), mimetype="text/plain")
    if updated_at:
        response.headers["Last-Modified"] = formatdate(updated_at, usegmt=True)
    return response


def _exported_message(purpose):
    """rspamd metadata_exporter (multipart formatter): 'metadata' JSON +
    'message'. Returns (metadata, message), or None for a bad request."""
    upload = request.files.get("message")
    try:
        meta = json.loads(request.form.get("metadata", ""))
    except ValueError:
        meta = None
    if not isinstance(meta, dict) or upload is None:
        current_app.logger.error("%s: invalid request from rspamd", purpose)
        return None
    return meta, upload.read()


def _is_outbound(meta):
    """Mail from a relay network is outbound (sent by the protected organisation)."""
    return "RELAY_NETWORK" in _symbol_names(meta.get("symbols"))


@bp.post("/mail-log")
def maillog_ingest():
    """Every scanned message, for the mail log."""
    exported = _exported_message("mail log")
    if exported is None:
        return "invalid request", 400
    meta, raw = exported
    entry = maillog.store(meta, raw, "outbound" if _is_outbound(meta) else "inbound")
    db.session.commit()
    siem.enqueue("mail_log", siem.mail_event(entry))
    journal.enqueue(entry)
    return f"stored {entry.id}", 200


@bp.post("/refused-recipient")
def refused_recipient():
    """A recipient Postfix refused because it does not exist, found in the
    Postfix log by system/libexec/logship (JSON: time, ip, sender, rcpt,
    reason). Answers 200 also for events it does not keep (another domain, an
    unknown reason), so logship never retries them."""
    event = request.get_json(silent=True)
    if not isinstance(event, dict):
        return "invalid request", 400
    entry = maillog.store_refused(event)
    if entry is None:
        return "skipped", 200
    db.session.commit()
    siem.enqueue("mail_log", siem.mail_event(entry))
    return f"stored {entry.id}", 200


@bp.post("/delivery")
def delivery_event():
    """A delivery attempt or a notice to the sender, from the Postfix log
    (system/libexec/logship, services/deliveries.py). 200 also for events it
    does not keep, so logship never retries them."""
    event = request.get_json(silent=True)
    if not isinstance(event, dict):
        return "invalid request", 400
    if deliveries.record(event) is None:
        return "skipped", 200
    db.session.commit()
    return "stored", 200


@bp.post("/quarantine")
def quarantine_ingest():
    """Rejected messages, one quarantine item per recipient."""
    exported = _exported_message("quarantine")
    if exported is None:
        return "invalid request", 400
    meta, raw = exported
    max_size = get_setting("quarantine_max_size_mb") * 1024 * 1024
    if len(raw) > max_size:
        current_app.logger.warning("quarantine: message %s too large (%d bytes), not stored",
                                   meta.get("qid"), len(raw))
        return "skipped: too large", 200

    rcpts = meta.get("rcpt") or []
    if isinstance(rcpts, str):
        rcpts = [rcpts]
    sender = str(meta.get("from") or "")[:320]

    # Outbound mail is only visible to administrators
    if _is_outbound(meta):
        # a data loss prevention rule's "quarantine" keeps it regardless
        if not get_setting("quarantine_outbound") and \
                "OUTBOUND_DLP_QUARANTINE" not in _symbol_names(meta.get("symbols")):
            return "skipped: outbound quarantine disabled", 200
        direction = "outbound"
        sender_domain = sender.rsplit("@", 1)[-1].lower() if "@" in sender else ""
        targets = [(rcpt, sender_domain) for rcpt in _normalized(rcpts)]
    else:
        direction = "inbound"
        enabled = {d.name for d in Domain.query.filter_by(active=True, quarantine_enabled=True)}
        targets = [(rcpt, rcpt.rsplit("@", 1)[-1]) for rcpt in _normalized(rcpts)]
        targets = [(rcpt, domain) for rcpt, domain in targets if domain in enabled]

    stored = 0
    for rcpt, domain in targets:
        db.session.add(QuarantineItem(
            direction=direction,
            qid=str(meta.get("qid") or "")[:64],
            subject=str(meta.get("subject") or "")[:500],
            sender=sender,
            rcpt=rcpt[:320],
            domain=domain[:253],
            score=float(meta.get("score") or 0),
            action=str(meta.get("action") or "")[:32],
            ip=str(meta.get("ip") or "")[:64],
            symbols=json.dumps(meta.get("symbols") or []),
            size=len(raw),
            message=raw,
        ))
        stored += 1
    db.session.commit()
    if stored:
        current_app.logger.info("quarantine: stored %s message %s for %d recipient(s)",
                                direction, meta.get("qid"), stored)
    return f"stored {stored}", 200


@bp.post("/reports")
def reports_ingest():
    """DMARC and TLS reports sent to reports@<hostname> (services/reports.py)."""
    raw = request.get_data(cache=False)
    if not raw:
        return "empty request", 400
    try:
        result = reports.ingest(raw)
    except reports.ReportError as exc:
        return f"refused: {exc}", 413
    current_app.logger.info("reports: stored %d DMARC and %d TLS report(s)%s", result["dmarc"], result["tls"],
                            f", skipped: {'; '.join(result['skipped'][:5])}" if result["skipped"] else "")
    return f"stored {result['dmarc']} DMARC and {result['tls']} TLS report(s)", 200


@bp.post("/learn/<kind>")
def learn_report(kind):
    """Messages users reported to spam@ or ham@<hostname> (services/user_reports.py)."""
    if kind not in user_reports.KINDS:
        return "unknown kind", 404
    raw = request.get_data(cache=False)
    if not raw:
        return "empty request", 400
    report = user_reports.handle(kind, raw, request.headers.get("X-Envelope-From", ""),
                                 request.headers.get("X-Client-IP", ""),
                                 request.headers.get("X-Relay-Network") == "yes")
    return f"{report.status}: {report.learned} learned", 200


def _normalized(rcpts):
    return sorted({str(r).strip().lower() for r in rcpts if r})


def _symbol_names(symbols):
    if isinstance(symbols, dict):
        return set(symbols)
    if isinstance(symbols, list):
        return {s.get("name") for s in symbols if isinstance(s, dict)}
    return set()
