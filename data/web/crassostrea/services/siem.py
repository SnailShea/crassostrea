"""Events for a SIEM: every logged message and every audit log entry as a
JSON object, optionally in a syslog line (RFC 5424, facility local0), sent
to siem_host over UDP, TCP or TLS (one event per line).

``enqueue`` puts events into a Valkey list (sf_siem, at most QUEUE_MAX: the
oldest are dropped while the receiver is away), so a slow or missing
receiver never holds up mail. ``forward`` (flask siem-forward,
crassostrea-siem.service, on every node of a cluster: the list is shared)
sends them.
"""
import json
import socket
import ssl
import time
from datetime import datetime, timezone

from flask import current_app

from ..models import get_setting
from . import store

QUEUE = "sf_siem"
QUEUE_MAX = 100_000
BATCH = 200
# local0.info
PRIORITY = 16 * 8 + 6


def enabled(kind):
    return bool(get_setting("siem_host")) and bool(get_setting(f"siem_{kind}"))


def mail_event(entry):
    return {"type": "mail", "time": _now(entry.created_at), "node": current_app.config["HOSTNAME"],
            "direction": entry.direction, "queue_id": entry.qid, "message_id": entry.message_id,
            "sender": entry.sender, "recipients": entry.rcpt_list, "from": entry.header_from,
            "subject": entry.subject, "score": entry.score, "action": entry.action, "ip": entry.ip,
            "size": entry.size, "virus": entry.is_virus, "symbols": [s["name"] for s in entry.symbol_list],
            **({"refused": entry.reject_reason} if entry.reject_reason else {})}


def audit_event(entry, description):
    return {"type": "audit", "time": _now(entry.at), "node": current_app.config["HOSTNAME"], "actor": entry.actor,
            "ip": entry.ip, "method": entry.method, "action": entry.action, "description": description,
            "target": entry.target, "outcome": entry.outcome, "message": entry.message}


def _now(moment=None):
    moment = moment or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.isoformat(timespec="seconds").replace("+00:00", "Z")


def enqueue(kind, event):
    """Queue an event of ``kind`` (mail_log, audit) if the SIEM wants it.
    Never raises: the SIEM must not break mail or the audit log."""
    try:
        if not enabled(kind):
            return False
        r = store.get_redis()
        pipe = r.pipeline()
        pipe.rpush(QUEUE, json.dumps(event, separators=(",", ":")))
        pipe.ltrim(QUEUE, -QUEUE_MAX, -1)
        pipe.execute()
        return True
    except Exception as exc:
        current_app.logger.warning("SIEM event not queued: %s", exc)
        return False


def line(event, fmt=None):
    """The line sent for an event."""
    payload = event if isinstance(event, str) else json.dumps(event, separators=(",", ":"))
    if (fmt or get_setting("siem_format")) != "rfc5424":
        return payload
    data = json.loads(payload)
    return (f"<{PRIORITY}>1 {data.get('time') or _now()} {data.get('node') or '-'} crassostrea - "
            f"{data.get('type', 'event')} - {payload}")


class Connection:
    """A connection to the SIEM, opened again when the settings change."""

    def __init__(self):
        self.sock, self.key = None, None

    def _settings(self):
        return (get_setting("siem_host"), get_setting("siem_port"), get_setting("siem_protocol"),
                bool(get_setting("siem_verify_tls")))

    def send(self, lines):
        settings = self._settings()
        host, port, protocol, verify = settings
        if settings != self.key:
            self.close()
            self.key = settings
        data = [(text + "\n").encode() for text in lines]
        if protocol == "udp":
            family, kind, proto, _, address = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)[0]
            with socket.socket(family, kind, proto) as sock:
                for chunk in data:
                    sock.sendto(chunk[:65000], address)
            return
        if self.sock is None:
            sock = socket.create_connection((host, port), timeout=10)
            if protocol == "tls":
                context = ssl.create_default_context()
                if not verify:
                    context.check_hostname, context.verify_mode = False, ssl.CERT_NONE
                sock = context.wrap_socket(sock, server_hostname=host)
            self.sock = sock
        try:
            self.sock.sendall(b"".join(data))
        except OSError:
            self.close()
            raise

    def close(self):
        if self.sock is not None:
            try:
                self.sock.close()
            except OSError:
                pass
        self.sock = None


def send_test():
    """Send one test event now. Raises OSError."""
    event = {"type": "test", "time": _now(), "node": current_app.config["HOSTNAME"],
             "message": "Test event of the mail gateway"}
    connection = Connection()
    try:
        connection.send([line(event)])
    finally:
        connection.close()


def forward(stop=lambda: False, idle=5):
    """Send queued events until ``stop()``; keeps them while the SIEM is away."""
    connection = Connection()
    backoff = 1
    while not stop():
        if not get_setting("siem_host"):
            connection.close()
            time.sleep(idle)
            continue
        r = store.get_redis()
        first = r.blpop(QUEUE, timeout=idle)
        if first is None:
            continue
        events = [first[1]] + [e for e in (r.lpop(QUEUE, BATCH - 1) or [])]
        try:
            connection.send([line(e) for e in events])
            backoff = 1
        except (OSError, ssl.SSLError) as exc:
            current_app.logger.warning("SIEM not reachable, %d event(s) kept: %s", len(events), exc)
            r.lpush(QUEUE, *reversed(events))
            time.sleep(backoff)
            backoff = min(backoff * 2, 60)
    connection.close()
