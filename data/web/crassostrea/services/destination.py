"""The destination server of a domain: where Postfix delivers its mail, and a
test of it (domain page, ``POST /api/v1/domains/{id}/test-destination``).

The test talks SMTP as the gateway's delivery would: connect, EHLO, STARTTLS
when offered (is the certificate trusted?), ``MAIL FROM:<>``, then
``RCPT TO`` for an address you give and for a made-up one of the domain.
Nothing is sent: the dialogue ends before DATA. A server that accepts the
made-up address accepts any address, so the gateway's "verify" recipient
check cannot tell real mailboxes from wrong ones there.
"""
import secrets
import smtplib
import socket
import ssl
import time

import dns.exception
import dns.resolver
from flask import current_app

TIMEOUT = 10
MAX_HOSTS = 3


def destinations(domain):
    """(host, port) of the domain's destination, as Postfix's transport uses
    it: the host itself, or its MX hosts with use MX."""
    if not domain.use_mx:
        return [(domain.destination_host, domain.destination_port or 25)]
    try:
        answers = dns.resolver.resolve(domain.destination_host, "MX", lifetime=10)
        hosts = [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda r: r.preference)]
    except dns.exception.DNSException:
        hosts = [domain.destination_host]
    return [(host, domain.destination_port or 25) for host in hosts[:MAX_HOSTS] if host]


def _verdict(code):
    if 200 <= code < 300:
        return "accepted"
    if 400 <= code < 500:
        return "deferred"
    return "refused"


def _text(message):
    return (message.decode("utf-8", "replace") if isinstance(message, bytes) else str(message or "")).strip()


def _dialogue(host, port, domain, address, probe, tls):
    """One SMTP session. ``tls``: "verify" (trusted certificate), "any"
    (encrypted, certificate not checked) or "off". Returns a result dict;
    raises ssl.SSLCertVerificationError when "verify" fails."""
    result = {"steps": [], "tls": None, "address": None, "accepts_any": None}
    steps = result["steps"]
    with smtplib.SMTP(timeout=TIMEOUT, local_hostname=current_app.config["HOSTNAME"]) as smtp:
        code, message = smtp.connect(host, port)
        steps.append({"command": "connect", "code": code, "text": _text(message)})
        if code != 220:
            return result
        code, message = smtp.ehlo()
        steps.append({"command": "EHLO", "code": code, "text": _text(message).splitlines()[0] if message else ""})
        result["starttls"] = smtp.has_extn("starttls")
        if result["starttls"] and tls != "off":
            context = ssl.create_default_context()
            if tls == "any":
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            code, message = smtp.starttls(context=context)
            steps.append({"command": "STARTTLS", "code": code, "text": _text(message)})
            result["tls"] = {"version": smtp.sock.version(), "cipher": smtp.sock.cipher()[0],
                             "trusted": tls == "verify"}
            smtp.ehlo()
        code, message = smtp.mail("")
        steps.append({"command": "MAIL FROM:<>", "code": code, "text": _text(message)})
        if code >= 400:
            return result
        if address:
            code, message = smtp.rcpt(address)
            steps.append({"command": f"RCPT TO:<{address}>", "code": code, "text": _text(message)})
            result["address"] = _verdict(code)
        code, message = smtp.rcpt(probe)
        steps.append({"command": f"RCPT TO:<{probe}>", "code": code, "text": _text(message)})
        result["accepts_any"] = 200 <= code < 300
        try:
            smtp.rset()
        except smtplib.SMTPException:
            pass
    return result


def test(domain, address=None):
    """Test every destination host of ``domain``: [{host, port, ok, error,
    seconds, steps, starttls, tls, address, accepts_any}]."""
    probe = f"sf-test-{secrets.token_hex(6)}@{domain.name}"
    results = []
    for host, port in destinations(domain):
        started = time.monotonic()
        entry = {"host": host, "port": port, "error": None, "steps": [], "starttls": None, "tls": None,
                 "address": None, "accepts_any": None, "tls_error": None}
        try:
            try:
                entry.update(_dialogue(host, port, domain, address, probe, "verify"))
            except ssl.SSLCertVerificationError as exc:
                # Postfix encrypts without checking the certificate of a
                # destination (security level "may"): test that way too
                entry["tls_error"] = exc.verify_message or str(exc)
                entry.update(_dialogue(host, port, domain, address, probe, "any"))
        except (OSError, smtplib.SMTPException, socket.timeout) as exc:
            entry["error"] = str(exc) or exc.__class__.__name__
        entry["seconds"] = round(time.monotonic() - started, 2)
        steps = entry["steps"]
        entry["ok"] = (entry["error"] is None and len(steps) >= 3 and steps[0]["code"] == 220
                       and any(s["command"] == "MAIL FROM:<>" and s["code"] < 400 for s in steps))
        results.append(entry)
    return results
