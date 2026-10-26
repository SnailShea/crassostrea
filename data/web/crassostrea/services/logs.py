"""Logs page: the Postfix log of all nodes (Valkey, from logship) and the
journal of the other services of this node, read by the root helper
system/libexec/log-reader (socket-activated, crassostrea group only), which
knows the units of each source; the web UI only names the source.
"""
import json
import socket

from flask import current_app

# Sources: key, label, what it covers. "postfix" is the mail log in Valkey;
# the others are sources of log-reader (keep the keys in sync).
SOURCES = [
    ("postfix", "Postfix", "The mail log of Postfix: connections, deliveries, rejections"),
    ("rspamd", "Rspamd", "The filter: scans, maps, Lua errors"),
    ("clamav", "ClamAV", "The virus scanner, signature updates, Olefy"),
    ("web", "Web interface", "The web interface, the API and the internal API for Rspamd"),
    ("nginx", "nginx", "The web server (its access log is in /var/log/nginx)"),
    ("database", "Database", "MariaDB (and in a cluster Galera)"),
    ("valkey", "Valkey", "Valkey (and in a cluster Sentinel and haproxy)"),
    ("dns", "DNS resolver", "unbound, which resolves the DNS blocklists"),
    ("postfix-service", "Postfix service", "Postfix's service itself, the TLS policy service and reloads"),
    ("netfilter", "Bans", "netfilter, which bans hosts, and logship"),
    ("watchdog", "Watchdog", "Health checks, restarts and notifications"),
    ("certificates", "Certificates", "Let's Encrypt and the certificate changes of the web interface"),
    ("jobs", "Jobs", "Cleanup, digests, map sync, directories, alerts, backups, DMARC reports, rule updates"),
    ("senders", "SIEM & journaling", "The senders of SIEM events and journal copies"),
    ("system", "Root services", "Hostname and network changes, mail queue actions, this log reader"),
    ("cluster", "Cluster", "Cluster reports, maintenance and the floating address"),
]
# The journal's priorities, for the filter (journalctl -p: this and worse)
PRIORITIES = [("", "All"), ("info", "Info and worse"), ("notice", "Notice and worse"),
              ("warning", "Warnings and errors"), ("err", "Errors")]
PRIORITY_NAMES = {0: "emerg", 1: "alert", 2: "crit", 3: "err", 4: "warning", 5: "notice", 6: "info", 7: "debug"}


class LogReaderError(Exception):
    pass


def sources():
    """The sources of this gateway (the cluster only in a cluster)."""
    cluster = bool(current_app.config["CLUSTER_NODES"])
    return [s for s in SOURCES if s[0] != "cluster" or cluster]


def journal(source, lines=500, priority=""):
    """Entries of a source, newest first: [{time, unit, identifier, pid,
    priority, message}]. Raises LogReaderError."""
    request = {"source": source, "lines": lines}
    if priority:
        request["priority"] = priority
    chunks = []
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(35)
            sock.connect(current_app.config["LOG_READER_SOCKET"])
            sock.sendall(json.dumps(request).encode() + b"\n")
            sock.shutdown(socket.SHUT_WR)
            while chunk := sock.recv(65536):
                chunks.append(chunk)
    except OSError as exc:
        raise LogReaderError(f"The log reader (crassostrea-logs.socket) is not reachable: {exc}") from exc
    try:
        response = json.loads(b"".join(chunks))
    except ValueError:
        raise LogReaderError("Unexpected response from the log reader")
    if not isinstance(response, dict) or not response.get("ok"):
        raise LogReaderError((response or {}).get("error") if isinstance(response, dict) else "failed")
    return response.get("entries") or []
