"""Backups page: the backups of the gateway, made by system/libexec/backup.

The web UI cannot read the configuration, the certificates or the database
dump it would need: it writes a request (BACKUP_REQUEST), and
crassostrea-backup-request.path starts libexec/backup as root, which makes or
deletes the backup and writes its outcome to BACKUP_DIR/status.json.
crassostrea-backup.timer makes a scheduled backup every night and removes the
scheduled ones beyond backup_keep. The archives are readable by the group
crassostrea, so the web UI can list and download them. Restoring stops the
services (this one too): system/backup.sh restore, as root.
"""
import json
import os
import re
import tarfile
import time
from datetime import datetime, timezone

from flask import current_app

from .errors import ServiceError
from .maps import _write_if_changed

# libexec/backup's NAME_RE
NAME_RE = re.compile(r"^backup-(\d{8})-(\d{6})-(manual|scheduled)\.tar\.gz$")
# A backup that runs longer than this is assumed to have died
STALE_AFTER = 60 * 60
MANIFEST_MAX = 64 * 1024


def _dir():
    return current_app.config["BACKUP_DIR"]


def _manifest(path):
    """manifest.json of a backup (its first member), or {}."""
    try:
        with tarfile.open(path, "r:gz") as archive:
            member = archive.next()
            if member is None or member.name != "manifest.json" or not member.isfile() or member.size > MANIFEST_MAX:
                return {}
            data = json.load(archive.extractfile(member))
    except (OSError, tarfile.TarError, ValueError, EOFError):
        return {}
    return data if isinstance(data, dict) else {}


def backups():
    """The backups, newest first."""
    try:
        names = os.listdir(_dir())
    except OSError:
        return []
    found = []
    for name in names:
        match = NAME_RE.match(name)
        path = os.path.join(_dir(), name)
        if not match or not os.path.isfile(path):
            continue
        manifest = _manifest(path)
        created = datetime.strptime(match.group(1) + match.group(2), "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
        found.append({"name": name, "kind": match.group(3), "created_at": created, "size": os.path.getsize(path),
                      "hostname": manifest.get("hostname", ""), "mail_log": bool(manifest.get("mail_log")),
                      "quarantine": bool(manifest.get("quarantine")), "valkey": bool(manifest.get("valkey")),
                      "readable": bool(manifest)})
    return sorted(found, key=lambda b: b["name"][7:22], reverse=True)


def status():
    """The outcome of the last backup or deletion, or None."""
    try:
        with open(os.path.join(_dir(), "status.json"), encoding="utf-8") as handle:
            entry = json.load(handle)
    except (OSError, ValueError):
        return None
    if not isinstance(entry, dict):
        return None
    if entry.get("state") == "running" and time.time() - entry.get("at", 0) > STALE_AFTER:
        entry["state"] = "stale"
    return entry


def busy():
    return os.path.exists(current_app.config["BACKUP_REQUEST"]) or (status() or {}).get("state") == "running"


def path_for(name):
    """The file of the backup ``name``; ServiceError if there is none."""
    if not isinstance(name, str) or not NAME_RE.match(name):
        raise ServiceError("There is no such backup", "name", 404)
    path = os.path.join(_dir(), name)
    if not os.path.isfile(path):
        raise ServiceError(f"There is no backup {name}", "name", 404)
    return path


def _request(data):
    if busy():
        raise ServiceError("A backup is being made or deleted; try again when it is done", "backup", 409)
    try:
        _write_if_changed(current_app.config["BACKUP_REQUEST"], json.dumps(data) + "\n")
    except OSError as exc:
        raise ServiceError(f"Cannot send the request ({exc}); is crassostrea-backup-request.path installed?",
                           "backup", 503) from exc


def request_create():
    _request({"action": "create"})
    current_app.logger.info("backup requested")


def request_delete(name):
    path_for(name)
    _request({"action": "delete", "name": name})
    current_app.logger.info("deletion of backup %s requested", name)
