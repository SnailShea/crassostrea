"""Backups page and API: listing, requests to libexec/backup, downloads, settings."""
import io
import json
import os
import tarfile
import time

import pytest

from crassostrea.models import AuditEntry, get_setting
from crassostrea.services import backups

NAME = "backup-20261020-023012-scheduled.tar.gz"
MANUAL = "backup-20261021-101500-manual.tar.gz"


def make_backup(app, name, manifest=None):
    """An archive like libexec/backup's: manifest.json first."""
    directory = app.config["BACKUP_DIR"]
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, name)
    with tarfile.open(path, "w:gz") as archive:
        for member, data in (("manifest.json", json.dumps(manifest if manifest is not None else {
                "format": 1, "hostname": "mx.example.com", "quarantine": True, "mail_log": False,
                "valkey": True}).encode()), ("database.sql", b"-- dump\n")):
            info = tarfile.TarInfo(member)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return path


def write_status(app, **entry):
    os.makedirs(app.config["BACKUP_DIR"], exist_ok=True)
    with open(os.path.join(app.config["BACKUP_DIR"], "status.json"), "w") as handle:
        json.dump({"at": int(time.time()), **entry}, handle)


def request_file(app):
    try:
        with open(app.config["BACKUP_REQUEST"]) as handle:
            return json.load(handle)
    except FileNotFoundError:
        return None


def test_list(app, logged_in):
    make_backup(app, NAME)
    make_backup(app, MANUAL, manifest={})
    make_backup(app, "backup-latest.tar.gz")
    with open(os.path.join(app.config["BACKUP_DIR"], "notes.txt"), "w") as handle:
        handle.write("x")
    with app.test_request_context():
        found = backups.backups()
    assert [b["name"] for b in found] == [MANUAL, NAME]
    assert found[1]["hostname"] == "mx.example.com" and found[1]["quarantine"] and not found[1]["mail_log"]
    assert not found[0]["readable"]
    page = logged_in.get("/backups/").get_data(as_text=True)
    assert "mx.example.com" in page and "configuration, database, quarantine, Valkey" in page
    assert "unreadable" in page and 'href="/backups/" class="active"' in page


def test_empty(logged_in):
    assert "No backups yet" in logged_in.get("/backups/").get_data(as_text=True)


def test_create_and_busy(app, logged_in):
    response = logged_in.post("/backups/create", follow_redirects=True)
    assert "Making a backup" in response.get_data(as_text=True)
    assert request_file(app) == {"action": "create"}
    # one request at a time
    response = logged_in.post("/backups/create", follow_redirects=True)
    assert "A backup is being made" in response.get_data(as_text=True)
    os.remove(app.config["BACKUP_REQUEST"])
    write_status(app, state="running", message="Creating x", name="x")
    assert "Creating x…" in logged_in.get("/backups/").get_data(as_text=True)
    write_status(app, state="running", message="Creating x", at=int(time.time()) - 2 * 3600)
    with app.test_request_context():
        assert backups.status()["state"] == "stale" and not backups.busy()
    write_status(app, state="failed", message="The database could not be dumped")
    assert "The database could not be dumped" in logged_in.get("/backups/").get_data(as_text=True)


def test_delete(app, logged_in):
    make_backup(app, NAME)
    response = logged_in.post(f"/backups/{NAME}/delete", follow_redirects=True)
    assert f"Deleting {NAME}" in response.get_data(as_text=True)
    assert request_file(app) == {"action": "delete", "name": NAME}
    os.remove(app.config["BACKUP_REQUEST"])
    response = logged_in.post(f"/backups/{MANUAL}/delete", follow_redirects=True)
    assert "There is no backup" in response.get_data(as_text=True) and request_file(app) is None
    logged_in.post("/backups/..%2Fcrassostrea.conf/delete")
    assert request_file(app) is None


def test_download_is_audited(app, logged_in):
    path = make_backup(app, NAME)
    response = logged_in.get(f"/backups/{NAME}/download")
    assert response.status_code == 200 and response.data == open(path, "rb").read()
    assert NAME in response.headers["Content-Disposition"]
    entry = AuditEntry.query.filter_by(action="backups.download").one()
    assert (entry.actor, entry.target, entry.method) == ("admin", NAME, "GET")
    assert logged_in.get(f"/backups/{MANUAL}/download").status_code == 404
    assert logged_in.get("/backups/status.json/download").status_code == 404


def test_mailbox_users_have_no_access(app, client):
    from crassostrea.extensions import db
    from crassostrea.models import Domain, MailboxUser
    make_backup(app, NAME)
    domain = Domain(name="example.com", destination_host="mx.internal")
    user = MailboxUser(email="alice@example.com", domain=domain)
    user.set_password("alice-password")
    db.session.add_all([domain, user])
    db.session.commit()
    client.post("/login", data={"username": "alice@example.com", "password": "alice-password"})
    assert client.get(f"/backups/{NAME}/download").status_code in (302, 403)


def test_settings(app, logged_in):
    response = logged_in.post("/backups/settings", data={"backup_keep": "14", "backup_include_mail_log": "y"})
    assert response.status_code == 302
    assert (get_setting("backup_keep"), get_setting("backup_include_mail_log"),
            get_setting("backup_include_quarantine")) == (14, 1, 0)
    assert logged_in.post("/backups/settings", data={"backup_keep": "91"}).status_code == 400


def test_api(app, api):
    make_backup(app, NAME)
    body = api("GET", "/backups").get_json()
    assert body["items"][0]["name"] == NAME and body["items"][0]["created_at"].startswith("2026-10-20T02:30:12")
    assert body["busy"] is False and body["status"] is None
    response = api("POST", "/backups")
    assert response.status_code == 202 and response.get_json()["busy"] is True
    assert api("POST", "/backups").status_code == 409
    os.remove(app.config["BACKUP_REQUEST"])
    assert api("DELETE", f"/backups/{MANUAL}").status_code == 404
    assert api("DELETE", f"/backups/{NAME}").status_code == 202
    assert request_file(app) == {"action": "delete", "name": NAME}
    download = api("GET", f"/backups/{NAME}/download")
    assert download.status_code == 200 and download.mimetype == "application/gzip"
    entry = AuditEntry.query.filter_by(action="api.download_backup").one()
    assert entry.actor == "api:test" and entry.target == NAME


@pytest.mark.parametrize("changes, ok", [
    ({"backup_keep": 0}, False), ({"backup_keep": 90}, True), ({"backup_include_mail_log": "yes"}, False),
    ({"backup_include_quarantine": False}, True),
])
def test_api_settings(api, changes, ok):
    response = api("PATCH", "/settings", json=changes)
    assert (response.status_code == 200) is ok
    if ok:
        assert {k: response.get_json()[k] for k in changes} == changes
