"""Attachment policy: settings, the map for rspamd and the page."""
import json
import os

import pytest

from crassostrea.extensions import db
from crassostrea.models import SETTING_DEFAULTS, get_setting
from crassostrea.services import filters
from crassostrea.services.errors import ServiceError
from crassostrea.services.maps import build_attachment_policy


def test_defaults_in_the_map(app):
    policy = json.loads(build_attachment_policy())
    assert {"exe", "js", "lnk", "iso", "scr"} <= set(policy["extensions"])
    assert (policy["archives"], policy["encrypted"], policy["outbound"], policy["exempt"]) == (True, False, False, [])


def test_validation(app):
    settings = filters.update_settings(attachment_blocked_extensions=" .EXE, *.js\nlnk  exe ",
                                       attachment_exempt_senders="Vendor.example\n it@Partner.example ,vendor.example")
    assert settings["attachment_blocked_extensions"] == "exe js lnk"
    assert settings["attachment_exempt_senders"] == "it@partner.example\nvendor.example"
    assert filters.update_settings(attachment_blocked_extensions="")["attachment_blocked_extensions"] == ""
    for changes, field in [({"attachment_blocked_extensions": "exe e/x"}, "attachment_blocked_extensions"),
                           ({"attachment_blocked_extensions": 5}, "attachment_blocked_extensions"),
                           ({"attachment_exempt_senders": "not a sender"}, "attachment_exempt_senders"),
                           ({"attachment_outbound": "yes"}, "attachment_outbound")]:
        with pytest.raises(ServiceError) as exc:
            filters.update_settings(**changes)
        assert exc.value.field == field
    db.session.rollback()


def test_page(app, logged_in):
    page = logged_in.get("/attachments/").get_data(as_text=True)
    assert 'href="/attachments/" class="active"' in page and "invoice.pdf.exe is an exe" in page
    response = logged_in.post("/attachments/", data={
        "attachment_blocked_extensions": "exe js\ndocm", "attachment_scan_archives": "y",
        "attachment_block_encrypted": "y", "attachment_exempt_senders": "vendor.example"}, follow_redirects=True)
    assert "Attachment policy saved" in response.get_data(as_text=True)
    path = os.path.join(app.config["RSPAMD_MAP_DIR"], "attachment_policy.json")
    assert json.load(open(path)) == {"extensions": ["docm", "exe", "js"], "archives": True, "encrypted": True,
                                     "outbound": False, "exempt": ["vendor.example"]}
    response = logged_in.post("/attachments/", data={"attachment_blocked_extensions": "exe",
                                                     "attachment_exempt_senders": "@@"})
    assert response.status_code == 400 and "address or a domain" in response.get_data(as_text=True)
    assert get_setting("attachment_exempt_senders") == "vendor.example"


def test_api(api):
    body = api("GET", "/settings").get_json()
    assert body["attachment_blocked_extensions"] == SETTING_DEFAULTS["attachment_blocked_extensions"]
    assert body["attachment_scan_archives"] is True
    body = api("PATCH", "/settings", json={"attachment_outbound": True, "attachment_blocked_extensions": "exe"})
    assert body.status_code == 200 and body.get_json()["attachment_outbound"] is True
    assert api("PATCH", "/settings", json={"attachment_blocked_extensions": "e x e/"}).status_code == 422
