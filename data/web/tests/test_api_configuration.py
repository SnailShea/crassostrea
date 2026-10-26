"""REST API: domains, recipients, allow/block lists, DKIM, relay networks, settings."""
import os

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from crassostrea.extensions import db
from crassostrea.models import Domain, ListEntry, Recipient, get_setting
from crassostrea.services import accounts
from crassostrea.services.maps import render_rspamd_settings

from conftest import make_api_key


def _read(config, name, key="RSPAMD_MAP_DIR"):
    with open(os.path.join(config[key], name)) as handle:
        return handle.read()


@pytest.fixture
def domain(api):
    response = api("POST", "/domains", json={"name": "Example.COM", "destination_host": "mail.internal"})
    assert response.status_code == 201, response.get_json()
    return response.get_json()


# --- domains ----------------------------------------------------------------

def test_domain_crud(api, config, domain):
    assert domain["name"] == "example.com" and domain["destination_port"] == 25 and domain["active"] is True
    assert domain["recipient_check"] == "any" and domain["dkim_selector"] is None
    assert "example.com\n" in _read(config, "protected_domains.map")

    response = api("PATCH", f"/domains/{domain['id']}", json={
        "destination_port": 2525, "recipient_check": "list", "reject_score": 12.5, "description": "Main"})
    assert response.status_code == 200
    assert response.get_json()["destination_port"] == 2525 and response.get_json()["reject_score"] == 12.5
    assert "reject = 12.5;" in render_rspamd_settings()
    assert api("PATCH", f"/domains/{domain['id']}", json={"reject_score": None}).get_json()["reject_score"] is None

    listed = api("GET", "/domains?q=exam").get_json()
    assert listed["total"] == 1 and listed["items"][0]["name"] == "example.com"
    assert api("GET", "/domains?name=example.com").get_json()["total"] == 1
    assert api("GET", "/domains?active=false").get_json()["total"] == 0
    assert api("GET", "/domains?active=maybe").status_code == 400

    assert api("DELETE", f"/domains/{domain['id']}").status_code == 204
    assert api("GET", f"/domains/{domain['id']}").status_code == 404
    assert "example.com" not in _read(config, "protected_domains.map")


@pytest.mark.parametrize("body, status, field", [
    ({"name": "example.com", "destination_host": "other.internal"}, 409, "name"),
    ({"name": "not a domain", "destination_host": "x.internal"}, 422, "name"),
    ({"name": "b.example", "destination_host": "192.0.2.1", "use_mx": True}, 422, "use_mx"),
    ({"name": "b.example", "destination_host": "x.internal", "greylist_score": 20, "add_header_score": 10}, 422,
     "reject_score"),
    ({"name": "b.example", "destination_host": "x.internal", "destination_port": 0}, 422, "destination_port"),
    ({"name": "b.example", "destination_host": "x.internal", "active": "yes"}, 422, "active"),
    ({"name": "b.example", "destination_host": "x.internal", "recipient_check": "all"}, 422, "recipient_check"),
    ({"name": "b.example", "destination_host": "x.internal", "colour": "red"}, 422, "colour"),
    ({"name": "b.example"}, 422, "destination_host"),
])
def test_domain_validation(api, domain, body, status, field):
    response = api("POST", "/domains", json=body)
    assert response.status_code == status and response.get_json()["field"] == field
    assert Domain.query.count() == 1


def test_domain_name_cannot_be_changed(api, domain):
    response = api("PATCH", f"/domains/{domain['id']}", json={"name": "evil.example"})
    assert response.status_code == 422
    assert db.session.get(Domain, domain["id"]).name == "example.com"


# --- recipients -------------------------------------------------------------

def test_recipients(api, domain):
    response = api("POST", f"/domains/{domain['id']}/recipients",
                   json={"addresses": ["Alice@example.com", "bob", "carol@other.org", "bad address", 7]})
    assert response.get_json() == {"added": ["alice@example.com", "bob@example.com"], "skipped": 0,
                                   "invalid": ["carol@other.org", "bad address", "7"]}
    again = api("POST", f"/domains/{domain['id']}/recipients", json={"addresses": ["alice"]}).get_json()
    assert again["added"] == [] and again["skipped"] == 1
    listed = api("GET", f"/domains/{domain['id']}/recipients").get_json()
    assert [r["address"] for r in listed["items"]] == ["alice@example.com", "bob@example.com"]
    rid = listed["items"][0]["id"]
    assert api("DELETE", f"/domains/{domain['id']}/recipients/{rid}").status_code == 204
    assert api("DELETE", f"/domains/{domain['id']}/recipients/{rid}").status_code == 404
    assert Recipient.query.count() == 1
    assert api("POST", f"/domains/{domain['id']}/recipients", json={"addresses": "alice"}).status_code == 422


# --- allow/block lists ------------------------------------------------------

def test_domain_list_entries(api, domain):
    path = f"/domains/{domain['id']}/list-entries"
    created = api("POST", path, json={"list_type": "allow", "kind": "sender", "value": "@Partner.org"})
    assert created.status_code == 201 and created.get_json()["value"] == "*@partner.org"
    assert api("POST", path, json={"list_type": "block", "kind": "ip", "value": "203.0.113.9"}).status_code == 201
    assert api("POST", path, json={"list_type": "allow", "kind": "sender", "value": "*@partner.org"}).status_code == 409
    invalid = api("POST", path, json={"list_type": "allow", "kind": "sender", "value": "*"})
    assert invalid.status_code == 422 and invalid.get_json()["field"] == "value"
    assert api("POST", path, json={"list_type": "maybe", "kind": "ip", "value": "1.2.3.4"}).status_code == 422

    assert api("GET", f"{path}?kind=ip").get_json()["items"][0]["value"] == "203.0.113.9/32"
    ucl = render_rspamd_settings()
    assert f"allow_{domain['id']}_from {{" in ucl and f"block_{domain['id']}_ip {{" in ucl

    entry_id = created.get_json()["id"]
    # not a global entry
    assert api("DELETE", f"/list-entries/{entry_id}").status_code == 404
    assert api("DELETE", f"{path}/{entry_id}").status_code == 204
    assert f"allow_{domain['id']}_from {{" not in render_rspamd_settings()


def test_global_list_entries(api, config, domain):
    created = api("POST", "/list-entries", json={"list_type": "block", "kind": "sender", "value": "spam.example",
                                                 "comment": "campaign"})
    assert created.status_code == 201 and created.get_json()["comment"] == "campaign"
    assert "/^.*@spam\\.example$/i" in _read(config, "global_smtp_from_blacklist.map")
    assert api("GET", "/list-entries?list_type=block").get_json()["total"] == 1
    assert api("DELETE", f"/list-entries/{created.get_json()['id']}").status_code == 204
    assert "spam\\.example" not in _read(config, "global_smtp_from_blacklist.map")


def test_personal_entries_are_never_global(api, app, config, domain):
    """A mailbox user's own allow list must not end up in the global maps."""
    user = accounts.create_mailbox_user("alice@example.com", "a-long-password")
    accounts.add_user_list_entry(user, "allow", "friend@partner.org")
    db.session.commit()
    api("POST", "/list-entries", json={"list_type": "allow", "kind": "sender", "value": "boss@partner.org"})
    assert "friend" not in _read(config, "global_smtp_from_whitelist.map")
    assert "friend" not in _read(config, "global_mime_from_whitelist.map")
    assert "boss" in _read(config, "global_smtp_from_whitelist.map")
    assert [e["value"] for e in api("GET", "/list-entries").get_json()["items"]] == ["boss@partner.org"]
    personal = ListEntry.query.filter(ListEntry.mailbox_user_id.isnot(None)).one()
    assert api("DELETE", f"/list-entries/{personal.id}").status_code == 404


# --- DKIM -------------------------------------------------------------------

def test_dkim(api, domain):
    path = f"/domains/{domain['id']}/dkim"
    assert api("GET", path).status_code == 404
    created = api("PUT", path, json={"selector": "sf202610", "key_size": 2048})
    assert created.status_code == 201
    key = created.get_json()
    assert key["dns_name"] == "sf202610._domainkey.example.com" and key["dns_value"].startswith("v=DKIM1; k=rsa; p=")
    assert "private_key" not in api("GET", path).get_json()
    assert api("GET", f"/domains/{domain['id']}").get_json()["dkim_selector"] == "sf202610"

    pem = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()).decode()
    replaced = api("PUT", path, json={"selector": "imported", "private_key": pem})
    assert replaced.status_code == 200 and replaced.get_json()["selector"] == "imported"

    assert api("PUT", path, json={"selector": "x", "private_key": "nonsense"}).get_json()["field"] == "private_key"
    assert api("PUT", path, json={"selector": "x", "key_size": 1024}).get_json()["field"] == "key_size"
    assert api("PUT", path, json={"selector": "x", "key_size": 2048, "private_key": pem}).status_code == 422
    assert api("PUT", path, json={"selector": "bad selector!", "key_size": 2048}).get_json()["field"] == "selector"
    assert api("GET", path).get_json()["selector"] == "imported"

    assert api("DELETE", path).status_code == 204
    assert api("DELETE", path).status_code == 404


# --- relay networks and settings -------------------------------------------

def test_relay_networks(api, config):
    created = api("POST", "/relay-networks", json={"cidr": "10.1.2.3/24", "comment": "exchange"})
    assert created.status_code == 201 and created.get_json()["cidr"] == "10.1.2.0/24"
    assert "10.1.2.0/24\tOK" in _read(config, "relay_networks.cidr", key="POSTFIX_DYNAMIC_DIR")
    assert api("POST", "/relay-networks", json={"cidr": "10.1.2.0/24"}).status_code == 409
    assert api("POST", "/relay-networks", json={"cidr": "everyone"}).status_code == 422
    assert api("GET", "/relay-networks").get_json()["total"] == 1
    assert api("DELETE", f"/relay-networks/{created.get_json()['id']}").status_code == 204
    assert "10.1.2.0" not in _read(config, "relay_networks.cidr", key="POSTFIX_DYNAMIC_DIR")


def test_settings(api, app):
    settings = api("GET", "/settings").get_json()
    assert settings["reject_score"] == get_setting("reject_score") and settings["quarantine_outbound"] is True

    response = api("PATCH", "/settings", json={"reject_score": 20, "digest_interval": "weekly",
                                               "digest_sender": "Filter@Example.com", "quarantine_outbound": False})
    assert response.status_code == 200
    assert response.get_json()["digest_sender"] == "filter@example.com"
    assert get_setting("reject_score") == 20.0 and get_setting("quarantine_outbound") == 0
    assert "reject = 20;" in render_rspamd_settings()

    assert api("PATCH", "/settings", json={"add_header_score": 25}).get_json()["field"] == "reject_score"
    assert api("PATCH", "/settings", json={"reject_score": None}).status_code == 422
    assert api("PATCH", "/settings", json={"digest_token_days": 31}).status_code == 422
    assert api("PATCH", "/settings", json={"brand_name": "x"}).status_code == 422
    assert get_setting("reject_score") == 20.0


def test_read_only_key_cannot_change_configuration(app, api, domain):
    client = app.test_client()
    headers = {"X-API-Key": make_api_key(read_only=True)}
    assert client.get("/api/v1/domains", headers=headers).status_code == 200
    assert client.patch("/api/v1/settings", headers=headers, json={"reject_score": 30}).status_code == 403
    assert client.delete(f"/api/v1/domains/{domain['id']}", headers=headers).status_code == 403
