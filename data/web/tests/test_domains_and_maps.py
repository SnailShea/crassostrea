import os

from crassostrea.extensions import db
from crassostrea.models import Domain, ListEntry, Recipient, get_setting
from crassostrea.services.maps import render_rspamd_settings


def _read(config, name, key="RSPAMD_MAP_DIR"):
    with open(os.path.join(config[key], name)) as handle:
        return handle.read()


def _add_domain(client, **overrides):
    data = {"name": "example.com", "destination_host": "mail.internal", "destination_port": "25",
            "recipient_check": "any", "active": "y", "quarantine_enabled": "y"}
    data.update(overrides)
    return client.post("/domains/new", data=data)


def test_create_domain_writes_protected_domain_map(logged_in, config):
    response = _add_domain(logged_in)
    assert response.status_code == 302
    domain = Domain.query.filter_by(name="example.com").one()
    assert domain.destination == "mail.internal:25"
    assert "example.com\n" in _read(config, "protected_domains.map")
    # No custom thresholds -> no domain specific settings rule
    assert "scores_" not in render_rspamd_settings()


def test_domain_validation(logged_in):
    response = _add_domain(logged_in, name="not a domain")
    assert b"is not a valid domain name" in response.data
    response = _add_domain(logged_in, destination_host="192.0.2.1", use_mx="y")
    assert b"MX lookup is not possible" in response.data
    response = _add_domain(logged_in, greylist_score="20", add_header_score="10")
    assert b"Thresholds must satisfy" in response.data
    assert Domain.query.count() == 0


def test_domain_name_cannot_be_changed(logged_in):
    _add_domain(logged_in)
    domain = Domain.query.one()
    logged_in.post(f"/domains/{domain.id}", data={
        "name": "evil.com", "destination_host": "other.internal", "destination_port": "2525",
        "recipient_check": "list", "active": "y"})
    db.session.refresh(domain)
    assert domain.name == "example.com"
    assert domain.destination_port == 2525
    assert domain.recipient_check == "list"


def test_custom_scores_render_settings_rule(logged_in):
    _add_domain(logged_in, reject_score="12.5")
    domain = Domain.query.one()
    ucl = render_rspamd_settings()
    assert f"scores_{domain.id} {{" in ucl
    # only when every recipient is in the domain
    assert 'selector = "sf_rcpts_in_domain(\\"example.com\\")";' in ucl
    assert "rcpt =" not in ucl.split(f"scores_{domain.id} {{", 1)[1].split("  }\n", 1)[0]
    assert "reject = 12.5;" in ucl
    # missing values fall back to the global defaults
    assert f'"add header" = {get_setting("add_header_score"):g};' in ucl
    # watchdog rule required by watchdog-crassostrea is always present
    assert "watchdog {" in ucl and "reject = 9999.0;" in ucl


def test_domain_list_entries_render_settings_rules(logged_in):
    _add_domain(logged_in)
    domain = Domain.query.one()
    logged_in.post(f"/domains/{domain.id}/entries",
                   data={"entry-list_type": "allow", "entry-kind": "sender", "entry-value": "@partner.org"})
    logged_in.post(f"/domains/{domain.id}/entries",
                   data={"entry-list_type": "block", "entry-kind": "ip", "entry-value": "203.0.113.9"})
    assert ListEntry.query.count() == 2
    ucl = render_rspamd_settings()
    assert f"allow_{domain.id}_from {{" in ucl
    assert f"allow_{domain.id}_mime {{" in ucl
    assert 'from = "/^.*@partner\\\\.org$/i";' in ucl
    assert "DOMAIN_ALLOWLIST = -999;" in ucl
    assert f"block_{domain.id}_ip {{" in ucl
    assert 'ip = "203.0.113.9/32";' in ucl
    assert "DOMAIN_BLOCKLIST = 999;" in ucl
    allow = ucl.split(f"allow_{domain.id}_from {{", 1)[1].split("  }\n", 1)[0]
    block = ucl.split(f"block_{domain.id}_ip {{", 1)[1].split("  }\n", 1)[0]
    # allow lists need every recipient in the domain, block lists any recipient
    assert 'selector = "sf_rcpts_in_domain(\\"example.com\\")";' in allow and "rcpt =" not in allow
    assert 'rcpt = "/@example\\\\.com$/i";' in block and "selector" not in block
    # braces are balanced
    assert ucl.count("{") == ucl.count("}")


def test_invalid_list_entry_is_rejected(logged_in):
    _add_domain(logged_in)
    domain = Domain.query.one()
    response = logged_in.post(f"/domains/{domain.id}/entries", follow_redirects=True,
                              data={"entry-list_type": "allow", "entry-kind": "sender", "entry-value": "*"})
    assert b"would match every domain" in response.data or b"invalid" in response.data
    assert ListEntry.query.count() == 0


def test_global_lists_write_rspamd_maps(logged_in, config):
    logged_in.post("/lists/", data={"list_type": "allow", "kind": "sender", "value": "boss@partner.org"})
    logged_in.post("/lists/", data={"list_type": "block", "kind": "sender", "value": "spam.example"})
    logged_in.post("/lists/", data={"list_type": "block", "kind": "ip", "value": "198.51.100.0/24"})
    assert "/^boss@partner\\.org$/i" in _read(config, "global_smtp_from_whitelist.map")
    assert "/^boss@partner\\.org$/i" in _read(config, "global_mime_from_whitelist.map")
    assert "/^.*@spam\\.example$/i" in _read(config, "global_smtp_from_blacklist.map")
    assert "198.51.100.0/24" in _read(config, "ip_bl.map")

    entry = ListEntry.query.filter_by(kind="ip").one()
    logged_in.post(f"/lists/{entry.id}/delete")
    assert "198.51.100.0/24" not in _read(config, "ip_bl.map")


def test_recipients(logged_in):
    _add_domain(logged_in, recipient_check="list")
    domain = Domain.query.one()
    response = logged_in.post(f"/domains/{domain.id}/recipients", follow_redirects=True,
                              data={"rcpt-addresses": "alice@example.com\nbob, carol@other.org\n bad address"})
    assert sorted(r.address for r in Recipient.query) == ["alice@example.com", "bob@example.com"]
    assert b"carol@other.org" in response.data  # reported as foreign
    ids = [str(r.id) for r in Recipient.query]
    logged_in.post(f"/domains/{domain.id}/recipients/delete", data={"ids": ids})
    assert Recipient.query.count() == 0


def test_delete_domain_cascades(logged_in, config):
    _add_domain(logged_in, recipient_check="list")
    domain = Domain.query.one()
    logged_in.post(f"/domains/{domain.id}/recipients", data={"rcpt-addresses": "alice"})
    logged_in.post(f"/domains/{domain.id}/entries",
                   data={"entry-list_type": "allow", "entry-kind": "sender", "entry-value": "x@y.org"})
    logged_in.post(f"/domains/{domain.id}/delete")
    assert Domain.query.count() == Recipient.query.count() == ListEntry.query.count() == 0
    assert "example.com" not in _read(config, "protected_domains.map")


def test_relay_networks_update_postfix_and_rspamd(logged_in, config):
    logged_in.post("/settings/networks", data={"net-cidr": "10.1.2.3/24", "net-comment": "exchange"})
    assert "10.1.2.0/24\tOK" in _read(config, "relay_networks.cidr", key="POSTFIX_DYNAMIC_DIR")
    assert "10.1.2.0/24" in _read(config, "relay_networks.map")
    # Postfix is reloaded by a systemd path unit whenever the file is replaced,
    # so unchanged content must leave the file alone
    path = os.path.join(config["POSTFIX_DYNAMIC_DIR"], "relay_networks.cidr")
    inode = os.stat(path).st_ino
    logged_in.post("/settings/networks", data={"net-cidr": "10.1.2.0/24"})
    assert os.stat(path).st_ino == inode


def test_global_settings(logged_in):
    response = logged_in.post("/settings/", data={
        "greylist_score": "5", "add_header_score": "6", "reject_score": "6",
        "quarantine_retention_days": "30", "quarantine_max_size_mb": "20",
        "digest_interval": "daily", "digest_token_days": "7", "mailbox_invite_days": "7", "ptr_check": "off"})
    assert response.status_code == 400
    response = logged_in.post("/settings/", data={
        "greylist_score": "5", "add_header_score": "6", "reject_score": "12",
        "quarantine_retention_days": "30", "quarantine_max_size_mb": "20",
        "maillog_retention_days": "14", "max_message_size_mb": "25", "max_attachment_size_mb": "0",
        "audit_retention_days": "365",
        "digest_interval": "weekly", "digest_token_days": "3", "digest_sender": "Filter@Example.com",
        "mailbox_invite_days": "7", "ptr_check": "off"})
    assert response.status_code == 302
    assert get_setting("digest_interval") == "weekly" and get_setting("digest_token_days") == 3
    assert get_setting("digest_sender") == "filter@example.com"
    assert get_setting("reject_score") == 12.0
    assert get_setting("quarantine_retention_days") == 30
    assert (get_setting("maillog_retention_days"), get_setting("max_message_size_mb")) == (14, 25)
    ucl = render_rspamd_settings()
    assert "global_scores {" in ucl and "reject = 12;" in ucl and '"add header" = 6;' in ucl
