"""REST API: filter configuration (domains with recipients, lists and DKIM
keys, directories, global lists, relay networks, outbound limits, data loss
prevention and content rules, protected people, settings, the hostname, certificates and
TLS, IP addressing)."""
from flask import jsonify, request, url_for

from ..extensions import db
from ..models import (ContentRule, Directory, DlpRule, Domain, ListEntry, OutboundLimit, ProtectedPerson, Recipient,
                      RelayNetwork)
from ..services import (certificates, content_rules, dkim, dlp, filters, hostname, impersonation, ipconfig, outbound,
                        ratelimits)
from ..services import destination
from ..services import directory as directory_service
from ..services.store import job_lock
from . import ApiError, _body, _bool_arg, _commit_config, _created, _get, _iso, _paginated, bp

SCORE_FIELDS = ("greylist_score", "add_header_score", "reject_score")


# ---------------------------------------------------------------------------
# Domains
# ---------------------------------------------------------------------------

def domain_json(domain):
    return {
        "id": domain.id, "name": domain.name, "description": domain.description, "active": domain.active,
        "destination_host": domain.destination_host, "destination_port": domain.destination_port,
        "use_mx": domain.use_mx, "recipient_check": domain.recipient_check, "directory_id": domain.directory_id,
        "quarantine_enabled": domain.quarantine_enabled, "link_protection": domain.link_protection,
        "digest_interval": domain.digest_interval,
        **{f: getattr(domain, f) for f in SCORE_FIELDS},
        "dkim_selector": domain.dkim_key.selector if domain.dkim_key else None,
        "created_at": _iso(domain.created_at),
    }


@bp.get("/domains")
def list_domains():
    query = Domain.query
    if request.args.get("name"):
        query = query.filter(Domain.name == request.args["name"].strip().lower())
    if request.args.get("q"):
        query = query.filter(Domain.name.contains(request.args["q"].strip().lower()))
    active = _bool_arg("active")
    if active is not None:
        query = query.filter(Domain.active.is_(active))
    return _paginated(query.order_by(Domain.name), domain_json)


@bp.post("/domains")
def create_domain():
    data = _body(("name",) + filters.DOMAIN_FIELDS, required=("name", "destination_host"))
    domain = filters.create_domain(data.pop("name"), **data)
    _commit_config()
    return _created(domain_json(domain), url_for("api.get_domain", domain_id=domain.id))


@bp.get("/domains/<int:domain_id>")
def get_domain(domain_id):
    return jsonify(domain_json(_get(Domain, domain_id, "Domain")))


@bp.patch("/domains/<int:domain_id>")
def update_domain(domain_id):
    domain = _get(Domain, domain_id, "Domain")
    filters.update_domain(domain, **_body(filters.DOMAIN_FIELDS))
    _commit_config()
    return jsonify(domain_json(domain))


@bp.post("/domains/<int:domain_id>/test-destination")
def test_domain_destination(domain_id):
    domain = _get(Domain, domain_id, "Domain")
    data = _body(("address",)) if request.get_data() else {}
    address = data.get("address")
    if address is not None:
        if not isinstance(address, str) or address.strip().lower().rpartition("@")[2] != domain.name \
                or address.count("@") != 1 or len(address) > 320 or any(c.isspace() or c in "<>" for c in address):
            raise ApiError(422, f"address must be an address of {domain.name}", "address")
        address = address.strip().lower()
    return jsonify({"results": destination.test(domain, address)})


@bp.delete("/domains/<int:domain_id>")
def delete_domain(domain_id):
    filters.delete_domain(_get(Domain, domain_id, "Domain"))
    _commit_config()
    return "", 204


# --- recipients -------------------------------------------------------------

def recipient_json(recipient):
    return {"id": recipient.id, "address": recipient.address, "source": recipient.source,
            "created_at": _iso(recipient.created_at)}


@bp.get("/domains/<int:domain_id>/recipients")
def list_recipients(domain_id):
    domain = _get(Domain, domain_id, "Domain")
    query = Recipient.query.filter_by(domain_id=domain.id)
    if request.args.get("q"):
        query = query.filter(Recipient.address.contains(request.args["q"].strip().lower()))
    return _paginated(query.order_by(Recipient.address), recipient_json)


@bp.post("/domains/<int:domain_id>/recipients")
def add_recipients(domain_id):
    domain = _get(Domain, domain_id, "Domain")
    data = _body(("addresses",), required=("addresses",))
    if not isinstance(data["addresses"], list):
        raise ApiError(422, "addresses must be a list of addresses or local parts", "addresses")
    result = filters.add_recipients(domain, data["addresses"])
    db.session.commit()
    return jsonify(result)


@bp.delete("/domains/<int:domain_id>/recipients/<int:recipient_id>")
def delete_recipient(domain_id, recipient_id):
    domain = _get(Domain, domain_id, "Domain")
    if not filters.delete_recipients(domain, [recipient_id]):
        raise ApiError(404, "Recipient not found")
    db.session.commit()
    return "", 204


# --- allow/block lists ------------------------------------------------------

LIST_ENTRY_FIELDS = ("list_type", "kind", "value", "comment")


def list_entry_json(entry):
    return {"id": entry.id, "list_type": entry.list_type, "kind": entry.kind, "value": entry.value,
            "comment": entry.comment, "created_at": _iso(entry.created_at)}


def _filtered_entries(query):
    for field in ("list_type", "kind"):
        if request.args.get(field):
            query = query.filter(getattr(ListEntry, field) == request.args[field])
    return query.order_by(ListEntry.list_type, ListEntry.kind, ListEntry.value)


def _add_entry(domain=None):
    data = _body(LIST_ENTRY_FIELDS, required=("list_type", "kind", "value"))
    entry = filters.add_list_entry(data["list_type"], data["kind"], data["value"], data.get("comment", ""),
                                   domain=domain)
    _commit_config()
    return jsonify(list_entry_json(entry)), 201


@bp.get("/domains/<int:domain_id>/list-entries")
def list_domain_entries(domain_id):
    domain = _get(Domain, domain_id, "Domain")
    return _paginated(_filtered_entries(filters.domain_list_entries(domain)), list_entry_json)


@bp.post("/domains/<int:domain_id>/list-entries")
def create_domain_entry(domain_id):
    return _add_entry(_get(Domain, domain_id, "Domain"))


@bp.delete("/domains/<int:domain_id>/list-entries/<int:entry_id>")
def delete_domain_entry(domain_id, entry_id):
    domain = _get(Domain, domain_id, "Domain")
    entry = filters.domain_list_entries(domain).filter(ListEntry.id == entry_id).first()
    if entry is None:
        raise ApiError(404, "List entry not found")
    filters.delete_list_entry(entry)
    _commit_config()
    return "", 204


@bp.get("/list-entries")
def list_global_entries():
    return _paginated(_filtered_entries(filters.global_list_entries()), list_entry_json)


@bp.post("/list-entries")
def create_global_entry():
    return _add_entry()


@bp.delete("/list-entries/<int:entry_id>")
def delete_global_entry(entry_id):
    entry = filters.global_list_entries().filter(ListEntry.id == entry_id).first()
    if entry is None:
        raise ApiError(404, "List entry not found")
    filters.delete_list_entry(entry)
    _commit_config()
    return "", 204


# --- DKIM -------------------------------------------------------------------

def dkim_json(domain):
    key = domain.dkim_key
    record = dkim.dns_record(key)
    return {"selector": key.selector, "key_size": key.key_size, "created_at": _iso(key.created_at),
            "dns_name": record["name"], "dns_value": record["value"]}


@bp.get("/domains/<int:domain_id>/dkim")
def get_dkim(domain_id):
    domain = _get(Domain, domain_id, "Domain")
    if domain.dkim_key is None:
        raise ApiError(404, "This domain has no DKIM key")
    return jsonify(dkim_json(domain))


@bp.put("/domains/<int:domain_id>/dkim")
def set_dkim(domain_id):
    domain = _get(Domain, domain_id, "Domain")
    data = _body(("selector", "key_size", "private_key"), required=("selector",))
    replaced = filters.set_dkim_key(domain, data["selector"], key_size=data.get("key_size"),
                                    private_key=data.get("private_key"))
    _commit_config()
    return jsonify(dkim_json(domain)), 200 if replaced else 201


@bp.delete("/domains/<int:domain_id>/dkim")
def delete_dkim(domain_id):
    filters.delete_dkim_key(_get(Domain, domain_id, "Domain"))
    _commit_config()
    return "", 204


# ---------------------------------------------------------------------------
# Relay networks
# ---------------------------------------------------------------------------

def network_json(network):
    return {"id": network.id, "cidr": network.cidr, "comment": network.comment,
            "created_at": _iso(network.created_at)}


@bp.get("/relay-networks")
def list_relay_networks():
    return _paginated(RelayNetwork.query.order_by(RelayNetwork.cidr), network_json)


@bp.post("/relay-networks")
def create_relay_network():
    data = _body(("cidr", "comment"), required=("cidr",))
    network = filters.add_relay_network(data["cidr"], data.get("comment", ""))
    _commit_config()
    return jsonify(network_json(network)), 201


@bp.delete("/relay-networks/<int:network_id>")
def delete_relay_network(network_id):
    filters.delete_relay_network(_get(RelayNetwork, network_id, "Relay network"))
    _commit_config()
    return "", 204


# ---------------------------------------------------------------------------
# Outbound limits (the default is in the settings: outbound_limit and
# outbound_limit_period)
# ---------------------------------------------------------------------------

def outbound_limit_json(limit):
    return {"id": limit.id, "sender": limit.sender, "max_recipients": limit.max_recipients, "period": limit.period,
            "comment": limit.comment, "created_at": _iso(limit.created_at)}


@bp.get("/outbound-limits")
def list_outbound_limits():
    return _paginated(OutboundLimit.query.order_by(OutboundLimit.sender), outbound_limit_json)


@bp.post("/outbound-limits")
def create_outbound_limit():
    data = _body(("sender", "max_recipients", "period", "comment"), required=("sender", "max_recipients"))
    limit = outbound.add_limit(data["sender"], data["max_recipients"], data.get("period", "hour"),
                               data.get("comment", ""))
    _commit_config()
    return _created(outbound_limit_json(limit), url_for("api.get_outbound_limit", limit_id=limit.id))


@bp.get("/outbound-limits/<int:limit_id>")
def get_outbound_limit(limit_id):
    return jsonify(outbound_limit_json(_get(OutboundLimit, limit_id, "Outbound limit")))


@bp.patch("/outbound-limits/<int:limit_id>")
def update_outbound_limit(limit_id):
    limit = outbound.update_limit(_get(OutboundLimit, limit_id, "Outbound limit"),
                                  **_body(("max_recipients", "period", "comment")))
    _commit_config()
    return jsonify(outbound_limit_json(limit))


@bp.delete("/outbound-limits/<int:limit_id>")
def delete_outbound_limit(limit_id):
    outbound.delete_limit(_get(OutboundLimit, limit_id, "Outbound limit"))
    _commit_config()
    return "", 204


@bp.get("/outbound-senders")
def list_outbound_senders():
    return jsonify({"counts": outbound.usage(), "deferred": outbound.hits()})


@bp.get("/rate-limits/hits")
def list_rate_limit_hits():
    return jsonify({"hits": ratelimits.hits()})


@bp.post("/rate-limits/reset")
def reset_rate_limit():
    data = _body(("kind", "key"), required=("kind", "key"))
    if data["kind"] not in ratelimits.KINDS or not isinstance(data["key"], str):
        raise ApiError(422, "kind must be ip, rcpt or bounce, key the address", "kind")
    return jsonify({"kind": data["kind"], "key": data["key"],
                    "counters": ratelimits.reset(data["kind"], data["key"].strip().lower())})


@bp.post("/outbound-senders/reset")
def reset_outbound_sender():
    data = _body(("sender",), required=("sender",))
    return jsonify({"sender": data["sender"], "reset": outbound.reset(data["sender"])})


# ---------------------------------------------------------------------------
# Directories (recipients from LDAP or Microsoft 365)
# ---------------------------------------------------------------------------

def directory_json(directory):
    data = {key: getattr(directory, key) for key in directory_service.FIELDS if key not in directory_service.SECRETS}
    return {"id": directory.id, **data, **{f"{key}_set": bool(getattr(directory, key))
                                           for key in directory_service.SECRETS},
            "domains": [d.name for d in directory.domains], "synced_at": _iso(directory.synced_at),
            "sync_error": directory.sync_error or None, "sync_count": directory.sync_count,
            "created_at": _iso(directory.created_at)}


@bp.get("/directories")
def list_directories():
    return _paginated(Directory.query.order_by(Directory.name), directory_json)


@bp.post("/directories")
def create_directory():
    directory = directory_service.create_directory(**_body(directory_service.FIELDS, required=("name", "kind")))
    db.session.commit()
    return _created(directory_json(directory), url_for("api.get_directory", directory_id=directory.id))


@bp.get("/directories/<int:directory_id>")
def get_directory(directory_id):
    return jsonify(directory_json(_get(Directory, directory_id, "Directory")))


@bp.patch("/directories/<int:directory_id>")
def update_directory(directory_id):
    directory = directory_service.update_directory(_get(Directory, directory_id, "Directory"),
                                                   **_body(directory_service.FIELDS))
    db.session.commit()
    return jsonify(directory_json(directory))


@bp.delete("/directories/<int:directory_id>")
def delete_directory(directory_id):
    directory_service.delete_directory(_get(Directory, directory_id, "Directory"))
    db.session.commit()
    return "", 204


@bp.post("/directories/<int:directory_id>/test")
def test_directory(directory_id):
    try:
        return jsonify(directory_service.preview(_get(Directory, directory_id, "Directory")))
    except directory_service.DirectoryError as exc:
        raise ApiError(502, str(exc)) from exc


@bp.post("/directories/<int:directory_id>/sync")
def sync_directory(directory_id):
    directory = _get(Directory, directory_id, "Directory")
    force = (_body(("force",)) if request.content_length else {}).get("force", False)
    if not isinstance(force, bool):
        raise ApiError(422, "force must be true or false", "force")
    with job_lock("sync-directories", timeout=600, wait=30) as acquired:
        if not acquired:
            raise ApiError(409, "A synchronisation is running")
        try:
            results = directory_service.sync(directory, force=force)
        except directory_service.DirectoryError as exc:
            raise ApiError(502, str(exc)) from exc
    return jsonify({"domains": results, "directory": directory_json(directory)})


# ---------------------------------------------------------------------------
# Content rules
# ---------------------------------------------------------------------------

def content_rule_json(rule):
    return {"id": rule.id, **{key: getattr(rule, key) for key in content_rules.COLUMNS},
            "created_at": _iso(rule.created_at)}


@bp.get("/content-rules")
def list_content_rules():
    return _paginated(ContentRule.query.order_by(ContentRule.name), content_rule_json)


@bp.post("/content-rules")
def create_content_rule():
    rule = content_rules.add_rule(**_body(content_rules.COLUMNS, required=("name", "field", "value")))
    _commit_config()
    return _created(content_rule_json(rule), url_for("api.get_content_rule", rule_id=rule.id))


@bp.get("/content-rules/<int:rule_id>")
def get_content_rule(rule_id):
    return jsonify(content_rule_json(_get(ContentRule, rule_id, "Content rule")))


@bp.patch("/content-rules/<int:rule_id>")
def update_content_rule(rule_id):
    rule = content_rules.update_rule(_get(ContentRule, rule_id, "Content rule"), **_body(content_rules.COLUMNS))
    _commit_config()
    return jsonify(content_rule_json(rule))


@bp.delete("/content-rules/<int:rule_id>")
def delete_content_rule(rule_id):
    content_rules.delete_rule(_get(ContentRule, rule_id, "Content rule"))
    _commit_config()
    return "", 204


@bp.post("/content-rules/test")
def test_content_rules():
    data = _body(("source", "envelope_from", "recipients", "direction"), required=("source",))
    recipients = data.get("recipients") or []
    if not isinstance(recipients, list) or not all(isinstance(r, str) for r in recipients):
        raise ApiError(422, "recipients must be a list of addresses", "recipients")
    if not isinstance(data.get("envelope_from") or "", str):
        raise ApiError(422, "envelope_from must be text", "envelope_from")
    values = content_rules.message_values(data["source"], data.get("envelope_from") or "", recipients)
    results = content_rules.test(values, data.get("direction") or "inbound")
    return jsonify({"results": [{"id": r["rule"].id, "name": r["rule"].name, "active": r["rule"].active,
                                 "matched": r["matched"], "value": r["value"]} for r in results]})


# ---------------------------------------------------------------------------
# Data loss prevention rules
# ---------------------------------------------------------------------------

DLP_FIELDS = ("name", "detector", "pattern", "min_matches", "sender", "action", "active", "comment")


def dlp_rule_json(rule):
    return {"id": rule.id, **{key: getattr(rule, key) for key in DLP_FIELDS}, "created_at": _iso(rule.created_at)}


@bp.get("/dlp-rules")
def list_dlp_rules():
    return _paginated(DlpRule.query.order_by(DlpRule.name), dlp_rule_json)


@bp.post("/dlp-rules")
def create_dlp_rule():
    rule = dlp.add_rule(**_body(DLP_FIELDS, required=("name", "detector")))
    _commit_config()
    return _created(dlp_rule_json(rule), url_for("api.get_dlp_rule", rule_id=rule.id))


@bp.get("/dlp-rules/<int:rule_id>")
def get_dlp_rule(rule_id):
    return jsonify(dlp_rule_json(_get(DlpRule, rule_id, "DLP rule")))


@bp.patch("/dlp-rules/<int:rule_id>")
def update_dlp_rule(rule_id):
    rule = dlp.update_rule(_get(DlpRule, rule_id, "DLP rule"), **_body(DLP_FIELDS))
    _commit_config()
    return jsonify(dlp_rule_json(rule))


@bp.delete("/dlp-rules/<int:rule_id>")
def delete_dlp_rule(rule_id):
    dlp.delete_rule(_get(DlpRule, rule_id, "DLP rule"))
    _commit_config()
    return "", 204


@bp.post("/dlp-rules/test")
def test_dlp_rules():
    data = _body(("text", "sender"), required=("text",))
    results = dlp.test(data["text"], data.get("sender") or "")
    return jsonify({"results": [{"id": r["rule"].id, "name": r["rule"].name, "active": r["rule"].active,
                                 "applies": r["applies"], "count": r["count"], "values": r["found"],
                                 "matched": r["matched"]} for r in results]})


# ---------------------------------------------------------------------------
# Impersonation: protected people (the checks' scores are settings)
# ---------------------------------------------------------------------------

def person_json(person):
    return {"id": person.id, "name": person.name, "addresses": person.addresses.split(),
            "created_at": _iso(person.created_at)}


@bp.get("/protected-people")
def list_protected_people():
    return _paginated(ProtectedPerson.query.order_by(ProtectedPerson.name), person_json)


@bp.post("/protected-people")
def create_protected_person():
    data = _body(("name", "addresses"), required=("name",))
    person = impersonation.add_person(data["name"], data.get("addresses", []))
    _commit_config()
    return _created(person_json(person), url_for("api.get_protected_person", person_id=person.id))


@bp.get("/protected-people/<int:person_id>")
def get_protected_person(person_id):
    return jsonify(person_json(_get(ProtectedPerson, person_id, "Protected person")))


@bp.patch("/protected-people/<int:person_id>")
def update_protected_person(person_id):
    person = impersonation.update_person(_get(ProtectedPerson, person_id, "Protected person"),
                                         **_body(("name", "addresses")))
    _commit_config()
    return jsonify(person_json(person))


@bp.delete("/protected-people/<int:person_id>")
def delete_protected_person(person_id):
    impersonation.delete_person(_get(ProtectedPerson, person_id, "Protected person"))
    _commit_config()
    return "", 204


@bp.post("/impersonation/test")
def test_impersonation():
    data = _body(("name", "address"), required=("address",))
    if not isinstance(data.get("name", ""), str):
        raise ApiError(422, "name must be text", "name")
    result = impersonation.test(data.get("name", ""), data["address"])
    return jsonify({"person": result["name"].name if result["name"] else None, "own_domain": result["own_domain"],
                    "lookalike": result["lookalike"]})


# ---------------------------------------------------------------------------
# Global settings
# ---------------------------------------------------------------------------

@bp.get("/settings")
def get_settings():
    return jsonify(filters.get_settings())


@bp.patch("/settings")
def update_settings():
    settings = filters.update_settings(**_body(filters.ALL_SETTINGS))
    _commit_config()
    return jsonify(settings)


# ---------------------------------------------------------------------------
# Hostname (applied by system/libexec/set-hostname, see services/hostname.py)
# ---------------------------------------------------------------------------

def _hostname_json(warnings=None):
    data = {"hostname": hostname.current(), "pending": hostname.pending(), "cluster": hostname.in_cluster()}
    if warnings is not None:
        data["warnings"] = warnings
    return data


@bp.get("/hostname")
def get_hostname():
    return jsonify(_hostname_json())


@bp.put("/hostname")
def change_hostname():
    data = _body(("hostname",), required=("hostname",))
    warnings = hostname.request_change(data["hostname"])
    return jsonify(_hostname_json(warnings)), 202


# ---------------------------------------------------------------------------
# Certificates & TLS (applied by system/libexec/tls-apply, see services/certificates.py)
# ---------------------------------------------------------------------------

def _certificate_json(info):
    if info is None:
        return None
    return {**info, "not_before": _iso(info["not_before"].replace(tzinfo=None)),
            "not_after": _iso(info["not_after"].replace(tzinfo=None))}


def _status_json():
    return {key: {k: v for k, v in entry.items() if k != "at_time"} for key, entry in certificates.status().items()
            if isinstance(entry, dict)}


@bp.get("/tls")
def get_tls():
    return jsonify({"settings": certificates.settings(), "certificate": _certificate_json(
        certificates.current_certificate()), "status": _status_json(), "busy": certificates.busy()})


@bp.post("/tls/letsencrypt/test")
def tls_staging_test():
    data = _body(("names",))
    return jsonify({"names": certificates.request_staging_test(data.get("names", []))}), 202


@bp.post("/tls/letsencrypt/apply")
def tls_letsencrypt_apply():
    data = _body(("names",))
    return jsonify({"names": certificates.request_letsencrypt(data.get("names", []))}), 202


@bp.post("/tls/certificate")
def tls_upload():
    files = {name: request.files.get(name) for name in ("certificate", "key", "chain")}
    data = {name: (f.read(certificates.MAX_UPLOAD + 1) if f else b"") for name, f in files.items()}
    report = certificates.validate(data["certificate"], data["key"], data["chain"])
    body = {"errors": report["errors"], "warnings": report["warnings"],
            "certificate": _certificate_json(report["info"])}
    if report["errors"]:
        return jsonify({"error": report["errors"][0], **body}), 422
    return jsonify({**body, "sha256": certificates.stage(report)})


@bp.post("/tls/certificate/apply")
def tls_certificate_apply():
    data = _body(("sha256",), required=("sha256",))
    certificates.request_manual(data["sha256"])
    return jsonify({"sha256": data["sha256"]}), 202


@bp.put("/tls/versions")
def tls_versions():
    data = _body(("https_min", "smtp_min"), required=("https_min", "smtp_min"))
    certificates.request_versions(data["https_min"], data["smtp_min"])
    return jsonify({"https_min": data["https_min"], "smtp_min": data["smtp_min"]}), 202


# ---------------------------------------------------------------------------
# IP addressing (applied and tested by system/libexec/network-apply)
# ---------------------------------------------------------------------------

@bp.get("/ip-config")
def get_ip_config():
    try:
        state = ipconfig.current(request.args.get("device") or None)
    except ipconfig.NetworkStateError as exc:
        raise ApiError(503, str(exc)) from exc
    return jsonify({"state": state, "change": ipconfig.status(), "busy": ipconfig.busy()})


@bp.put("/ip-config")
def change_ip_config():
    data = _body(("device", "ipv4", "ipv6"), required=("ipv4", "ipv6"))
    try:
        families = ipconfig.request_change(data)
    except ipconfig.NetworkStateError as exc:
        raise ApiError(503, str(exc)) from exc
    return jsonify(families), 202
