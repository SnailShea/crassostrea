"""REST API: day-to-day operations (quarantine, mail log, mail queue, bans, training, audit log,
backups, link clicks, attachment hash detections, DMARC and TLS reports, statistics, monitoring checks, journaling, user reports,
the cluster).

The mail queue and training act on the node that answers the request; in a
cluster every node has its own queue.
"""
import ipaddress
import json
import re

from flask import current_app, g, jsonify, request, send_file

from ..extensions import db
from ..models import DIRECTIONS, DmarcReport, MailLogEntry, QuarantineItem, TlsReport
from ..services import (audit, backups, cluster, hashcheck, journal, links, maillog, monitoring, postfix_control,
                        reports, stats, store, user_reports)
from ..services.maps import sync_all
from ..services.quarantine import (SENDER_SCOPES, base_address, learn_spam_and_delete, list_sender, owned_by,
                                   parse_message, release)
from ..services.rspamd import train
from . import ApiError, _body, _bool_arg, _check_types, _get, _iso, _paginated, bp

# Short and long Postfix queue IDs, checked again by the control service
QUEUE_ID = re.compile(r"^[0-9A-Za-z]{6,32}$")


def _actor():
    """Recorded as released_by and requeued_by."""
    return f"api:{g.api_key.name}"[:64]


# ---------------------------------------------------------------------------
# Quarantine
# ---------------------------------------------------------------------------

def quarantine_json(item):
    return {
        "id": item.id, "direction": item.direction, "queue_id": item.qid, "subject": item.subject,
        "sender": item.sender, "rcpt": item.rcpt, "domain": item.domain, "score": item.score,
        "action": item.action, "ip": item.ip, "size": item.size, "virus": item.is_virus,
        "created_at": _iso(item.created_at), "released_at": _iso(item.released_at),
        "released_by": item.released_by,
    }


@bp.get("/quarantine")
def list_quarantine():
    query = QuarantineItem.query
    direction = request.args.get("direction", "")
    if direction:
        if direction not in DIRECTIONS:
            raise ApiError(400, "direction must be inbound or outbound")
        query = query.filter(QuarantineItem.direction == direction)
    for field in ("domain", "rcpt"):
        if request.args.get(field):
            query = query.filter(getattr(QuarantineItem, field) == request.args[field].strip().lower())
    if request.args.get("mailbox"):
        mailbox = request.args["mailbox"].strip().lower()
        if "@" not in mailbox or len(mailbox) > 320:
            raise ApiError(400, "mailbox must be an address")
        query = query.filter(owned_by(base_address(mailbox)))
    status = request.args.get("status", "")
    if status == "released":
        query = query.filter(QuarantineItem.released_at.isnot(None))
    elif status == "pending":
        query = query.filter(QuarantineItem.released_at.is_(None))
    elif status:
        raise ApiError(400, "status must be pending or released")
    if request.args.get("q"):
        like = f"%{request.args['q'].strip()}%"
        query = query.filter(db.or_(QuarantineItem.subject.ilike(like), QuarantineItem.sender.ilike(like),
                                    QuarantineItem.rcpt.ilike(like)))
    return _paginated(query.order_by(QuarantineItem.created_at.desc(), QuarantineItem.id.desc()), quarantine_json)


@bp.get("/quarantine/<int:item_id>")
def get_quarantine_item(item_id):
    item = _get(QuarantineItem, item_id, "Quarantined message")
    return jsonify({**quarantine_json(item), "symbols": item.symbol_list, "message": parse_message(item.message)})


@bp.get("/quarantine/<int:item_id>/raw")
def get_quarantine_raw(item_id):
    item = _get(QuarantineItem, item_id, "Quarantined message")
    return current_app.response_class(item.message, mimetype="message/rfc822", headers={
        "Content-Disposition": f'attachment; filename="quarantine-{item.id}.eml"'})


@bp.post("/quarantine/<int:item_id>/release")
def release_quarantine_item(item_id):
    item = _get(QuarantineItem, item_id, "Quarantined message")
    data = _body(("learn_ham", "allow_virus", "allow_sender")) if request.get_data() else {}
    for field in ("learn_ham", "allow_virus"):
        if not isinstance(data.get(field, False), bool):
            raise ApiError(422, f"{field} must be true or false", field)
    if item.is_virus and not data.get("allow_virus"):
        raise ApiError(409, "This message contains a virus; set allow_virus to release it anyway", "allow_virus")
    listed = None
    if data.get("allow_sender") is not None:
        listed = list_sender(item, "allow", _sender_scope(data["allow_sender"], "allow_sender"))
    notes = release(item, _actor(), learn_ham=data.get("learn_ham", False))
    db.session.commit()
    if listed:
        sync_all()
        notes = [*notes, listed]
    return jsonify({**quarantine_json(item), "notes": notes})


def _sender_scope(value, field):
    if value not in SENDER_SCOPES:
        raise ApiError(422, f"{field} must be one of {', '.join(SENDER_SCOPES)}", field)
    return value


@bp.post("/quarantine/<int:item_id>/block-sender")
def block_quarantine_sender(item_id):
    item = _get(QuarantineItem, item_id, "Quarantined message")
    data = _body(("scope", "delete"), required=("scope",))
    if not isinstance(data.get("delete", True), bool):
        raise ApiError(422, "delete must be true or false", "delete")
    listed = list_sender(item, "block", _sender_scope(data["scope"], "scope"))
    if data.get("delete", True):
        db.session.delete(item)
    db.session.commit()
    sync_all()
    return jsonify({"notes": [listed]})


@bp.post("/quarantine/<int:item_id>/learn-spam")
def learn_quarantine_item(item_id):
    notes = learn_spam_and_delete(_get(QuarantineItem, item_id, "Quarantined message"))
    db.session.commit()
    return jsonify({"notes": notes})


@bp.delete("/quarantine/<int:item_id>")
def delete_quarantine_item(item_id):
    db.session.delete(_get(QuarantineItem, item_id, "Quarantined message"))
    db.session.commit()
    return "", 204


# ---------------------------------------------------------------------------
# Mail log
# ---------------------------------------------------------------------------

def maillog_json(entry):
    return {
        "id": entry.id, "direction": entry.direction, "queue_id": entry.qid, "message_id": entry.message_id,
        "subject": entry.subject, "sender": entry.sender, "header_from": entry.header_from,
        "rcpts": entry.rcpt_list, "score": entry.score, "action": entry.action, "ip": entry.ip,
        "size": entry.size, "scan_ms": entry.scan_ms, "virus": entry.is_virus,
        "created_at": _iso(entry.created_at), "requeued_at": _iso(entry.requeued_at),
        "requeued_by": entry.requeued_by,
        "refused": entry.reject_reason or None,
    }


@bp.get("/mail-log")
def list_maillog():
    args = request.args
    query = maillog.filtered(args.get("direction", ""), args.get("action", ""), args.get("domain", ""),
                             args.get("q", ""), strict=True)
    return _paginated(query, maillog_json)


@bp.get("/mail-log/<int:entry_id>")
def get_maillog_entry(entry_id):
    entry = _get(MailLogEntry, entry_id, "Logged message")
    return jsonify({**maillog_json(entry), "symbols": entry.symbol_list, "message": parse_message(entry.message),
                    "quarantine_ids": [item.id for item in maillog.quarantined(entry)]})


@bp.get("/mail-log/<int:entry_id>/raw")
def get_maillog_raw(entry_id):
    entry = _get(MailLogEntry, entry_id, "Logged message")
    if entry.refused:
        raise ApiError(404, "Postfix refused this recipient: there is no message")
    return current_app.response_class(entry.message, mimetype="message/rfc822", headers={
        "Content-Disposition": f'attachment; filename="mail-log-{entry.id}.eml"'})


@bp.post("/mail-log/<int:entry_id>/requeue")
def requeue_maillog_entry(entry_id):
    entry = _get(MailLogEntry, entry_id, "Logged message")
    data = _body(("rcpts", "allow_virus")) if request.get_data() else {}
    rcpts = data.get("rcpts", entry.rcpt_list)
    if not isinstance(rcpts, list) or not all(isinstance(r, str) for r in rcpts):
        raise ApiError(422, "rcpts must be a list of addresses", "rcpts")
    if not isinstance(data.get("allow_virus", False), bool):
        raise ApiError(422, "allow_virus must be true or false", "allow_virus")
    notes = maillog.requeue(entry, rcpts, _actor(), allow_virus=data.get("allow_virus", False))
    db.session.commit()
    return jsonify({**maillog_json(entry), "notes": notes})


# ---------------------------------------------------------------------------
# Mail queue (of the node answering the request)
# ---------------------------------------------------------------------------

# API action -> postfix-control task
QUEUE_ACTIONS = {"flush": "flush", "deliver": "deliver", "hold": "hold", "unhold": "unhold", "delete": "delete",
                 "delete_all": "super_delete"}


@bp.get("/queue")
def list_queue():
    items = sorted(postfix_control.mail_queue(), key=lambda i: i.get("arrival_time", 0), reverse=True)
    return jsonify({"node": current_app.config["HOSTNAME"], "items": items, "total": len(items)})


@bp.get("/queue/<queue_id>")
def get_queued_message(queue_id):
    if not QUEUE_ID.match(queue_id):
        raise ApiError(404, "Queued message not found")
    return jsonify({"queue_id": queue_id, "content": postfix_control.queue_message(queue_id)})


@bp.post("/queue/actions")
def queue_action():
    data = _body(("action", "ids"), required=("action",))
    action = data["action"]
    if action not in QUEUE_ACTIONS:
        raise ApiError(422, f"action must be one of {', '.join(QUEUE_ACTIONS)}", "action")
    ids = data.get("ids", [])
    if not isinstance(ids, list) or not all(isinstance(i, str) and QUEUE_ID.match(i) for i in ids):
        raise ApiError(422, "ids must be a list of queue IDs", "ids")
    if action in ("flush", "delete_all"):
        ids = []
    elif not ids:
        raise ApiError(422, f"{action} needs the ids of the messages", "ids")
    postfix_control.queue_action(QUEUE_ACTIONS[action], ids)
    return jsonify({"node": current_app.config["HOSTNAME"], "action": action, "ids": ids})


# ---------------------------------------------------------------------------
# Bans (netfilter)
# ---------------------------------------------------------------------------

@bp.get("/bans")
def list_bans():
    bans = store.banned_networks()
    return jsonify({"items": bans, "total": len(bans)})


@bp.post("/bans/unban")
def unban():
    data = _body(("network",), required=("network",))
    try:
        network = str(ipaddress.ip_network(data["network"], strict=False))
    except (TypeError, ValueError):
        raise ApiError(422, "network must be an IP address or network", "network")
    if not any(b["network"] == network and not b["permanent"] for b in store.banned_networks()):
        raise ApiError(404, "This network is not banned (permanent bans come from netfilter's denylist, "
                            "F2B_BLACKLIST in valkey)")
    store.queue_unban(network)
    return jsonify({"network": network, "unban_queued": True}), 202


# ---------------------------------------------------------------------------
# Training (Bayes, fuzzy hashes)
# ---------------------------------------------------------------------------

@bp.post("/training/spam", defaults={"kind": "spam"})
@bp.post("/training/ham", defaults={"kind": "ham"})
def learn(kind):
    message = request.get_data()
    if not message.strip():
        raise ApiError(400, "Send the raw message (headers and body) as request body (Content-Type: message/rfc822)")
    if b":" not in message.split(b"\n", 1)[0]:
        raise ApiError(422, "This does not look like a raw e-mail message (headers are missing)")
    return jsonify({"notes": train(message, spam=kind == "spam")})


# ---------------------------------------------------------------------------
# Audit log (read-only)
# ---------------------------------------------------------------------------

def audit_json(entry):
    return {"id": entry.id, "at": _iso(entry.at), "actor": entry.actor, "ip": entry.ip, "method": entry.method,
            "action": entry.action, "description": audit.describe(entry), "target": entry.target,
            "outcome": entry.outcome, "message": entry.message, "details": audit.details(entry)}


@bp.get("/audit-log")
def list_audit_log():
    outcome = request.args.get("outcome", "")
    if outcome not in ("", "ok", "failed"):
        raise ApiError(400, "outcome must be ok or failed")
    return _paginated(audit.filtered(request.args.get("actor", ""), outcome, request.args.get("q", "")), audit_json)


# ---------------------------------------------------------------------------
# Backups
# ---------------------------------------------------------------------------

def backup_json(item):
    return {"name": item["name"], "kind": item["kind"], "created_at": _iso(item["created_at"]),
            "size": item["size"], "hostname": item["hostname"], "quarantine": item["quarantine"],
            "mail_log": item["mail_log"], "valkey": item["valkey"], "readable": item["readable"]}


def _backup_state():
    status = backups.status()
    return {"items": [backup_json(b) for b in backups.backups()], "busy": backups.busy(),
            "status": status and {"state": status.get("state"), "message": status.get("message"),
                                  "at": status.get("at"), "name": status.get("name")}}


@bp.get("/backups")
def list_backups():
    return jsonify(_backup_state())


@bp.post("/backups")
def create_backup():
    backups.request_create()
    return jsonify(_backup_state()), 202


@bp.delete("/backups/<name>")
def delete_backup(name):
    backups.request_delete(name)
    return jsonify(_backup_state()), 202


@bp.get("/backups/<name>/download")
def download_backup(name):
    path = backups.path_for(name)
    audit.event("api.download_backup", name, f"Downloaded {name}")
    return send_file(path, mimetype="application/gzip", as_attachment=True, download_name=name)


# ---------------------------------------------------------------------------
# Link protection
# ---------------------------------------------------------------------------

@bp.get("/link-clicks")
def list_link_clicks():
    return jsonify({"items": links.clicks(limit=request.args.get("limit", 200, type=int) or 200,
                                          blocked_only=_bool_arg("blocked") is True)})


@bp.post("/link-check")
def check_link():
    data = _body(("url",), required=("url",))
    if not isinstance(data["url"], str) or len(data["url"]) > 2000:
        raise ApiError(422, "url must be text of at most 2000 characters", "url")
    url = data["url"].strip()
    return jsonify(links.check(url if "://" in url else "http://" + url))


# ---------------------------------------------------------------------------
# Attachment hash lookups
# ---------------------------------------------------------------------------

@bp.get("/hash-detections")
def list_hash_detections():
    return jsonify({"items": hashcheck.hits(limit=min(request.args.get("limit", 100, type=int) or 100, 500))})


@bp.post("/hash-lookup")
def lookup_hash():
    data = _body(("hash",), required=("hash",))
    if not isinstance(data["hash"], str):
        raise ApiError(422, "hash must be text", "hash")
    return jsonify(hashcheck.check(data["hash"]))


# ---------------------------------------------------------------------------
# DMARC and TLS reports
# ---------------------------------------------------------------------------

def _days():
    days = request.args.get("days", 30, type=int)
    if not 1 <= days <= 3650:
        raise ApiError(400, "days must be from 1 to 3650")
    return days


@bp.get("/reports/summary")
def report_summary():
    return jsonify({"address": reports.address(), "days": _days(), "domains": reports.summary(_days())})


@bp.get("/reports/dmarc")
def list_dmarc_reports():
    query = DmarcReport.query.order_by(DmarcReport.end.desc())
    if request.args.get("domain"):
        query = query.filter(DmarcReport.domain == request.args["domain"].lower())
    return _paginated(query, lambda r: {
        "id": r.id, "org": r.org, "report_id": r.report_id, "domain": r.domain, "policy": r.policy,
        "begin": _iso(r.begin), "end": _iso(r.end), "messages": r.messages, "passed": r.passed,
        "records": [{"source_ip": x.source_ip, "count": x.count, "disposition": x.disposition, "dkim": x.dkim,
                     "spf": x.spf, "header_from": x.header_from} for x in r.records]})


@bp.get("/reports/tls")
def list_tls_reports():
    query = TlsReport.query.order_by(TlsReport.end.desc())
    if request.args.get("domain"):
        query = query.filter(TlsReport.domain == request.args["domain"].lower())
    return _paginated(query, lambda r: {
        "id": r.id, "org": r.org, "report_id": r.report_id, "domain": r.domain, "policy_type": r.policy_type,
        "begin": _iso(r.begin), "end": _iso(r.end), "successful": r.successful, "failed": r.failed,
        "failures": json.loads(r.failures or "[]")})


# ---------------------------------------------------------------------------
# Statistics
# ---------------------------------------------------------------------------

@bp.get("/statistics")
def statistics():
    range_key = request.args.get("range", "7d")
    if range_key not in stats.RANGES:
        raise ApiError(400, f"range must be one of {', '.join(stats.RANGES)}")
    direction = request.args.get("direction", "")
    if direction not in ("", "inbound", "outbound"):
        raise ApiError(400, "direction must be inbound or outbound")
    data = stats.series(range_key, request.args.get("domain", "").lower(), direction)
    return jsonify({"range": data["range"], "bucket_hours": data["bucket_hours"], "start": _iso(data["start"]),
                    "end": _iso(data["end"]), "totals": data["totals"],
                    "buckets": [{**b, "start": _iso(b["start"])} for b in data["buckets"]],
                    "top_domains": [{"domain": d, "messages": n} for d, n in data["top"]]})


# ---------------------------------------------------------------------------
# Monitoring
# ---------------------------------------------------------------------------

@bp.get("/monitoring/checks")
def monitoring_checks():
    return jsonify({"checks": {name: {**result, "label": monitoring.label(name)}
                               for name, result in monitoring.check().items()}})


# ---------------------------------------------------------------------------
# Cluster
# ---------------------------------------------------------------------------

def _cluster_member_json(m):
    keys = ("name", "address", "role", "self", "reporting", "age", "maintenance", "maintenance_applied", "changed_by",
            "promoting", "last_action", "galera", "valkey", "sentinel", "vip", "queue", "services_down", "scanned",
            "load", "cpus", "memory_percent", "disk", "uptime", "version", "deployed_at")
    data = {key: m[key] for key in keys}
    data["reported_at"] = _iso(m["reported_at"])
    data["maintenance_since"] = _iso(m["maintenance_since"])
    return data


@bp.get("/cluster")
def get_cluster():
    st = cluster.state()
    if st is None:
        return jsonify({"cluster": False, "setup": cluster.setup_status(), "busy": cluster.setup_busy(),
                        "addresses": cluster.local_addresses()})
    return jsonify({"cluster": True, "self": st["self"], "level": st["level"], "votes": st["votes"],
                    "valkey_master": st["valkey_master"], "vip": st["vip"], "witness": st["witness"],
                    "problems": st["problems"], "notices": st["notices"],
                    "members": [_cluster_member_json(m) for m in st["members"]]})


@bp.put("/cluster/nodes/<node>/maintenance")
def cluster_maintenance(node):
    data = _body(("enabled", "force"), required=("enabled",))
    _check_types(data, {"enabled": ("boolean",), "force": ("boolean",)})
    cluster.set_maintenance(node, data["enabled"], _actor(), force=bool(data.get("force")))
    db.session.commit()
    return jsonify({"node": node.lower(), "maintenance": data["enabled"]})


@bp.post("/cluster/nodes/<node>/valkey-master")
def cluster_valkey_master(node):
    cluster.request_valkey_master(node, _actor())
    db.session.commit()
    return jsonify({"node": node.lower(), "requested": True}), 202


@bp.delete("/cluster/nodes/<node>")
def cluster_remove_node(node):
    remaining = cluster.remove_node(node, _actor())
    db.session.commit()
    return jsonify({"removed": node.lower(), "nodes": [name for name, _ in remaining]})


@bp.delete("/cluster/witness")
def cluster_remove_witness():
    cluster.remove_witness(_actor())
    db.session.commit()
    return "", 204


@bp.post("/cluster/join-information")
def cluster_join_information():
    info = cluster.join_information(_actor())
    db.session.commit()
    return jsonify(info), 201


@bp.post("/cluster/create")
def cluster_create():
    data = _body(("address", "vip"), required=("address",))
    _check_types(data, {"address": ("string",), "vip": ("string", "null")})
    return jsonify(cluster.request_create(data["address"], data.get("vip") or "")), 202


@bp.post("/cluster/join")
def cluster_join():
    data = _body(("information", "address"), required=("information", "address"))
    _check_types(data, {"information": ("string",), "address": ("string",)})
    return jsonify(cluster.request_join(data["information"], data["address"])), 202


# ---------------------------------------------------------------------------
# Journaling
# ---------------------------------------------------------------------------

@bp.get("/journal/status")
def journal_status():
    return jsonify(journal.status())


# ---------------------------------------------------------------------------
# Messages reported by users
# ---------------------------------------------------------------------------

@bp.get("/user-reports")
def list_user_reports():
    return jsonify({"addresses": user_reports.addresses(), "items": [
        {"id": r.id, "at": _iso(r.at), "reporter": r.reporter, "kind": r.kind, "status": r.status,
         "learned": r.learned, "subjects": r.subjects, "detail": r.detail} for r in user_reports.recent()]})
