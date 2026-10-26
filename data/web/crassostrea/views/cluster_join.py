"""POST /cluster/join: a gateway joining the cluster with a join information
(its system/libexec/cluster-setup calls this, over HTTPS pinned to this
node's certificate). No login: the one-time secret of the join information
authenticates it (services/cluster.py join)."""
import base64

from flask import Blueprint, current_app, jsonify, request

from ..extensions import csrf
from ..services import audit, cluster
from ..services.errors import ServiceError

bp = Blueprint("cluster_join", __name__)
csrf.exempt(bp)


@bp.post("/cluster/join")
def join():
    if not cluster.enabled():
        return jsonify({"error": "This gateway is not part of a cluster"}), 409
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object with token, hostname and address is required"}), 400
    hostname = str(data.get("hostname", ""))[:253]
    try:
        status, bundle = cluster.join(str(data.get("token", "")), hostname, str(data.get("address", "")))
    except ServiceError as exc:
        current_app.logger.warning("cluster join of %s from %s refused: %s", hostname, request.remote_addr, exc)
        audit.record("cluster.join", target=hostname, message=f"Refused from {request.remote_addr}: {exc}",
                     actor=f"join:{hostname}", outcome="failed")
        return jsonify({"error": str(exc)}), exc.status
    if bundle is None:
        return jsonify({"state": "preparing"}), 202
    audit.record("cluster.join", target=hostname, message=f"Join bundle handed to {hostname} ({request.remote_addr})",
                 actor=f"join:{hostname}")
    return jsonify({"state": "ready", "bundle": base64.b64encode(bundle).decode()}), 200
