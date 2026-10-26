"""/metrics for Prometheus (services/monitoring.py), with the bearer token
created under Settings → Alerts & export."""
from flask import Blueprint, Response, request

from ..services import monitoring

bp = Blueprint("metrics", __name__)


@bp.get("/metrics")
def metrics():
    header = request.headers.get("Authorization", "")
    token = header[7:].strip() if header.lower().startswith("bearer ") else ""
    if not monitoring.token_valid(token):
        return Response("A valid bearer token is required (Settings -> Alerts & export)\n", 401,
                        {"WWW-Authenticate": 'Bearer realm="metrics"', "Content-Type": "text/plain"})
    return Response(monitoring.render(monitoring.collect()), 200,
                    {"Content-Type": "text/plain; version=0.0.4; charset=utf-8", "Cache-Control": "no-store"})
