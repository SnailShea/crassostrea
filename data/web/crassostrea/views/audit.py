from flask import request

from ..services import audit
from . import protected_blueprint, render_live

bp = protected_blueprint("audit", __name__, url_prefix="/audit")

PER_PAGE = 100


@bp.get("/")
def index():
    page = request.args.get("page", 1, type=int)
    query = audit.filtered(request.args.get("actor", ""), request.args.get("outcome", ""),
                           request.args.get("q", ""))
    pagination = query.paginate(page=page, per_page=PER_PAGE, error_out=False)
    return render_live("audit.html", "_audit_live.html", pagination=pagination, actors=audit.actors(),
                       describe=audit.describe, details=audit.details)
