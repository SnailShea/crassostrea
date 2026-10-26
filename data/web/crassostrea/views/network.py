from flask import render_template

from ..services import netcheck
from . import protected_blueprint

bp = protected_blueprint("network", __name__)


@bp.get("/network")
def index():
    """DNS records and ports the gateway needs, checked on every visit."""
    results = netcheck.run(netcheck.settings())
    return render_template("network.html", results=results, summary=netcheck.summary(results))
