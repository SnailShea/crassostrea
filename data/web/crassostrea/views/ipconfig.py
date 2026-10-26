import ipaddress
import re

from flask import flash, redirect, request, url_for

from ..services import ipconfig
from ..services.errors import ServiceError
from . import protected_blueprint, render_live

bp = protected_blueprint("ipconfig", __name__, url_prefix="/ip")


def _lines(text):
    return [item for item in re.split(r"[\s,]+", text or "") if item]


def form_settings(form):
    """The form as the settings network-apply takes."""
    return {"device": form.get("device") or None, **{f"ipv{v}": {"enabled": form.get(f"ipv{v}_enabled") == "on",
                        "method": form.get(f"ipv{v}_method", "manual"),
                        "addresses": _lines(form.get(f"ipv{v}_addresses")),
                        "gateway": form.get(f"ipv{v}_gateway", "").strip(),
                        "dns": _lines(form.get(f"ipv{v}_dns"))} for v in (4, 6)}}


def _client_family():
    try:
        address = ipaddress.ip_address(request.remote_addr or "")
    except ValueError:
        return None, None
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.version, str(address)


def render_page(hostname_form=None, code=200):
    """The page with a hostname form that failed validation (views/settings.py)."""
    return _render(code=code, hostname_form=hostname_form)


def _render(values=None, error=None, code=200, hostname_form=None):
    from .settings import hostname_context
    device = (values or {}).get("device") or request.args.get("device") or None
    try:
        state, state_error = ipconfig.current(device), None
    except ipconfig.NetworkStateError as exc:
        state, state_error = None, str(exc)
    except ServiceError as exc:  # an interface that is gone: show the default one
        state, state_error = ipconfig.current(), str(exc)
    version, client = _client_family()
    return render_live("ipconfig.html", "_ipconfig_status.html", state=state, state_error=state_error,
                       values=values or (state and {f"ipv{v}": state[f"ipv{v}"] for v in (4, 6)}),
                       error=error, change=ipconfig.status(), busy=ipconfig.busy(), methods=ipconfig.METHODS,
                       client_version=version, client_address=client, **hostname_context(hostname_form)), code


@bp.get("/")
def index():
    return _render()


@bp.post("/")
def save():
    values = form_settings(request.form)
    try:
        ipconfig.request_change(values)
    except ipconfig.NetworkStateError as exc:
        return _render(values, str(exc), 503)
    except ServiceError as exc:
        return _render(values, str(exc), 400)
    flash(f"Applying the IP settings of {values['device'] or 'the interface'}. Every family with a gateway is tested "
          "for internet access; if a test fails, the previous settings come back. This takes up to a minute.",
          "success")
    return redirect(url_for("ipconfig.index", device=values["device"]) + "#change")
