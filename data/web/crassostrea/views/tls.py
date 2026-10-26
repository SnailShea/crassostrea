import re

from flask import flash, redirect, request, url_for

from ..services import certificates
from ..services.errors import ServiceError
from . import protected_blueprint, render_live

bp = protected_blueprint("tls", __name__, url_prefix="/tls")


def _render(report=None, sha256=None, names_text=None, code=200):
    s = certificates.settings()
    mode = request.args.get("mode") if request.args.get("mode") in ("letsencrypt", "manual") else s["mode"]
    if report is not None:
        mode = "manual"
    status = certificates.status()
    tested = status.get("le_test") or {}
    if names_text is not None:
        names = [n for n in re.split(r"[\s,]+", names_text) if n]
    elif tested.get("names") and tested.get("at", 0) > (status.get("le_apply") or {}).get("at", 0):
        # names under test (or tested and not applied yet) are not in crassostrea.conf yet
        names = [n for n in tested["names"] if n != s["hostname"]]
    else:
        names = s["extra_names"]
    passed = certificates.passed_test(tested.get("names", [])) if tested.get("state") == "ok" else None
    response = render_live("tls.html", "_tls_status.html", settings=s, mode=mode,
                           certificate=certificates.current_certificate(), status=status, staging_test=tested,
                           busy=certificates.busy(), extra_names="\n".join(names), passed_test=passed,
                           report=report, sha256=sha256)
    return response, code


@bp.get("/")
def index():
    return _render()


def _done(message, mode=None):
    """Back to the page, on the tab of the change (the staging test and its
    Apply step show on the Let's Encrypt tab)."""
    flash(message, "success")
    return redirect(url_for("tls.index", mode=mode) + "#status")


@bp.post("/letsencrypt/test")
def letsencrypt_test():
    try:
        names = certificates.request_staging_test(request.form.get("names", ""))
    except ServiceError as exc:
        flash(str(exc), "danger")
        return _render(names_text=request.form.get("names", ""), code=400)
    return _done(f"Staging test of {', '.join(names)} started; it takes up to a few minutes.", "letsencrypt")


@bp.post("/letsencrypt/apply")
def letsencrypt_apply():
    try:
        names = certificates.request_letsencrypt(request.form.getlist("names"))
    except ServiceError as exc:
        flash(str(exc), "danger")
        return _render(code=400)
    return _done(f"Requesting the certificate for {', '.join(names)} from Let's Encrypt.", "letsencrypt")


@bp.post("/upload")
def upload():
    files = {name: request.files.get(name) for name in ("certificate", "key", "chain")}
    data = {name: (f.read(certificates.MAX_UPLOAD + 1) if f else b"") for name, f in files.items()}
    report = certificates.validate(data["certificate"], data["key"], data["chain"])
    sha256 = certificates.stage(report) if not report["errors"] else None
    return _render(report=report, sha256=sha256, code=400 if report["errors"] else 200)


@bp.post("/manual/apply")
def manual_apply():
    try:
        certificates.request_manual(request.form.get("sha256", ""))
    except ServiceError as exc:
        flash(str(exc), "danger")
        return _render(code=400)
    return _done("Installing the uploaded certificate.", "manual")


@bp.post("/versions")
def versions():
    minimums = {}
    for service in ("https", "smtp"):
        tls10, tls11 = request.form.get(f"{service}_tls10") == "on", request.form.get(f"{service}_tls11") == "on"
        if tls10 and not tls11:
            flash("TLS 1.0 can only be accepted together with TLS 1.1.", "danger")
            return _render(code=400)
        minimums[service] = "1.0" if tls10 else ("1.1" if tls11 else "1.2")
    try:
        certificates.request_versions(minimums["https"], minimums["smtp"])
    except ServiceError as exc:
        flash(str(exc), "danger")
        return _render(code=400)
    return _done("Applying the TLS versions; nginx and Postfix reload.")
