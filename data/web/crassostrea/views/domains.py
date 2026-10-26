from flask import abort, flash, redirect, render_template, request, url_for

from ..extensions import db
from ..forms import DkimGenerateForm, DkimImportForm, DomainForm, ListEntryForm, RecipientsForm
from ..models import Domain, ListEntry, get_setting, utcnow
from ..services import destination, dkim, filters
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint, require_full_admin, require_scope, scope

# Domain administrators edit their own domains; adding and deleting domains
# stays with the administrators
bp = protected_blueprint("domains", __name__, url_prefix="/domains", domain_admins=True)


def _get_domain(domain_id):
    domain = db.session.get(Domain, domain_id)
    if domain is None:
        abort(404)
    require_scope(domain.name)
    return domain


def _commit_config():
    db.session.commit()
    if not sync_all():
        flash("The change was saved but not all filter maps could be updated, see the web UI log (journalctl -u crassostrea-web).",
              "warning")


def _domain_fields(form):
    return {
        "description": form.description.data or "",
        "active": form.active.data,
        "destination_host": form.destination_host.data,
        "destination_port": form.destination_port.data,
        "use_mx": form.use_mx.data,
        "recipient_check": form.recipient_check.data,
        "directory_id": form.directory_id.data,
        "quarantine_enabled": form.quarantine_enabled.data,
        "link_protection": form.link_protection.data,
        "digest_interval": form.digest_interval.data or None,
        "greylist_score": form.greylist_score.data,
        "add_header_score": form.add_header_score.data,
        "reject_score": form.reject_score.data,
    }


def _form_error(form, exc):
    """Show a ServiceError next to the field it concerns."""
    db.session.rollback()
    field = getattr(form, exc.field, None) if exc.field else None
    if field is not None:
        field.errors = [*field.errors, str(exc)]
    else:
        flash(str(exc), "danger")


def _flash_errors(form):
    for errors in form.errors.values():
        for error in errors:
            flash(error, "danger")


@bp.get("/")
def index():
    query = request.args.get("q", "").strip().lower()
    domains = Domain.query
    if query:
        domains = domains.filter(Domain.name.contains(query))
    allowed = scope()
    if allowed is not None:
        domains = domains.filter(Domain.name.in_(sorted(allowed) or [""]))
    domains = domains.order_by(Domain.name).all()
    return render_template("domains/index.html", domains=domains, query=query)


@bp.route("/new", methods=["GET", "POST"])
def create():
    require_full_admin()
    form = DomainForm()
    if form.validate_on_submit():
        try:
            domain = filters.create_domain(form.name.data, **_domain_fields(form))
        except ServiceError as exc:
            _form_error(form, exc)
        else:
            _commit_config()
            flash(f"Domain {domain.name} added.", "success")
            return redirect(url_for("domains.edit", domain_id=domain.id))
    return render_template("domains/form.html", form=form, domain=None,
                           defaults=_global_scores())


@bp.route("/<int:domain_id>", methods=["GET", "POST"])
def edit(domain_id):
    domain = _get_domain(domain_id)
    form = DomainForm(obj=domain)
    # The name cannot be changed, recipients and list entries belong to it
    form.name.render_kw = {"readonly": True}
    if request.method == "POST":
        form.name.raw_data = [domain.name]
        form.name.data = domain.name
    if form.validate_on_submit():
        try:
            filters.update_domain(domain, **_domain_fields(form))
        except ServiceError as exc:
            _form_error(form, exc)
            domain = _get_domain(domain_id)
        else:
            _commit_config()
            flash(f"Domain {domain.name} saved.", "success")
            return redirect(url_for("domains.edit", domain_id=domain.id))
    return _render_edit(domain, form)


def _render_edit(domain, form, **extra):
    entry_form = ListEntryForm(prefix="entry")
    recipients_form = RecipientsForm(prefix="rcpt")
    dkim_form = DkimGenerateForm(prefix="dkim", data={"selector": f"sf{utcnow():%Y%m}"})
    dkim_import_form = DkimImportForm(prefix="dkimimport", data={"selector": f"sf{utcnow():%Y%m}"})
    dkim_dns = dkim.dns_record(domain.dkim_key) if domain.dkim_key else None
    return render_template("domains/form.html", form=form, domain=domain, entry_form=entry_form,
                           recipients_form=recipients_form, defaults=_global_scores(),
                           dkim_form=dkim_form, dkim_import_form=dkim_import_form, dkim_dns=dkim_dns, **extra)


@bp.post("/<int:domain_id>/test-destination")
def test_destination(domain_id):
    """Talk SMTP to the destination server (services/destination.py); the
    results are shown on the domain page."""
    domain = _get_domain(domain_id)
    address = request.form.get("address", "").strip().lower()
    if address and (len(address) > 320 or address.rpartition("@")[2] != domain.name or address.count("@") != 1
                    or any(c.isspace() or c in "<>" for c in address)):
        flash(f"The test address must be an address of {domain.name}.", "danger")
        return redirect(url_for("domains.edit", domain_id=domain.id, _anchor="destination-test"))
    form = DomainForm(obj=domain, formdata=None)
    form.name.render_kw = {"readonly": True}
    return _render_edit(domain, form, test_results=destination.test(domain, address or None),
                        test_address=address)


def _global_scores():
    return {k: get_setting(k) for k in ("greylist_score", "add_header_score", "reject_score")}


@bp.post("/<int:domain_id>/delete")
def delete(domain_id):
    require_full_admin()
    domain = _get_domain(domain_id)
    name = domain.name
    filters.delete_domain(domain)
    _commit_config()
    flash(f"Domain {name} deleted. Mail for it is no longer accepted.", "success")
    return redirect(url_for("domains.index"))


@bp.post("/<int:domain_id>/recipients")
def add_recipients(domain_id):
    domain = _get_domain(domain_id)
    form = RecipientsForm(prefix="rcpt")
    if not form.validate_on_submit():
        flash("Please enter at least one address.", "danger")
        return redirect(url_for("domains.edit", domain_id=domain.id, _anchor="recipients"))

    result = filters.add_recipients(domain, form.addresses.data.replace(",", "\n").splitlines())
    db.session.commit()
    added = len(result["added"])
    flash(f"{added} recipient(s) added, {result['skipped']} already present.", "success" if added else "info")
    if result["invalid"]:
        flash("Invalid or foreign addresses ignored: " + ", ".join(result["invalid"][:20]), "warning")
    if domain.recipient_check not in ("list", "directory"):
        flash("Note: the recipient list is only used when recipient validation is set to "
              "'Only recipients from the list' or a directory.", "info")
    return redirect(url_for("domains.edit", domain_id=domain.id, _anchor="recipients"))


@bp.post("/<int:domain_id>/recipients/delete")
def delete_recipients(domain_id):
    domain = _get_domain(domain_id)
    ids = [int(i) for i in request.form.getlist("ids") if i.isdigit()]
    if ids:
        deleted = filters.delete_recipients(domain, ids)
        db.session.commit()
        flash(f"{deleted} recipient(s) deleted.", "success")
    return redirect(url_for("domains.edit", domain_id=domain.id, _anchor="recipients"))


@bp.post("/<int:domain_id>/entries")
def add_entry(domain_id):
    domain = _get_domain(domain_id)
    form = ListEntryForm(prefix="entry")
    if form.validate_on_submit():
        try:
            filters.add_list_entry(form.list_type.data, form.kind.data, form.value.data, form.comment.data,
                                   domain=domain)
        except ServiceError as exc:
            db.session.rollback()
            if exc.status == 409:
                flash(f"{exc}.", "info")
            else:
                flash(str(exc), "danger")
        else:
            _commit_config()
            flash(f"{form.value.data} added to the {form.list_type.data} list of {domain.name}.", "success")
    else:
        _flash_errors(form)
    return redirect(url_for("domains.edit", domain_id=domain.id, _anchor="lists"))


@bp.post("/<int:domain_id>/entries/<int:entry_id>/delete")
def delete_entry(domain_id, entry_id):
    _get_domain(domain_id)
    entry = ListEntry.query.filter_by(id=entry_id, domain_id=domain_id).first_or_404()
    filters.delete_list_entry(entry)
    _commit_config()
    flash("Entry removed.", "success")
    return redirect(url_for("domains.edit", domain_id=domain_id, _anchor="lists"))


def _store_dkim_key(domain, selector, **key):
    try:
        replaced = filters.set_dkim_key(domain, selector, **key)
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
        return
    db.session.commit()
    if not sync_all():
        flash("The key was saved but could not be copied to redis yet, see the web UI log (journalctl -u crassostrea-web).", "warning")
    flash(f"DKIM key with selector '{domain.dkim_key.selector}' "
          f"{'replaced the previous key' if replaced else 'created'}. "
          "Publish the DNS record below; outbound mail is signed from now on.", "success")


@bp.post("/<int:domain_id>/dkim")
def dkim_generate(domain_id):
    domain = _get_domain(domain_id)
    form = DkimGenerateForm(prefix="dkim")
    if form.validate_on_submit():
        _store_dkim_key(domain, form.selector.data, key_size=int(form.key_size.data))
    return redirect(url_for("domains.edit", domain_id=domain.id, _anchor="dkim"))


@bp.post("/<int:domain_id>/dkim/import")
def dkim_import(domain_id):
    domain = _get_domain(domain_id)
    form = DkimImportForm(prefix="dkimimport")
    if form.validate_on_submit():
        _store_dkim_key(domain, form.selector.data, private_key=form.private_key.data)
    else:
        flash("Selector and private key are required.", "danger")
    return redirect(url_for("domains.edit", domain_id=domain.id, _anchor="dkim"))


@bp.post("/<int:domain_id>/dkim/delete")
def dkim_delete(domain_id):
    domain = _get_domain(domain_id)
    if domain.dkim_key is not None:
        filters.delete_dkim_key(domain)
        db.session.commit()
        sync_all()
        flash("DKIM key deleted, outbound mail of this domain is no longer signed. "
              "Remove the DNS record once no signed mail is in transit anymore.", "success")
    return redirect(url_for("domains.edit", domain_id=domain.id, _anchor="dkim"))
