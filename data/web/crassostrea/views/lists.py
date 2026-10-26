from flask import abort, flash, redirect, request, url_for

from ..extensions import db
from ..forms import ListEntryForm
from ..models import LIST_TYPES, Domain, ListEntry
from ..services import filters
from ..services.errors import ServiceError
from ..services.maps import sync_all
from . import protected_blueprint, render_live

bp = protected_blueprint("lists", __name__, url_prefix="/lists")


def _page(list_type):
    entries = (filters.global_list_entries().filter(ListEntry.list_type == list_type)
               .order_by(ListEntry.kind, ListEntry.value).all())
    domain_entries = (db.session.query(Domain, db.func.count(ListEntry.id))
                      .join(ListEntry, ListEntry.domain_id == Domain.id)
                      .filter(ListEntry.list_type == list_type)
                      .group_by(Domain.id).order_by(Domain.name).all())
    form = ListEntryForm(formdata=None, data={"list_type": list_type})
    return render_live("lists.html", "_lists_live.html", form=form, entries=entries, domain_entries=domain_entries,
                       list_type=list_type)


@bp.get("/")
def index():
    return redirect(url_for("lists.allow"))


@bp.get("/allow")
def allow():
    return _page("allow")


@bp.get("/block")
def block():
    return _page("block")


@bp.post("/")
def add():
    form = ListEntryForm()
    list_type = form.list_type.data if form.list_type.data in LIST_TYPES else "allow"
    if form.validate_on_submit():
        try:
            filters.add_list_entry(form.list_type.data, form.kind.data, form.value.data, form.comment.data)
        except ServiceError as exc:
            db.session.rollback()
            if exc.status == 409:
                flash(f"{exc}.", "info")
            else:
                flash(str(exc), "danger")
        else:
            db.session.commit()
            if not sync_all():
                flash("Saved, but the filter maps could not be written. See the web UI log (journalctl -u crassostrea-web).", "warning")
            flash(f"{form.value.data} added to the global {form.list_type.data} list.", "success")
    else:
        for errors in form.errors.values():
            for error in errors:
                flash(error, "danger")
    return redirect(url_for(f"lists.{list_type}"))


@bp.post("/<int:entry_id>/delete")
def delete(entry_id):
    entry = filters.global_list_entries().filter(ListEntry.id == entry_id).first_or_404()
    list_type = entry.list_type
    filters.delete_list_entry(entry)
    db.session.commit()
    sync_all()
    flash("Entry removed.", "success")
    return redirect(url_for(f"lists.{list_type}" if list_type in LIST_TYPES else "lists.index"))
