"""Cluster page: the state of every member (services/cluster.py), maintenance
and the Valkey master; building the cluster like Proxmox: create it on a
single gateway, hand out join information, join another gateway, remove a
member."""
from flask import flash, redirect, render_template, request, session, url_for
from flask_login import current_user

from ..extensions import db
from ..services import cluster
from ..services.errors import ServiceError
from . import protected_blueprint, render_live

bp = protected_blueprint("cluster", __name__, url_prefix="/cluster")


@bp.get("/")
def index():
    """Monitoring → Cluster: the state of the members."""
    if not cluster.enabled():
        return render_template("cluster.html", setup=cluster.setup_status())
    errors, state = [], None
    try:
        state = cluster.state()
    except Exception as exc:  # the database of this node is the problem
        db.session.rollback()
        errors.append(f"Cannot read the cluster's state from the database: {exc}")
    return render_live("cluster.html", "_cluster_live.html", state=state, errors=errors)


@bp.get("/manage")
def manage():
    """Settings → Cluster: create or join (single gateway); join information,
    maintenance, the Valkey master, removing members (cluster)."""
    if not cluster.enabled():
        return render_live("cluster_manage.html", "_cluster_setup_status.html", state=None, errors=[],
                           setup=cluster.setup_status(), busy=cluster.setup_busy(),
                           addresses=cluster.local_addresses())
    errors, state = [], None
    try:
        state = cluster.state()
    except Exception as exc:
        db.session.rollback()
        errors.append(f"Cannot read the cluster's state from the database: {exc}")
    return render_live("cluster_manage.html", "_cluster_manage_live.html", state=state, errors=errors,
                       join_info=session.pop("cluster_join_info", None),
                       members_text=cluster.format_members(cluster.nodes()),
                       witness_text=cluster.format_members([cluster.witness()] if cluster.witness() else []))


@bp.post("/<node>/maintenance")
def maintenance(node):
    on = request.form.get("on") == "1"
    try:
        cluster.set_maintenance(node, on, current_user.username, force=request.form.get("force") == "1")
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        db.session.commit()
        flash(f"{node}: maintenance {'on' if on else 'off'}; the node applies it within seconds.", "success")
    return redirect(url_for("cluster.manage"))


@bp.post("/<node>/valkey-master")
def valkey_master(node):
    try:
        cluster.request_valkey_master(node, current_user.username)
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        db.session.commit()
        flash(f"Making {node} the Valkey master; this takes about 30 seconds.", "success")
    return redirect(url_for("cluster.manage"))


@bp.post("/<node>/remove")
def remove(node):
    try:
        cluster.remove_node(node, current_user.username)
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        db.session.commit()
        flash(f"{node} removed: every member updates its configuration within a minute. Do not start {node} "
              "again with this cluster's data; reinstall it to use it again.", "success")
    return redirect(url_for("cluster.manage"))


@bp.post("/witness/remove")
def remove_witness():
    try:
        cluster.remove_witness(current_user.username)
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        db.session.commit()
        flash("The witness was removed: every member updates its configuration within a minute. Stop its "
              "services there with system/cluster.sh leave.", "success")
    return redirect(url_for("cluster.manage"))


@bp.post("/join-information")
def join_information():
    try:
        info = cluster.join_information(current_user.username)
    except ServiceError as exc:
        db.session.rollback()
        flash(str(exc), "danger")
    else:
        db.session.commit()
        # shown once, like a new API key
        session["cluster_join_info"] = info
    return redirect(url_for("cluster.manage") + "#join-information")


@bp.post("/setup/create")
def create():
    try:
        cluster.request_create(request.form.get("address", ""), request.form.get("vip", ""))
    except ServiceError as exc:
        flash(str(exc), "danger")
    else:
        flash("Creating the cluster: the gateway installs the cluster components and restarts its services, the "
              "web interface too. This takes a few minutes; reload the page if it does not answer for a moment.",
              "success")
    return redirect(url_for("cluster.manage"))


@bp.post("/setup/join")
def join():
    try:
        target = cluster.request_join(request.form.get("information", ""), request.form.get("address", ""))
    except ServiceError as exc:
        flash(str(exc), "danger")
    else:
        flash(f"Joining the cluster of {target['host']}: this gateway gets the cluster's configuration and "
              "data and restarts its services. This takes several minutes; afterwards log in with an account of "
              "the cluster.", "success")
    return redirect(url_for("cluster.manage"))
