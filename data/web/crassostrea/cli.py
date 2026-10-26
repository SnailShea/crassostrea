"""Management commands: ``flask --app crassostrea <command>``."""
import secrets
import time
from datetime import timedelta

import click
import redis
from flask import current_app

from .extensions import db
from .models import SETTING_DEFAULTS, Admin, QuarantineItem, Setting, get_setting, touch_config, utcnow


def register(app):
    app.cli.add_command(init_db)
    app.cli.add_command(create_admin)
    app.cli.add_command(reset_password)
    app.cli.add_command(reset_two_factor)
    app.cli.add_command(admin_networks)
    app.cli.add_command(provision_accounts)
    app.cli.add_command(cleanup)
    app.cli.add_command(sync)
    app.cli.add_command(sync_directories)
    app.cli.add_command(send_digests)
    app.cli.add_command(check_alerts)
    app.cli.add_command(siem_forward)
    app.cli.add_command(journal_send)
    app.cli.add_command(cluster_report)


def _audit(action, target, message):
    """Management commands change accounts as root: recorded like web UI changes."""
    from .services import audit
    try:
        audit.record(action, target=target, message=message)
    except Exception as exc:  # the database may be the problem being fixed
        click.echo(f"Warning: cannot write the audit log: {exc}")


def _store():
    from .services import store
    return store


@click.command("init-db")
def init_db():
    """Create tables, default settings, the initial admin and map files."""
    # The nodes of a cluster may start together: one of them sets up the
    # database while the others wait (redis may still be electing a master)
    for attempt in range(30):
        try:
            with _store().job_lock("init-db", timeout=600, wait=600) as acquired:
                if not acquired:
                    raise click.ClickException("Another node is still setting up the database")
                _init_database()
            break
        except redis.RedisError as exc:
            if attempt == 29:
                raise click.ClickException(f"Cannot lock the database setup in redis: {exc}") from exc
            time.sleep(2)

    from .services.maps import sync_all
    sync_all()
    click.echo("Database initialised.")


def _init_database():
    db.create_all()
    _migrate()
    for key, value in SETTING_DEFAULTS.items():
        if db.session.get(Setting, key) is None:
            db.session.add(Setting(key=key, value=str(value)))
    db.session.flush()
    if get_setting("config_updated_at") == 0:
        touch_config()

    if Admin.query.count() == 0:
        password = current_app.config["INITIAL_ADMIN_PASSWORD"]
        generated = not password
        if generated:
            password = secrets.token_urlsafe(16)
        admin = Admin(username="admin")
        admin.set_password(password)
        db.session.add(admin)
        if generated:
            click.echo("=" * 70)
            click.echo(f"Created initial administrator 'admin' with password: {password}")
            click.echo("=" * 70)
        else:
            click.echo("Created initial administrator 'admin' (password from WEB_ADMIN_PASSWORD)")
    db.session.commit()

    try:
        _store().seed_f2b_regex()
    except Exception as exc:  # redis may still be starting, not fatal
        click.echo(f"Warning: cannot update netfilter rules in redis: {exc}")


# Columns added to existing tables: (table, column, DDL type). create_all()
# only creates missing tables, never columns; init-db adds these.
_MIGRATIONS = []


def _migrate():
    inspector = db.inspect(db.engine)
    for table, column, ddl in _MIGRATIONS:
        if column not in {c["name"] for c in inspector.get_columns(table)}:
            with db.engine.begin() as conn:
                conn.execute(db.text(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}"))
            click.echo(f"Migrated: added {table}.{column}")


@click.command("create-admin")
@click.argument("username")
@click.password_option()
def create_admin(username, password):
    """Create an administrator."""
    if Admin.query.filter_by(username=username).first():
        raise click.ClickException(f"Administrator {username} already exists")
    admin = Admin(username=username)
    admin.set_password(password)
    db.session.add(admin)
    db.session.commit()
    _audit("cli.create-admin", username, "Administrator created")
    click.echo(f"Administrator {username} created.")


@click.command("reset-password")
@click.argument("username", default="admin")
@click.option("--password", help="New password (generated if omitted)")
def reset_password(username, password):
    """Reset the password of an administrator (re-activates the account)."""
    admin = Admin.query.filter_by(username=username).first()
    if admin is None:
        admin = Admin(username=username)
        db.session.add(admin)
    password = password or secrets.token_urlsafe(16)
    admin.set_password(password)
    admin.active = True
    db.session.commit()
    try:
        _store().clear_all_failed_logins()
    except Exception as exc:
        click.echo(f"Warning: cannot reset login throttling: {exc}")
    _audit("cli.reset-password", username, "Password reset, account enabled")
    click.echo(f"Password for {username}: {password}")


@click.command("reset-2fa")
@click.argument("username")
def reset_two_factor(username):
    """Turn off two-factor login of an administrator (lost phone and recovery codes)."""
    from .services import twofactor
    admin = Admin.query.filter_by(username=username).first()
    if admin is None:
        raise click.ClickException(f"There is no administrator {username}")
    twofactor.disable(admin)
    db.session.commit()
    _audit("cli.reset-2fa", username, "Two-factor login turned off")
    click.echo(f"Two-factor login of {username} is off.")


@click.command("admin-networks")
@click.option("--clear", is_flag=True, help="Allow administrators from any address again")
@click.option("--add", "add", multiple=True, metavar="NETWORK", help="Allow this network or address too")
def admin_networks(clear, add):
    """Show or change the networks administrators may log in from (an
    administrator locked out by Settings -> administrator access)."""
    from .services import filters
    from .services.errors import ServiceError
    if clear or add:
        current = "" if clear else filters.get_settings()["admin_allowed_networks"]
        try:
            filters.update_settings(admin_allowed_networks="\n".join([current, *add]))
        except ServiceError as exc:
            raise click.ClickException(str(exc))
        db.session.commit()
        _audit("cli.admin-networks", "admin_allowed_networks", "Cleared" if clear and not add else "Changed")
    value = filters.get_settings()["admin_allowed_networks"]
    click.echo(value if value else "Administrators may log in from any address.")


@click.command("cleanup")
def cleanup():
    """Expire old quarantine items and mail log entries, trim the Postfix log in redis."""
    with _store().job_lock("cleanup") as acquired:
        if not acquired:
            click.echo("Another node is running the cleanup.")
            return
        _cleanup()


def _cleanup():
    days = get_setting("quarantine_retention_days")
    cutoff = utcnow() - timedelta(days=days)
    deleted = QuarantineItem.query.filter(QuarantineItem.created_at < cutoff).delete(synchronize_session=False)
    from .services import audit, maillog, reports, stats
    from .services.digest import cleanup_tokens
    logged, log_days = maillog.cleanup()
    audited, audit_days = audit.cleanup()
    report_count, report_days = reports.cleanup()
    stat_count, stat_days = stats.cleanup()
    tokens = cleanup_tokens()
    db.session.commit()
    click.echo(f"Deleted {deleted} quarantine item(s) older than {days} day(s), {logged} mail log entr"
               f"{'y' if logged == 1 else 'ies'} older than {log_days} day(s), {audited} audit log entr"
               f"{'y' if audited == 1 else 'ies'} older than {audit_days} day(s), {report_count} DMARC/TLS "
               f"report(s) older than {report_days} day(s), {stat_count} hourly statistic(s) older than "
               f"{stat_days} day(s) and {tokens} expired digest token(s) and password link(s).")
    try:
        _store().trim_logs(current_app.config["LOG_LINES"])
    except Exception as exc:
        click.echo(f"Warning: cannot trim logs: {exc}")


@click.command("sync")
def sync():
    """Rewrite all rspamd/postfix map files from the database."""
    from .services.maps import sync_all
    if not sync_all():
        raise click.ClickException("Some maps could not be written, see log")
    click.echo("Maps are up to date.")


@click.command("sync-directories")
def sync_directories():
    """Copy the recipients of LDAP and Microsoft 365 directories to the domains that use them."""
    from .services import directory
    with _store().job_lock("sync-directories", timeout=600) as acquired:
        if not acquired:
            click.echo("Another node is synchronising the directories.")
            return
        outcome = directory.sync_all()
    for name, result in outcome.items():
        if isinstance(result, Exception):
            click.echo(f"{name}: not synchronised: {result}")
        else:
            for domain, counts in result.items():
                click.echo(f"{name}: {domain}: {counts['total']} recipients ({counts['added']} added, "
                           f"{counts['removed']} removed)")
    if not outcome:
        click.echo("No domain uses a directory.")
    if any(isinstance(result, Exception) for result in outcome.values()):
        raise SystemExit(1)


@click.command("check-alerts")
def check_alerts():
    """Mail the administrators about problems (Monitoring page)."""
    from .services import mailer, monitoring
    with _store().job_lock("check-alerts", timeout=300) as acquired:
        if not acquired:
            click.echo("Another node checks the alerts.")
            return
        try:
            failing, recovered = monitoring.run_alerts()
        except mailer.ReleaseError as exc:
            raise click.ClickException(f"The alert mail could not be sent: {exc}") from exc
    for name, message in failing:
        click.echo(f"PROBLEM {name}: {message}")
    for name, message in recovered:
        click.echo(f"SOLVED {name}: {message}")


@click.command("siem-forward")
def siem_forward():
    """Send the queued events to the SIEM (runs until stopped)."""
    import signal
    from .services import siem
    stopping = []
    signal.signal(signal.SIGTERM, lambda *args: stopping.append(True))
    click.echo("Forwarding events to the SIEM (settings: Monitoring page)")
    while not stopping:
        try:
            siem.forward(stop=lambda: bool(stopping))
        except Exception as exc:  # Valkey or the database away: try again
            current_app.logger.warning("SIEM forwarding paused: %s", exc)
            db.session.rollback()
            time.sleep(10)


@click.command("journal-send")
def journal_send():
    """Send journal copies to the archive (runs until stopped)."""
    import signal
    from .services import journal
    stopping = []
    signal.signal(signal.SIGTERM, lambda *args: stopping.append(True))
    click.echo("Sending journal copies (settings: Journaling page)")
    while not stopping:
        try:
            journal.forward(stop=lambda: bool(stopping))
        except Exception as exc:  # Valkey or the database away: try again
            current_app.logger.warning("journaling paused: %s", exc)
            db.session.rollback()
            time.sleep(10)


@click.command("cluster-report")
def cluster_report():
    """Report this cluster node's state and apply maintenance (runs until stopped)."""
    import signal
    from .services import cluster
    if not cluster.enabled():
        raise click.ClickException("This gateway is not part of a cluster (HA_NODES is empty)")
    stopping = []
    signal.signal(signal.SIGTERM, lambda *args: stopping.append(True))
    click.echo(f"Reporting the state of {current_app.config['HOSTNAME']} every {cluster.REPORT_SECONDS} s")
    while not stopping:
        try:
            requested = cluster.report_once()
            if requested:
                click.echo(f"Requested of crassostrea-cluster.service: {requested}")
        except Exception as exc:  # the database away (it is a cluster): try again
            current_app.logger.warning("cluster report failed: %s", exc)
            db.session.rollback()
        db.session.remove()
        for _ in range(cluster.REPORT_SECONDS):
            if stopping:
                break
            time.sleep(1)


@click.command("provision-accounts")
def provision_accounts():
    """Create accounts for recipients of quarantined mail (Settings, when
    enabled) and mail them a link to set a password."""
    from .services.invites import provision
    # Only one node of a cluster: the others would create them too
    with _store().job_lock("provision-accounts") as acquired:
        if not acquired:
            click.echo("Another node is creating the accounts.")
            return
        created, failed = provision()
    for address in created:
        click.echo(f"Created {address}")
    for address, error in failed.items():
        click.echo(f"Failed for {address}: {error}")
    if failed:
        raise SystemExit(1)


@click.command("send-digests")
def send_digests():
    """Send quarantine digests that are due."""
    from .services.digest import send_due_digests
    # Only one node of a cluster sends: the others would send them again
    with _store().job_lock("send-digests") as acquired:
        if not acquired:
            click.echo("Another node is sending the digests.")
            return
        sent, failed = send_due_digests()
    click.echo(f"Sent {len(sent)} digest(s).")
    for address, error in failed.items():
        click.echo(f"Failed for {address}: {error}")
    if failed:
        raise SystemExit(1)
