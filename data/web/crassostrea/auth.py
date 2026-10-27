import time

from flask import Blueprint, abort, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user, logout_user
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db, login_manager
from .forms import ChoosePasswordForm, CodeForm, ForgotPasswordForm, LoginForm, PasswordForm, TwoFactorDisableForm
from .models import Admin, MailboxUser, get_setting, utcnow
from .services import adminaccess, branding, invites, store, twofactor
from .views import safe_next

bp = Blueprint("auth", __name__)

# Compared against when the username does not exist, so the response time
# does not reveal which usernames are valid.
_DUMMY_HASH = generate_password_hash("not-a-real-password")

# Session keys of the two-factor login: the administrator whose password was
# right (until the code is entered), the secret of a setup in progress
PENDING = "2fa_pending"
SETUP_SECRET = "2fa_setup_secret"
PENDING_MAX_AGE = 300
# Reachable while an administrator must still set up two-factor login
TWO_FACTOR_OPEN = {"auth.twofactor_setup", "auth.logout", "static", "branding.favicon", "branding.logo",
                   "branding.stylesheet", "branding.set_theme"}


@login_manager.user_loader
def load_user(user_id):
    kind, _, raw_id = str(user_id).partition(":")
    model = {"admin": Admin, "user": MailboxUser}.get(kind)
    if model is None or not raw_id.isdigit():
        return None
    account = db.session.get(model, int(raw_id))
    # Disabled accounts lose their existing sessions immediately
    return account if account is not None and account.active else None


@bp.before_app_request
def expire_login():
    """A login ends the session lifetime of Settings after it began, however
    active the session is (live pages request updates all the time); closing
    the browser ends it earlier. Sessions without a login time are ended."""
    if "_user_id" not in session:
        return
    started = session.get("login_at")
    lifetime = get_setting("session_lifetime_minutes") * 60
    valid = isinstance(started, (int, float)) and not isinstance(started, bool)
    if valid and 0 <= time.time() - started < lifetime:
        return
    logout_user()
    session.clear()
    flash("Your session has expired, please log in again.", "info")


@bp.before_app_request
def restrict_admin_networks():
    """Settings -> administrator access: an administrator's session from an
    address outside the allowed networks ends (API keys have their own)."""
    if not current_user.is_authenticated or not current_user.is_admin:
        return None
    endpoint = request.endpoint or ""
    if endpoint.startswith("api.") or endpoint in ("static", "branding.stylesheet", "branding.favicon"):
        return None
    if adminaccess.allowed(request.remote_addr):
        return None
    logout_user()
    session.clear()
    if endpoint == "auth.docs_access":
        return "", 401
    flash("Administrators cannot use the web interface from your address.", "danger")
    return redirect(url_for("auth.login"))


@bp.before_app_request
def require_two_factor():
    """With Settings -> require two-factor login, an administrator without it
    can only set it up (API keys are no password: not affected)."""
    if not current_user.is_authenticated or not current_user.is_admin:
        return None
    endpoint = request.endpoint or ""
    if endpoint in TWO_FACTOR_OPEN or endpoint.startswith("api."):
        return None
    if twofactor.required() and not twofactor.enabled(current_user):
        if endpoint == "auth.docs_access":
            return "", 401  # nginx only understands 2xx, 401 and 403 from it
        flash("Set up two-factor login to continue: it is required for administrators.", "info")
        return redirect(url_for("auth.twofactor_setup"))
    return None


@bp.get("/auth/docs")
def docs_access():
    """nginx's auth_request for /docs/ (system/lib/docs.sh): 204 lets a
    logged-in administrator see the documentation, 401 sends anyone else to
    the login page."""
    if current_user.is_authenticated and current_user.is_admin:
        return "", 204
    return "", 401


def home_url(account):
    return url_for("dashboard.index") if account.is_admin else url_for("portal.index")


def _find_account(login):
    """Administrators log in with their username, mailbox users with their address."""
    admin = Admin.query.filter_by(username=login).first()
    if admin is not None:
        return admin
    if "@" in login:
        return MailboxUser.query.filter_by(email=login.strip().lower()).first()
    return None


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(home_url(current_user))
    form = LoginForm()
    if form.validate_on_submit():
        ip = request.remote_addr or "unknown"
        if store.login_blocked(ip, form.username.data):
            flash("Too many failed logins, please try again later.", "danger")
            return render_template("login.html", form=form), 429
        if "@" not in form.username.data and not adminaccess.allowed(ip):
            # only administrators log in without an address: no password is
            # checked, nothing tells whether the username exists
            flash(f"Administrators cannot log in from your address ({ip}).", "danger")
            return render_template("login.html", form=form), 403
        account = _find_account(form.username.data)
        if account is None:
            check_password_hash(_DUMMY_HASH, form.password.data)
        elif account.active and account.check_password(form.password.data):
            if account.is_admin and twofactor.enabled(account):
                # the code decides; failed attempts are counted until then
                session[PENDING] = {"id": account.id, "at": int(time.time()),
                                    "next": safe_next(request.args.get("next"), "")}
                return redirect(url_for("auth.login_code"))
            return _complete_login(account, ip, form.username.data, request.args.get("next"))
        store.report_failed_login(form.username.data, ip)
        flash("Invalid username or password.", "danger")
    return render_template("login.html", form=form)


def _complete_login(account, ip, login, next_url):
    login_user(account)
    session["login_at"] = int(time.time())
    account.last_login_at = utcnow()
    db.session.commit()
    store.clear_failed_logins(ip, login)
    return redirect(safe_next(next_url, home_url(account)))


@bp.route("/login/code", methods=["GET", "POST"])
def login_code():
    """Second step of an administrator's login with two-factor login."""
    pending = session.get(PENDING)
    admin = None
    if isinstance(pending, dict) and 0 <= time.time() - pending.get("at", 0) <= PENDING_MAX_AGE:
        admin = db.session.get(Admin, pending.get("id") or 0)
    if admin is None or not admin.active or not twofactor.enabled(admin) or not adminaccess.allowed(
            request.remote_addr):
        session.pop(PENDING, None)
        flash("Please log in again.", "info")
        return redirect(url_for("auth.login"))
    form = CodeForm()
    if form.validate_on_submit():
        ip = request.remote_addr or "unknown"
        if store.login_blocked(ip, admin.username):
            flash("Too many failed logins, please try again later.", "danger")
            return render_template("login_code.html", form=form), 429
        kind = twofactor.verify(admin, form.code.data)
        if kind:
            session.pop(PENDING, None)
            if kind == "recovery":
                flash(f"You used a recovery code; {twofactor.recovery_codes_left(admin)} left. Create new ones on "
                      "your account page if you lost your phone.", "warning")
            return _complete_login(admin, ip, admin.username, pending.get("next"))
        store.report_failed_login(admin.username, ip)
        flash("Invalid code.", "danger")
    return render_template("login_code.html", form=form)


@bp.route("/login/forgot", methods=["GET", "POST"])
def forgot_password():
    """Mailbox users ask for a link to set a new password. The answer is the
    same whether the address has an account or not."""
    if current_user.is_authenticated:
        return redirect(home_url(current_user))
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        invites.request_reset(form.email.data, request.remote_addr or "unknown")
        flash(f"If {form.email.data.strip()} has an account, a mail with a link to set a new password is on its "
              f"way. The link is valid for {get_setting('mailbox_invite_days')} day(s).", "info")
        return redirect(url_for("auth.login"))
    return render_template("forgot_password.html", form=form)


@bp.route("/account/set-password/<token>", methods=["GET", "POST"])
def set_password(token):
    """The link of an invitation or a password reset (services/invites.py):
    one use; the mailbox user is logged in afterwards."""
    row, user = invites.resolve(token)
    if row is None:
        response = render_template("set_password.html", form=None), 404
    else:
        form = ChoosePasswordForm()
        if form.validate_on_submit():
            invites.use(row, user, form.password.data)
            db.session.commit()
            if current_user.is_authenticated:
                logout_user()
            session.clear()
            flash("Your password is set.", "success")
            return _complete_login(user, request.remote_addr or "unknown", user.email, None)
        response = render_template("set_password.html", form=form, address=user.email), 200
    # the token is in the URL: not to other sites, not cached
    page, code = response
    return page, code, {"Referrer-Policy": "no-referrer", "Cache-Control": "no-store"}


@bp.post("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("auth.login"))


@bp.route("/account", methods=["GET", "POST"])
@login_required
def account():
    form = PasswordForm()
    if form.validate_on_submit():
        if not current_user.check_password(form.current.data):
            form.current.errors.append("Current password is wrong")
        else:
            current_user.set_password(form.password.data)
            db.session.commit()
            flash("Password changed.", "success")
            return redirect(url_for("auth.account"))
    return _account_page(form)


def _account_page(form=None, codes_form=None, disable_form=None):
    return render_template("account.html", form=form or PasswordForm(formdata=None),
                           codes_form=codes_form or CodeForm(prefix="codes", formdata=None),
                           disable_form=disable_form or TwoFactorDisableForm(prefix="off", formdata=None),
                           two_factor=current_user.is_admin and twofactor.enabled(current_user),
                           two_factor_required=twofactor.required(),
                           recovery_left=twofactor.recovery_codes_left(current_user) if current_user.is_admin else 0)


def _admin_only():
    if not current_user.is_admin:
        abort(403)


@bp.route("/account/two-factor", methods=["GET", "POST"])
@login_required
def twofactor_setup():
    _admin_only()
    if twofactor.enabled(current_user):
        return redirect(url_for("auth.account"))
    secret = session.get(SETUP_SECRET) or twofactor.new_secret()
    session[SETUP_SECRET] = secret
    form = CodeForm()
    if form.validate_on_submit():
        codes = twofactor.enable(current_user, secret, form.code.data)
        if codes:
            db.session.commit()
            session.pop(SETUP_SECRET, None)
            return render_template("twofactor_codes.html", codes=codes)
        form.code.errors.append("The code does not match. Check that your phone's clock is right and try again.")
    issuer = f"{branding.get_branding()['name']} ({current_app.config['HOSTNAME']})"
    uri = twofactor.provisioning_uri(secret, current_user.username, issuer)
    return render_template("twofactor_setup.html", form=form, qr=twofactor.qr_data_uri(uri),
                           secret=" ".join(secret[i:i + 4] for i in range(0, len(secret), 4)),
                           required=twofactor.required())


@bp.post("/account/two-factor/recovery-codes")
@login_required
def twofactor_recovery_codes():
    _admin_only()
    form = CodeForm(prefix="codes")
    if form.validate_on_submit() and twofactor.verify(current_user, form.code.data) == "totp":
        codes = twofactor.regenerate_recovery_codes(current_user)
        db.session.commit()
        return render_template("twofactor_codes.html", codes=codes)
    db.session.rollback()
    form.code.errors.append("Invalid code from your app.")
    return _account_page(codes_form=form), 400


@bp.post("/account/two-factor/disable")
@login_required
def twofactor_disable():
    _admin_only()
    if twofactor.required():
        flash("Two-factor login is required for administrators (Settings).", "danger")
        return redirect(url_for("auth.account"))
    form = TwoFactorDisableForm(prefix="off")
    if form.validate_on_submit():
        if not current_user.check_password(form.password.data):
            form.password.errors.append("Wrong password")
        elif twofactor.verify(current_user, form.code.data) != "totp":
            form.code.errors.append("Invalid code from your app")
        else:
            twofactor.disable(current_user)
            db.session.commit()
            flash("Two-factor login is off.", "success")
            return redirect(url_for("auth.account"))
    db.session.rollback()
    return _account_page(disable_form=form), 400
