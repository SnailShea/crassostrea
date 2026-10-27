import fakeredis
import pytest
from flask import g

from crassostrea import create_app
from crassostrea.extensions import db
from crassostrea.models import Admin, ApiKey
from crassostrea.services import store


@pytest.fixture
def fake_redis(monkeypatch):
    server = fakeredis.FakeRedis(decode_responses=True)
    monkeypatch.setattr(store, "get_redis", lambda: server)
    return server


@pytest.fixture
def config(tmp_path):
    map_dir = tmp_path / "rspamd"
    postfix_dir = tmp_path / "postfix"
    map_dir.mkdir()
    postfix_dir.mkdir()
    return {
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "SQLALCHEMY_DATABASE_URI": f"sqlite:///{tmp_path / 'test.db'}",
        "SQLALCHEMY_ENGINE_OPTIONS": {},
        "WTF_CSRF_ENABLED": False,
        "SESSION_COOKIE_SECURE": False,
        "RSPAMD_MAP_DIR": str(map_dir),
        "POSTFIX_DYNAMIC_DIR": str(postfix_dir),
        "HOSTNAME_REQUEST": str(tmp_path / "hostname-request"),
        "TIMEZONE_REQUEST": str(tmp_path / "timezone"),
        "TIMEZONE_STATUS": str(tmp_path / "timezone-status.json"),
        "LOCALTIME": str(tmp_path / "localtime"),
        "WEB_ACCESS_REQUEST": str(tmp_path / "web-access"),
        "SPAMHAUS_REQUEST": str(tmp_path / "spamhaus"),
        "CONF_FILE": str(tmp_path / "crassostrea.conf"),
        "TLS_REQUEST": str(tmp_path / "tls-request.json"),
        "TLS_UPLOAD_DIR": str(tmp_path / "tls-upload"),
        "TLS_STATUS": str(tmp_path / "tls-status.json"),
        "SSL_CERT": str(tmp_path / "cert.pem"),
        "CA_BUNDLE": str(tmp_path / "ca-bundle.crt"),
        "IP_REQUEST": str(tmp_path / "ip-request.json"),
        "IP_STATUS": str(tmp_path / "ip-status.json"),
        "BACKUP_DIR": str(tmp_path / "backups"),
        "BACKUP_REQUEST": str(tmp_path / "backup-request.json"),
        "CLUSTER_REQUEST": str(tmp_path / "cluster-request"),
        "CLUSTER_PROBE": str(tmp_path / "cluster-probe.json"),
        "VERSION_FILE": str(tmp_path / "version"),
        "CLUSTER_BUNDLE_REQUEST": str(tmp_path / "cluster-bundle"),
        "CLUSTER_BUNDLE_DIR": str(tmp_path),
        "CLUSTER_SETUP_REQUEST": str(tmp_path / "cluster-setup.json"),
        "CLUSTER_SETUP_STATUS": str(tmp_path / "cluster-setup-status.json"),
        "INITIAL_ADMIN_PASSWORD": "initial-password",
        # rspamd as seen by the internal API in the tests
        "INTERNAL_CLIENTS": ["172.22.1.5", "172.22.1.9"],
    }


@pytest.fixture
def app(config, fake_redis):
    app = create_app("ui", config)

    @app.before_request
    def fresh_login_cache():
        # The fixture keeps one app context open, so g would otherwise carry
        # per-request caches (logged in user, branding) between requests.
        g.pop("_login_user", None)
        g.pop("branding", None)

    with app.app_context():
        result = app.test_cli_runner().invoke(args=["init-db"])
        assert result.exit_code == 0, result.output
        yield app
        db.session.remove()


@pytest.fixture
def internal_app(app, config):
    """Internal API app sharing the database with ``app``."""
    return create_app("internal", config)


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def logged_in(client):
    response = client.post("/login", data={"username": "admin", "password": "initial-password"})
    assert response.status_code == 302
    return client


@pytest.fixture
def make_admin(app):
    def _make(username, password="secret-password", active=True):
        admin = Admin(username=username, active=active)
        admin.set_password(password)
        db.session.add(admin)
        db.session.commit()
        return admin
    return _make


def make_api_key(read_only=False, allow_from=""):
    api_key, token = ApiKey.create("test", read_only=read_only, allow_from=allow_from)
    db.session.add(api_key)
    db.session.commit()
    return token


@pytest.fixture
def api(app):
    """Calls the REST API with a read/write key: api("GET", "/domains", json=...)."""
    token = make_api_key()
    client = app.test_client()

    def call(method, path, **kwargs):
        headers = kwargs.pop("headers", {})
        headers.setdefault("X-API-Key", token)
        return client.open(f"/api/v1{path}", method=method, headers=headers, **kwargs)
    return call
