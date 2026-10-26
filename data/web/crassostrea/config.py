import os
from urllib.parse import quote_plus


def _bool(name, default):
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in ("1", "y", "yes", "true", "on")


def _list(name, default):
    return [item.strip() for item in os.environ.get(name, default).split(",") if item.strip()]


def _database_uri():
    if os.environ.get("DATABASE_URL"):
        return os.environ["DATABASE_URL"]
    user = quote_plus(os.environ.get("DBUSER", "crassostrea"))
    password = quote_plus(os.environ.get("DBPASS", ""))
    host = os.environ.get("DBHOST", "127.0.0.1")
    name = os.environ.get("DBNAME", "crassostrea")
    return f"mysql+pymysql://{user}:{password}@{host}:3306/{name}?charset=utf8mb4"


def _members(name):
    """(hostname, address) pairs of a cluster setting (name=address,...)."""
    entries = os.environ.get(name, "").split(",")
    return [tuple(part.strip().lower() for part in e.split("=", 1)) for e in entries if "=" in e]


def _public_url():
    if os.environ.get("WEB_PUBLIC_URL"):
        return os.environ["WEB_PUBLIC_URL"].rstrip("/")
    host = os.environ.get("CRASSOSTREA_HOSTNAME", "localhost")
    port = os.environ.get("HTTPS_PORT", "443")
    return f"https://{host}" if port == "443" else f"https://{host}:{port}"


class Config:
    SECRET_KEY = os.environ.get("WEB_SECRET_KEY") or os.environ.get("SECRET_KEY")

    SQLALCHEMY_DATABASE_URI = _database_uri()
    SQLALCHEMY_ENGINE_OPTIONS = {"pool_pre_ping": True, "pool_recycle": 1800}

    REDIS_HOST = os.environ.get("REDIS_HOST", "127.0.0.1")
    REDIS_PORT = int(os.environ.get("REDIS_PORT_INTERNAL", "6379"))
    REDIS_PASSWORD = os.environ.get("REDISPASS") or None

    RSPAMD_URL = os.environ.get("RSPAMD_URL", "http://127.0.0.1:11334")
    RSPAMD_PASSWORD = os.environ.get("RSPAMD_PASSWORD", "")

    # Postfix listener without milters, used to re-inject released mail
    REINJECT_HOST = os.environ.get("REINJECT_HOST", "127.0.0.1")
    REINJECT_PORT = int(os.environ.get("REINJECT_PORT", "590"))

    # Hosts besides loopback allowed to use the internal API (settings map,
    # quarantine ingestion), e.g. an rspamd on another machine
    INTERNAL_CLIENTS = _list("INTERNAL_CLIENTS", "")

    # Mail queue actions (system/libexec/postfix-control, socket-activated)
    POSTFIX_CONTROL_SOCKET = os.environ.get("POSTFIX_CONTROL_SOCKET", "/run/crassostrea/postfix-control.sock")
    # Journal of the services for the Logs page (system/libexec/log-reader)
    LOG_READER_SOCKET = os.environ.get("LOG_READER_SOCKET", "/run/crassostrea/logs.sock")
    # systemd units listed on the dashboard (set by system/configure.sh)
    SERVICE_UNITS = _list("CRASSOSTREA_UNITS", "mariadb.service,valkey.service,unbound.service,rspamd.service,"
                          "postfix.service,nginx.service,crassostrea-web.service,crassostrea-web-internal.service")

    # Directories shared with rspamd / postfix (written by the web UI)
    RSPAMD_MAP_DIR = os.environ.get("RSPAMD_MAP_DIR", "/etc/rspamd/custom")
    POSTFIX_DYNAMIC_DIR = os.environ.get("POSTFIX_DYNAMIC_DIR", "/var/lib/crassostrea/postfix")

    HOSTNAME = os.environ.get("CRASSOSTREA_HOSTNAME", "localhost")
    # A hostname change requested in the UI, applied by system/libexec/set-hostname
    HOSTNAME_REQUEST = os.environ.get("HOSTNAME_REQUEST", "/var/lib/crassostrea/web/hostname")
    # The time zone of Settings, applied by system/libexec/set-timezone
    TIMEZONE_REQUEST = os.environ.get("TIMEZONE_REQUEST", "/var/lib/crassostrea/web/timezone")
    TIMEZONE_STATUS = os.environ.get("TIMEZONE_STATUS", "/var/lib/crassostrea/timezone/status.json")
    LOCALTIME = os.environ.get("LOCALTIME", "/etc/localtime")
    # Certificates & TLS: settings read from crassostrea.conf, requests applied
    # by system/libexec/tls-apply, which records their outcome in TLS_STATUS
    CONF_FILE = os.environ.get("SF_CONF", "/etc/crassostrea/crassostrea.conf")
    TLS_REQUEST = os.environ.get("TLS_REQUEST", "/var/lib/crassostrea/web/tls-request.json")
    TLS_UPLOAD_DIR = os.environ.get("TLS_UPLOAD_DIR", "/var/lib/crassostrea/web/tls-upload")
    TLS_STATUS = os.environ.get("TLS_STATUS", "/var/lib/crassostrea/tls/status.json")
    SSL_CERT = os.environ.get("SSL_CERT", "/etc/crassostrea/ssl/cert.pem")
    CA_BUNDLE = os.environ.get("CA_BUNDLE", "/etc/pki/tls/certs/ca-bundle.crt")
    # Backups: made, deleted and listed by system/libexec/backup
    BACKUP_DIR = os.environ.get("BACKUP_DIR", "/var/lib/crassostrea/backups")
    BACKUP_REQUEST = os.environ.get("BACKUP_REQUEST", "/var/lib/crassostrea/web/backup-request.json")
    # IP addressing: requests applied and tested by system/libexec/network-apply
    IP_REQUEST = os.environ.get("IP_REQUEST", "/var/lib/crassostrea/web/ip-request.json")
    IP_STATUS = os.environ.get("IP_STATUS", "/var/lib/crassostrea/network/status.json")
    # High availability: (hostname, address) of the cluster's full nodes,
    # empty for a single gateway, and of the vote-only witness
    CLUSTER_NODES = _members("HA_NODES")
    CLUSTER_WITNESS = (_members("HA_WITNESS") or [None])[0]
    # Floating address of the web UI (HA_VIP is address/prefix)
    CLUSTER_VIP = os.environ.get("HA_VIP", "").split("/")[0].strip() or None
    # Cluster page: requests to system/libexec/cluster-node (maintenance,
    # Valkey master) and what it finds on this node; the deployed version
    CLUSTER_REQUEST = os.environ.get("CLUSTER_REQUEST", "/var/lib/crassostrea/web/cluster-request")
    CLUSTER_PROBE = os.environ.get("CLUSTER_PROBE", "/var/lib/crassostrea/cluster/probe.json")
    # Joining: the member writes a node's join bundle on request (cluster-node)
    CLUSTER_BUNDLE_REQUEST = os.environ.get("CLUSTER_BUNDLE_REQUEST", "/var/lib/crassostrea/web/cluster-bundle")
    CLUSTER_BUNDLE_DIR = os.environ.get("CLUSTER_BUNDLE_DIR", "/var/lib/crassostrea/cluster-bundles")
    # A single gateway creating or joining a cluster (system/libexec/cluster-setup)
    CLUSTER_SETUP_REQUEST = os.environ.get("CLUSTER_SETUP_REQUEST", "/var/lib/crassostrea/web/cluster-setup.json")
    CLUSTER_SETUP_STATUS = os.environ.get("CLUSTER_SETUP_STATUS", "/var/lib/crassostrea/cluster-setup/status.json")
    VERSION_FILE = os.environ.get("SF_VERSION_FILE", "/usr/local/lib/crassostrea/version")
    # Release notes of a deployed release: <PROJECT_URL>/releases/tag/<version>
    PROJECT_URL = os.environ.get("PROJECT_URL", "https://github.com/SnailShea/crassostrea").rstrip("/")
    # The documentation at /docs/, served by nginx to administrators
    # (system/lib/docs.sh; auth.docs_access answers its auth_request)
    DOCS_ENABLED = _bool("DOCS_ENABLED", False)

    # Ports and certificates, for the checks on the "DNS & ports" page
    HTTP_PORT = int(os.environ.get("HTTP_PORT") or "80")
    HTTPS_PORT = int(os.environ.get("HTTPS_PORT") or "443")
    HTTP_BIND = os.environ.get("HTTP_BIND", "").strip()
    HTTPS_BIND = os.environ.get("HTTPS_BIND", "").strip()
    LETS_ENCRYPT = not _bool("SKIP_LETS_ENCRYPT", False)
    ACME_DNS_CHALLENGE = _bool("ACME_DNS_CHALLENGE", False)
    # Base URL used in links of quarantine digest mails
    PUBLIC_URL = _public_url()
    LOG_LINES = int(os.environ.get("LOG_LINES", "9999"))
    INITIAL_ADMIN_PASSWORD = os.environ.get("WEB_ADMIN_PASSWORD", "")

    # WEB_SECURE_COOKIES is the name in crassostrea.conf
    SESSION_COOKIE_SECURE = _bool("SESSION_COOKIE_SECURE", _bool("WEB_SECURE_COOKIES", True))
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = "Lax"
    SESSION_COOKIE_NAME = "crassostrea_session"
    # Seconds after which a login ends however active it is (auth.expire_login)
    PERMANENT_SESSION_LIFETIME = int(os.environ.get("WEB_SESSION_LIFETIME", "28800"))
    WTF_CSRF_TIME_LIMIT = None

    # Uploads (training) and quarantine ingestion
    MAX_CONTENT_LENGTH = 64 * 1024 * 1024
    # Internal API: messages from Rspamd's metadata_exporter, up to the
    # largest message size the settings allow (models.MAX_MESSAGE_MB)
    INTERNAL_MAX_CONTENT_LENGTH = 160 * 1024 * 1024

    # Login throttling (per client IP, and per account across all IPs)
    LOGIN_MAX_FAILURES = int(os.environ.get("WEB_LOGIN_MAX_FAILURES", "10"))
    LOGIN_MAX_ACCOUNT_FAILURES = int(os.environ.get("WEB_LOGIN_MAX_ACCOUNT_FAILURES", "30"))
    LOGIN_FAILURE_WINDOW = int(os.environ.get("WEB_LOGIN_FAILURE_WINDOW", "900"))
