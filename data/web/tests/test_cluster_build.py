"""Building a cluster in the web UI (like Proxmox): the membership, join
information, the join handshake, removing members, creating or joining on a
single gateway, and the joining side (system/libexec/cluster-setup)."""
import base64
import importlib.machinery
import importlib.util
import io
import json
import os
import socket
import ssl
import subprocess
import sys
import tarfile
import threading
import time
from datetime import timedelta
from pathlib import Path

import pytest

from crassostrea.extensions import db
from crassostrea.models import ClusterJoinToken, ClusterMembership, ClusterReport, hash_token, utcnow
from crassostrea.services import cluster
from crassostrea.services.errors import ServiceError

NODES = [("mx1.example.com", "10.0.0.1"), ("mx2.example.com", "10.0.0.2")]
HELPER = Path(__file__).resolve().parents[3] / "system" / "libexec" / "cluster-setup"


def _load_helper():
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader("cluster_setup_helper", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


helper = _load_helper()


def self_signed(tmp_path, name="mx1.example.com"):
    key, cert = tmp_path / "key.pem", tmp_path / "cert.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes",
                    "-days", "2", "-subj", f"/CN={name}", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    return cert, key


@pytest.fixture
def member(app, config, tmp_path):
    """mx1 of a two-node cluster with a certificate."""
    app.config.update(CLUSTER_NODES=NODES, CLUSTER_WITNESS=None, HOSTNAME="mx1.example.com", HTTPS_PORT=443)
    cert, _ = self_signed(tmp_path)
    app.config["SSL_CERT"] = str(cert)
    with open(config["CONF_FILE"], "w") as handle:
        handle.write("HA_NODES=mx1.example.com=10.0.0.1,mx2.example.com=10.0.0.2\nHA_WITNESS=\n")
    return app


def info_of(text):
    return cluster.decode_join_information(text)


# ---------------------------------------------------------------------------
# Membership
# ---------------------------------------------------------------------------

def test_membership_seeded_and_reconciled(member, tmp_path):
    assert cluster.membership() is None
    cluster.seed_membership()
    row = cluster.membership()
    assert row.nodes == "mx1.example.com=10.0.0.1,mx2.example.com=10.0.0.2" and row.witness == ""
    cluster._last_request.clear()
    assert cluster.reconcile({}) is None  # the configuration matches
    row.nodes += ",mx3.example.com=10.0.0.3"
    db.session.commit()
    assert cluster.nodes()[-1] == ("mx3.example.com", "10.0.0.3") and cluster.votes() == (3, 2)
    wanted = cluster.reconcile({})
    assert wanted == {"members": row.nodes, "witness": ""}
    assert (tmp_path / "cluster-request").read_text() == f"members={row.nodes}\nwitness=\n"


# ---------------------------------------------------------------------------
# Join information and the handshake
# ---------------------------------------------------------------------------

def test_join_information(member):
    info = cluster.join_information("admin")
    db.session.commit()
    assert info["information"].startswith("sfjoin1.") and info["expires_in"] == 3600
    decoded = info_of(info["information"])
    assert decoded["host"] == "mx1.example.com" and decoded["address"] == "10.0.0.1" and decoded["port"] == 443
    assert decoded["fingerprint"] == cluster.certificate_fingerprint() == info["fingerprint"]
    # line breaks from copying do not matter; only the hash of the secret is stored
    text = info["information"]
    assert info_of(text[:20] + "\n" + text[20:])["token"] == decoded["token"]
    assert db.session.get(ClusterJoinToken, hash_token(decoded["token"])).created_by == "admin"
    for broken in ("hello", "sfjoin1.!!!", "sfjoin1." + base64.urlsafe_b64encode(b'{"host": "x"}').decode()):
        with pytest.raises(ServiceError):
            info_of(broken)


def test_join_handshake(member, tmp_path):
    token = info_of(cluster.join_information("admin")["information"])["token"]
    db.session.commit()
    # first call: mx3 becomes a member, the member is asked for its bundle
    assert cluster.join(token, "MX3.example.com", "10.0.0.3") == (202, None)
    assert cluster.membership().nodes.endswith(",mx3.example.com=10.0.0.3")
    request = (tmp_path / "cluster-bundle").read_text()
    assert request == ("members=mx1.example.com=10.0.0.1,mx2.example.com=10.0.0.2,mx3.example.com=10.0.0.3\n"
                       "witness=\nhost=mx3.example.com\n")
    assert cluster.join(token, "mx3.example.com", "10.0.0.3") == (202, None)
    # the same information does not let another gateway in
    with pytest.raises(ServiceError, match="invalid, used or expired") as error:
        cluster.join(token, "mx4.example.com", "10.0.0.4")
    assert error.value.status == 403
    # cluster-node wrote the bundle: handed out once, then deleted
    (tmp_path / "mx3.example.com.tar").write_bytes(b"bundle")
    assert cluster.join(token, "mx3.example.com", "10.0.0.3") == (200, b"bundle")
    assert not (tmp_path / "mx3.example.com.tar").exists()
    with pytest.raises(ServiceError):
        cluster.join(token, "mx3.example.com", "10.0.0.3")


@pytest.mark.parametrize("hostname, address, status", [
    ("mx2.example.com", "10.0.0.9", 409),  # a member's name
    ("mx9.example.com", "10.0.0.2", 409),  # a member's address
    ("not a name", "10.0.0.9", 422),
    ("mx9.example.com", "127.0.0.1", 422),
])
def test_join_refusals(member, hostname, address, status):
    token = info_of(cluster.join_information("admin")["information"])["token"]
    db.session.commit()
    with pytest.raises(ServiceError) as error:
        cluster.join(token, hostname, address)
    assert error.value.status == status
    assert "mx9" not in (cluster.membership().nodes if cluster.membership() else "")


def test_expired_join_information(member):
    token = info_of(cluster.join_information("admin")["information"])["token"]
    db.session.get(ClusterJoinToken, hash_token(token)).expires_at = utcnow() - timedelta(seconds=1)
    db.session.commit()
    with pytest.raises(ServiceError, match="expired"):
        cluster.join(token, "mx3.example.com", "10.0.0.3")


def test_bundle_request_written_again(member, tmp_path):
    token = info_of(cluster.join_information("admin")["information"])["token"]
    db.session.commit()
    cluster.join(token, "mx3.example.com", "10.0.0.3")
    os.remove(tmp_path / "cluster-bundle")  # cluster-node took it, but wrote no bundle
    row = db.session.get(ClusterJoinToken, hash_token(token))
    row.used_at = utcnow() - timedelta(minutes=5)
    db.session.commit()
    assert cluster.join(token, "mx3.example.com", "10.0.0.3") == (202, None)
    assert (tmp_path / "cluster-bundle").exists()


def test_join_endpoint(member, client, tmp_path):
    token = info_of(cluster.join_information("admin")["information"])["token"]
    db.session.commit()
    body = {"token": token, "hostname": "mx3.example.com", "address": "10.0.0.3"}
    assert client.post("/cluster/join", json={**body, "token": "x" * 40}).status_code == 403
    response = client.post("/cluster/join", json=body)  # no login, no CSRF token
    assert response.status_code == 202 and response.get_json() == {"state": "preparing"}
    (tmp_path / "mx3.example.com.tar").write_bytes(b"bundle")
    response = client.post("/cluster/join", json=body)
    assert response.status_code == 200 and base64.b64decode(response.get_json()["bundle"]) == b"bundle"
    from crassostrea.models import AuditEntry
    actions = [(e.action, e.outcome) for e in AuditEntry.query.order_by(AuditEntry.id)]
    assert actions == [("cluster.join", "failed"), ("cluster.join", "ok")]  # the polls are not recorded


def test_join_endpoint_on_a_single_gateway(client):
    assert client.post("/cluster/join", json={}).status_code == 409


# ---------------------------------------------------------------------------
# Removing members
# ---------------------------------------------------------------------------

def report(name, age):
    db.session.merge(ClusterReport(hostname=name, updated_at=utcnow() - timedelta(seconds=age), data="{}"))
    db.session.commit()


def test_remove_node(member):
    cluster.seed_membership()
    report("mx2.example.com", 5)
    with pytest.raises(ServiceError, match="is running"):
        cluster.remove_node("mx2.example.com", "admin")
    with pytest.raises(ServiceError, match="cannot remove itself"):
        cluster.remove_node("mx1.example.com", "admin")
    report("mx2.example.com", 600)
    assert cluster.remove_node("mx2.example.com", "admin") == [("mx1.example.com", "10.0.0.1")]
    db.session.commit()
    assert cluster.membership().nodes == "mx1.example.com=10.0.0.1" and cluster.membership().changed_by == "admin"
    assert db.session.get(ClusterReport, "mx2.example.com") is None


def test_remove_witness(member):
    db.session.add(ClusterMembership(id=1, nodes="mx1.example.com=10.0.0.1,mx2.example.com=10.0.0.2",
                                     witness="w.example.com=10.0.0.9"))
    db.session.commit()
    assert cluster.witness() == ("w.example.com", "10.0.0.9")
    cluster.remove_witness("admin")
    db.session.commit()
    assert cluster.witness() is None
    with pytest.raises(ServiceError, match="no witness"):
        cluster.remove_witness("admin")


def test_cluster_page_building(member, logged_in):
    page = logged_in.get("/cluster/manage").get_data(as_text=True)
    assert "Add a node" in page and ">Join information</button>" in page
    page = logged_in.post("/cluster/join-information", follow_redirects=True).get_data(as_text=True)
    assert "sfjoin1." in page and "SHA-256" in page
    # shown once
    assert "sfjoin1." not in logged_in.get("/cluster/manage").get_data(as_text=True)
    report("mx2.example.com", 600)
    page = logged_in.get("/cluster/manage").get_data(as_text=True)
    assert 'action="/cluster/mx2.example.com/remove"' in page and "2 votes" in page
    logged_in.post("/cluster/mx2.example.com/remove")
    assert cluster.membership().nodes == "mx1.example.com=10.0.0.1"


def test_cluster_api_building(member, api):
    response = api("POST", "/cluster/join-information")
    assert response.status_code == 201 and response.get_json()["information"].startswith("sfjoin1.")
    report("mx2.example.com", 600)
    assert api("DELETE", "/cluster/nodes/mx1.example.com").status_code == 409
    response = api("DELETE", "/cluster/nodes/mx2.example.com")
    assert response.status_code == 200 and response.get_json()["nodes"] == ["mx1.example.com"]
    assert api("DELETE", "/cluster/witness").status_code == 404
    assert api("POST", "/cluster/create", json={"address": "10.0.0.1"}).status_code == 409  # a member


# ---------------------------------------------------------------------------
# A single gateway creating or joining
# ---------------------------------------------------------------------------

@pytest.fixture
def single(app, monkeypatch):
    monkeypatch.setattr(cluster, "local_addresses", lambda: ["192.0.2.10", "10.0.0.3"])
    app.config["HOSTNAME"] = "mx3.example.com"
    return app


def test_request_create(single, tmp_path):
    with pytest.raises(ServiceError, match="not an address of this server"):
        cluster.request_create("10.9.9.9")
    with pytest.raises(ServiceError, match="prefix length"):
        cluster.request_create("10.0.0.3", "192.0.2.50")
    assert cluster.request_create("10.0.0.3", "192.0.2.50/24") == {"address": "10.0.0.3", "vip": "192.0.2.50/24"}
    assert json.loads((tmp_path / "cluster-setup.json").read_text()) == {
        "action": "create", "address": "10.0.0.3", "vip": "192.0.2.50/24"}
    with pytest.raises(ServiceError, match="already running"):
        cluster.request_create("10.0.0.3")


def test_request_join(single, member_info, tmp_path):
    with pytest.raises(ServiceError, match="no join information"):
        cluster.request_join("hello", "10.0.0.3")
    assert cluster.request_join(member_info, "10.0.0.3") == {"host": "mx1.example.com", "address": "10.0.0.3"}
    request = json.loads((tmp_path / "cluster-setup.json").read_text())
    assert request["action"] == "join" and request["address"] == "10.0.0.3"
    assert request["member_address"] == "10.0.0.1" and len(request["fingerprint"]) == 64


@pytest.fixture
def member_info():
    raw = {"host": "mx1.example.com", "address": "10.0.0.1", "port": 443, "fingerprint": "a" * 64,
           "token": "t" * 43}
    return "sfjoin1." + base64.urlsafe_b64encode(json.dumps(raw).encode()).decode().rstrip("=")


def test_setup_page_and_status(single, logged_in, tmp_path):
    response = logged_in.post("/cluster/setup/create", data={"address": "10.0.0.3"}, follow_redirects=True)
    assert "Creating the cluster" in response.get_data(as_text=True)
    os.remove(tmp_path / "cluster-setup.json")
    (tmp_path / "cluster-setup-status.json").write_text(json.dumps({
        "action": "join", "state": "failed", "message": "Nothing was changed: mx1 refused", "at": 1, "log": "x"}))
    page = logged_in.get("/cluster/manage", headers={"X-Live-Fragment": "1"}).get_data(as_text=True)
    assert "Joining the cluster" in page and "mx1 refused" in page and ">failed</span>" in page


# ---------------------------------------------------------------------------
# The joining side: system/libexec/cluster-setup
# ---------------------------------------------------------------------------

def bundle_with(nodes):
    data = io.BytesIO()
    with tarfile.open(fileobj=data, mode="w") as tar:
        conf = f"CRASSOSTREA_HOSTNAME=mx3.example.com\nHA_NODES={nodes}\n".encode()
        entry = tarfile.TarInfo("crassostrea.conf")
        entry.size = len(conf)
        tar.addfile(entry, io.BytesIO(conf))
    return data.getvalue()


def test_fetch_bundle_polls(monkeypatch):
    monkeypatch.setattr(helper, "status_set", lambda *a: None)
    answers = [(202, {"state": "preparing"}), (202, {}), (200, {"bundle": base64.b64encode(b"tar").decode()})]
    calls = []

    def post(info, hostname, address):
        calls.append((hostname, address))
        return answers.pop(0)
    info = {"host": "mx1.example.com", "address": "10.0.0.1", "port": 443}
    assert helper.fetch_bundle(info, "mx3.example.com", "10.0.0.3", post=post, sleep=lambda s: None) == b"tar"
    assert calls == [("mx3.example.com", "10.0.0.3")] * 3
    with pytest.raises(helper.Refused, match="refused: The join information is invalid"):
        helper.fetch_bundle(info, "mx3.example.com", "10.0.0.3", sleep=lambda s: None,
                            post=lambda *a: (403, {"error": "The join information is invalid, used or expired"}))


def test_bundle_members():
    assert helper.bundle_members(bundle_with("mx1.example.com=10.0.0.1,mx3.example.com=10.0.0.3")) == [
        ("mx1.example.com", "10.0.0.1"), ("mx3.example.com", "10.0.0.3")]
    with pytest.raises(helper.Refused):
        data = io.BytesIO()
        with tarfile.open(fileobj=data, mode="w") as tar:
            entry = tarfile.TarInfo("../etc/passwd")
            tar.addfile(entry, io.BytesIO(b""))
        helper.bundle_members(data.getvalue())


def test_validate_join():
    request = {"host": "MX1.example.com", "port": 443, "fingerprint": "a" * 64, "token": "t" * 43,
               "member_address": "10.0.0.1"}
    assert helper.validate_join(request)["host"] == "mx1.example.com"
    for broken in ({"port": "443"}, {"fingerprint": "zz"}, {"token": "a b"}, {"member_address": "127.0.0.1"}):
        with pytest.raises(helper.Refused):
            helper.validate_join({**request, **broken})


@pytest.fixture
def tls_member(tmp_path):
    """An HTTPS server like a member's nginx: answers POST /cluster/join."""
    cert, key = self_signed(tmp_path)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(cert, key)
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen()
    seen = []

    def serve():
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            try:
                with context.wrap_socket(conn, server_side=True) as tls:
                    seen.append(tls.server_hostname if hasattr(tls, "server_hostname") else None)
                    request = b""
                    while b"\r\n\r\n" not in request:
                        request += tls.recv(65536)
                    head, _, body = request.partition(b"\r\n\r\n")
                    length = int(next(line.split(b":")[1] for line in head.split(b"\r\n")
                                      if line.lower().startswith(b"content-length")))
                    while len(body) < length:
                        body += tls.recv(65536)
                    seen.append((head + b"\r\n\r\n" + body).decode())
                    body = json.dumps({"state": "preparing"}).encode()
                    tls.sendall(b"HTTP/1.1 202 Accepted\r\nContent-Type: application/json\r\nContent-Length: "
                                + str(len(body)).encode() + b"\r\nConnection: close\r\n\r\n" + body)
            except (OSError, ssl.SSLError):
                pass

    threading.Thread(target=serve, daemon=True).start()
    from cryptography import x509
    from cryptography.hazmat.primitives.serialization import Encoding
    import hashlib
    der = x509.load_pem_x509_certificate(cert.read_bytes()).public_bytes(Encoding.DER)
    yield server.getsockname()[1], hashlib.sha256(der).hexdigest(), seen
    server.close()


def test_pinned_connection(tls_member):
    port, fingerprint, seen = tls_member
    info = {"host": "mx1.example.com", "address": "127.0.0.1", "port": port, "fingerprint": fingerprint,
            "token": "t" * 43}
    status, data = helper.post_join(info, "mx3.example.com", "10.0.0.3")
    assert status == 202 and data == {"state": "preparing"}
    request = seen[-1]
    assert request.startswith("POST /cluster/join HTTP/1.1") and f"Host: mx1.example.com:{port}" in request
    assert json.loads(request.split("\r\n\r\n", 1)[1]) == {"token": "t" * 43, "hostname": "mx3.example.com",
                                                          "address": "10.0.0.3"}
    # another certificate: refused before anything is sent
    count = len(seen)
    with pytest.raises(helper.Refused, match="does not match the join information"):
        helper.post_join({**info, "fingerprint": "b" * 64}, "mx3.example.com", "10.0.0.3")
    time.sleep(0.2)
    assert not any("POST" in str(s) for s in seen[count:])
