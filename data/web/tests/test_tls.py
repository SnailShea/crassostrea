"""Certificates & TLS page: checks of uploaded files, requests to tls-apply, the page and the API."""
import datetime
import hashlib
import io
import json
import os
import time

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from crassostrea.services import certificates
from crassostrea.services.errors import ServiceError

HOST = "mx.example.com"
NOW = datetime.datetime.now(datetime.timezone.utc)
DAY = datetime.timedelta(days=1)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _cert(subject, key, issuer=None, issuer_key=None, ca=False, names=(), start=None, end=None):
    """A certificate with the extensions path validation requires."""
    issuer, issuer_key = issuer or subject, issuer_key or key
    builder = (x509.CertificateBuilder().subject_name(_name(subject)).issuer_name(_name(issuer))
               .public_key(key.public_key()).serial_number(x509.random_serial_number())
               .not_valid_before(start or NOW - DAY).not_valid_after(end or NOW + 90 * DAY)
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
               .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
               .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                              critical=False))
    if ca:
        builder = builder.add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False, data_encipherment=False,
            key_agreement=False, key_cert_sign=True, crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
    else:
        builder = (builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in names]),
                                         critical=False)
                   .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False))
    return builder.sign(issuer_key, hashes.SHA256())


def _pem(*items):
    out = b""
    for item in items:
        if isinstance(item, x509.Certificate):
            out += item.public_bytes(serialization.Encoding.PEM)
        else:
            out += item.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption())
    return out


@pytest.fixture(scope="module")
def pki():
    root_key, inter_key, leaf_key = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _cert("Test Root", root_key, ca=True)
    inter = _cert("Test Intermediate", inter_key, "Test Root", root_key, ca=True)
    leaf = _cert(HOST, leaf_key, "Test Intermediate", inter_key, names=[HOST, "mail.example.com"])
    return {"root": root, "inter": inter, "inter_key": inter_key, "leaf": leaf, "leaf_key": leaf_key}


@pytest.fixture
def gateway(app, config, pki):
    """A single gateway with Let's Encrypt; the test root is the trusted CA."""
    def conf(**values):
        values = {"CRASSOSTREA_HOSTNAME": HOST, "SKIP_LETS_ENCRYPT": "n", "ADDITIONAL_SAN": "mail.example.com",
                  "HTTPS_TLS_MIN": "1.2", "SMTP_TLS_MIN": "1.2", "HA_NODES": "", **values}
        with open(config["CONF_FILE"], "w") as handle:
            handle.write("".join(f"{k}={v}\n" for k, v in values.items()))
    conf()
    with open(config["CA_BUNDLE"], "wb") as handle:
        handle.write(_pem(pki["root"]))
    with open(config["SSL_CERT"], "wb") as handle:
        handle.write(_pem(pki["leaf"], pki["inter"]))
    app.config.update(HOSTNAME=HOST, CLUSTER_NODES=[])
    app.conf = conf
    return app


def _status(app, **sections):
    with open(app.config["TLS_STATUS"], "w") as handle:
        json.dump(sections, handle)


def _request(app):
    with open(app.config["TLS_REQUEST"]) as handle:
        return json.load(handle)


# ---------------------------------------------------------------------------
# Settings and the installed certificate
# ---------------------------------------------------------------------------

def test_settings_come_from_crassostrea_conf(gateway):
    s = certificates.settings()
    assert (s["hostname"], s["mode"], s["extra_names"], s["cluster"]) == (HOST, "letsencrypt", ["mail.example.com"],
                                                                          False)
    gateway.conf(SKIP_LETS_ENCRYPT="y", HTTPS_TLS_MIN="1.0", SMTP_TLS_MIN="bogus", HA_NODES="a=10.0.0.1")
    s = certificates.settings()
    assert (s["mode"], s["https_min"], s["smtp_min"], s["cluster"]) == ("manual", "1.0", "1.2", True)


def test_current_certificate(gateway):
    info = certificates.current_certificate()
    assert info["names"] == [HOST, "mail.example.com"] and info["issuer"] == "Test Intermediate"
    assert info["chain_length"] == 2 and 88 <= info["days_left"] <= 90 and info["key"] == "ECDSA secp256r1"


# ---------------------------------------------------------------------------
# Uploaded files
# ---------------------------------------------------------------------------

def test_valid_chain(gateway, pki):
    report = certificates.validate(_pem(pki["leaf"], pki["inter"]), _pem(pki["leaf_key"]))
    assert report["errors"] == [] and report["warnings"] == []
    # the chain may also come as a separate file
    report = certificates.validate(_pem(pki["leaf"]), _pem(pki["leaf_key"]), _pem(pki["inter"]))
    assert report["errors"] == [] and report["warnings"] == [] and report["info"]["chain_length"] == 2
    sha256 = certificates.stage(report)
    # as tls-apply computes it: cat cert.pem key.pem | sha256sum
    directory = gateway.config["TLS_UPLOAD_DIR"]
    with open(f"{directory}/cert.pem", "rb") as cert, open(f"{directory}/key.pem", "rb") as key:
        assert hashlib.sha256(cert.read() + key.read()).hexdigest() == sha256 == certificates.staged_sha256()
    assert oct(os.stat(f"{directory}/key.pem").st_mode & 0o777) == "0o600"


def test_errors(gateway, pki):
    def errors(cert, key, chain=b""):
        return certificates.validate(cert, key, chain)["errors"]

    leaf, inter, key = pki["leaf"], pki["inter"], pki["leaf_key"]
    other = ec.generate_private_key(ec.SECP256R1())
    assert errors(b"", _pem(key)) == ["Upload the certificate and its private key."]
    assert "not in PEM format" in errors(b"garbage", _pem(key))[0]
    assert "not in PEM format" in errors(_pem(leaf), b"garbage")[0]
    assert "does not belong" in errors(_pem(leaf), _pem(other))[0]
    encrypted = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                  serialization.BestAvailableEncryption(b"secret"))
    assert "encrypted" in errors(_pem(leaf), encrypted)[0]
    expired = _cert(HOST, key, "Test Intermediate", pki["inter_key"], names=[HOST], start=NOW - 10 * DAY,
                    end=NOW - DAY)
    assert "expired" in errors(_pem(expired, inter), _pem(key))[0]
    future = _cert(HOST, key, "Test Intermediate", pki["inter_key"], names=[HOST], start=NOW + DAY)
    assert "not valid before" in errors(_pem(future, inter), _pem(key))[0]
    weak_key = rsa.generate_private_key(65537, 1024)
    weak = _cert(HOST, weak_key, names=[HOST])
    assert "1024 bits" in errors(_pem(weak), _pem(weak_key))[0]
    # the issuer must follow the certificate it issued
    assert "out of order" in errors(_pem(inter, leaf), _pem(key))[0]


def test_warnings(gateway, pki):
    key = pki["leaf_key"]
    other_name = _cert("www.example.org", key, "Test Intermediate", pki["inter_key"], names=["www.example.org"])
    report = certificates.validate(_pem(other_name, pki["inter"]), _pem(key))
    assert report["errors"] == [] and len(report["warnings"]) == 1 and f"does not name {HOST}" in report["warnings"][0]
    self_signed = _cert(HOST, key, names=[HOST])
    report = certificates.validate(_pem(self_signed), _pem(key))
    assert report["errors"] == [] and "do not trust it" in report["warnings"][0]
    missing_intermediate = certificates.validate(_pem(pki["leaf"]), _pem(key))
    assert "do not trust it" in missing_intermediate["warnings"][0]
    soon = _cert(HOST, key, "Test Intermediate", pki["inter_key"], names=[HOST], end=NOW + 5 * DAY)
    report = certificates.validate(_pem(soon, pki["inter"]), _pem(key))
    assert report["warnings"] == ["The certificate expires in 4 days."]
    # a wildcard covers the hostname
    wildcard = _cert("*.example.com", key, "Test Intermediate", pki["inter_key"], names=["*.example.com"])
    assert certificates.validate(_pem(wildcard, pki["inter"]), _pem(key))["warnings"] == []


# ---------------------------------------------------------------------------
# Requests
# ---------------------------------------------------------------------------

def test_certificate_names(gateway):
    assert certificates.certificate_names("mail.example.com\n Webmail.Example.com, mx.example.com\n\n") == [
        HOST, "mail.example.com", "webmail.example.com"]
    for bad in ("bad_name.example.com", "localhost", "a..b.example.com", "*.example.com"):
        with pytest.raises(ServiceError):
            certificates.certificate_names(bad)
    gateway.conf(ACME_DNS_CHALLENGE="y")
    assert certificates.certificate_names(["*.example.com"]) == [HOST, "*.example.com"]
    with pytest.raises(ServiceError, match="At most 50"):
        certificates.certificate_names([f"n{i}.example.com" for i in range(50)])


def test_staging_test_then_apply(gateway):
    with pytest.raises(ServiceError, match="staging test") as error:
        certificates.request_letsencrypt(["mail.example.com"])
    assert error.value.status == 409
    assert certificates.request_staging_test("mail.example.com") == [HOST, "mail.example.com"]
    assert _request(gateway) == {"action": "le-test", "names": [HOST, "mail.example.com"]}
    # one change at a time
    with pytest.raises(ServiceError, match="still being applied"):
        certificates.request_versions("1.0", "1.2")
    os.remove(gateway.config["TLS_REQUEST"])  # tls-apply consumed it
    _status(gateway, le_test={"state": "running", "at": int(time.time()), "names": [HOST, "mail.example.com"]})
    assert certificates.busy()
    _status(gateway, le_test={"state": "ok", "at": int(time.time()), "names": ["mail.example.com", HOST]})
    with pytest.raises(ServiceError, match="staging test"):
        certificates.request_letsencrypt(["mail.example.com", "other.example.com"])  # other names
    certificates.request_letsencrypt(["mail.example.com"])
    assert _request(gateway) == {"action": "le-apply", "names": [HOST, "mail.example.com"]}
    os.remove(gateway.config["TLS_REQUEST"])
    _status(gateway, le_test={"state": "ok", "at": int(time.time()) - 25 * 3600, "names": [HOST, "mail.example.com"]})
    with pytest.raises(ServiceError, match="24 hours"):
        certificates.request_letsencrypt(["mail.example.com"])


def test_stale_requests_do_not_block(gateway):
    _status(gateway, versions={"state": "running", "at": int(time.time()) - 3600})
    assert certificates.status()["versions"]["state"] == "stale" and not certificates.busy()


def test_manual_apply_needs_the_checked_files(gateway, pki):
    sha256 = certificates.stage(certificates.validate(_pem(pki["leaf"], pki["inter"]), _pem(pki["leaf_key"])))
    with pytest.raises(ServiceError, match="no longer the checked ones"):
        certificates.request_manual("0" * 64)
    certificates.request_manual(sha256)
    assert _request(gateway) == {"action": "manual-apply", "sha256": sha256}


def test_cluster_members_cannot_request(gateway):
    gateway.conf(HA_NODES="mx.example.com=10.0.0.1,mx2.example.com=10.0.0.2")
    with pytest.raises(ServiceError, match="cluster member") as error:
        certificates.request_versions("1.0", "1.0")
    assert error.value.status == 409 and not os.path.exists(gateway.config["TLS_REQUEST"])


# ---------------------------------------------------------------------------
# Page
# ---------------------------------------------------------------------------

def test_page(logged_in, gateway):
    _status(gateway, le_test={"state": "ok", "message": "Let's Encrypt (staging) validated every name",
                              "at": int(time.time()), "names": [HOST, "mail.example.com"], "log": "Cert success."},
            versions={"state": "failed", "message": "Applying the TLS versions failed", "at": int(time.time()) - 60})
    page = logged_in.get("/tls/").get_data(as_text=True)
    assert "Installed certificate" in page and "mx.example.com, mail.example.com" in page and "Test Intermediate" in page
    assert "Passed " in page and 'name="names" value="mail.example.com"' in page
    assert "Applying the TLS versions failed" in page and "Cert success." in page
    assert 'href="/tls/" class="active"' in page
    fragment = logged_in.get("/tls/", headers={"X-Live-Fragment": "1"}).get_data(as_text=True)
    assert "Applying the TLS versions failed" in fragment and "<html" not in fragment
    response = logged_in.post("/tls/letsencrypt/apply", data={"names": [HOST, "mail.example.com"]})
    assert response.status_code == 302 and _request(gateway)["action"] == "le-apply"


def _apply_button(html):
    """The Apply button of the staging test step."""
    form = html[html.index('id="staging-test"'):]
    return form[form.index("<button"):form.index("</button>")]


def test_tested_names_stay_in_the_form(logged_in, gateway):
    """Regression: the names under test were replaced by the configured ones."""
    gateway.conf(SKIP_LETS_ENCRYPT="y", ADDITIONAL_SAN="")  # an uploaded certificate is in use
    response = logged_in.post("/tls/letsencrypt/test", data={"names": "new.example.com"})
    # back on the Let's Encrypt tab, where the test shows
    assert response.status_code == 302 and "mode=letsencrypt" in response.headers["Location"]
    os.remove(gateway.config["TLS_REQUEST"])  # tls-apply consumed it
    for state in ("running", "ok", "failed"):
        _status(gateway, le_test={"state": state, "at": int(time.time()), "names": [HOST, "new.example.com"]})
        page = logged_in.get("/tls/?mode=letsencrypt").get_data(as_text=True)
        assert ">new.example.com</textarea>" in page, state
    # once applied, crassostrea.conf has them
    gateway.conf(ADDITIONAL_SAN="new.example.com,other.example.com")
    _status(gateway, le_test={"state": "ok", "at": int(time.time()) - 60, "names": [HOST, "new.example.com"]},
            le_apply={"state": "ok", "at": int(time.time()), "names": [HOST, "new.example.com"]})
    page = logged_in.get("/tls/?mode=letsencrypt").get_data(as_text=True)
    assert ">new.example.com\nother.example.com</textarea>" in page


def test_apply_follows_the_staging_test(logged_in, gateway):
    """Apply is enabled once the staging test passed. The step is in the live
    region, which in-page submissions update; the page does not refresh
    itself."""
    live = {"X-Live-Fragment": "1"}
    _status(gateway, le_test={"state": "running", "at": int(time.time()), "names": [HOST, "mail.example.com"]})
    page = logged_in.get("/tls/?mode=letsencrypt").get_data(as_text=True)
    assert "data-live-refresh" not in page and page.index('id="staging-test"') > page.index('data-live>')
    assert "disabled" in _apply_button(page)
    # the other forms stay usable while a change runs (the server refuses a second one)
    test_button = page[page.index("Test with staging") - 80:page.index("Test with staging")]
    assert "disabled" not in test_button
    fragment = logged_in.get("/tls/?mode=letsencrypt", headers=live).get_data(as_text=True)
    assert "testing…" in fragment and "disabled" in _apply_button(fragment)
    # the test finished: the next request brings the enabled button
    _status(gateway, le_test={"state": "ok", "at": int(time.time()), "names": [HOST, "mail.example.com"]})
    fragment = logged_in.get("/tls/?mode=letsencrypt", headers=live).get_data(as_text=True)
    assert "disabled" not in _apply_button(fragment) and 'name="names" value="mail.example.com"' in fragment
    _status(gateway, le_test={"state": "failed", "message": "Validation failed, see the log", "log": "DNS problem",
                              "at": int(time.time()), "names": [HOST, "mail.example.com"]})
    fragment = logged_in.get("/tls/?mode=letsencrypt", headers=live).get_data(as_text=True)
    assert "Validation failed" in fragment and "DNS problem" in fragment and "disabled" in _apply_button(fragment)


def test_page_upload_and_apply(logged_in, gateway, pki):
    response = logged_in.post("/tls/upload", data={
        "certificate": (io.BytesIO(_pem(pki["leaf"], pki["inter"])), "cert.pem"),
        "key": (io.BytesIO(_pem(pki["leaf_key"])), "key.pem")}, content_type="multipart/form-data")
    page = response.get_data(as_text=True)
    assert response.status_code == 200 and "The files passed every check." in page
    sha256 = certificates.staged_sha256()
    assert f'name="sha256" value="{sha256}"' in page
    assert logged_in.post("/tls/manual/apply", data={"sha256": sha256}).status_code == 302
    assert _request(gateway) == {"action": "manual-apply", "sha256": sha256}

    os.remove(gateway.config["TLS_REQUEST"])
    other = ec.generate_private_key(ec.SECP256R1())
    response = logged_in.post("/tls/upload", data={
        "certificate": (io.BytesIO(_pem(pki["leaf"])), "cert.pem"),
        "key": (io.BytesIO(_pem(other)), "key.pem")}, content_type="multipart/form-data")
    page = response.get_data(as_text=True)
    assert response.status_code == 400 and "does not belong to the certificate" in page and 'name="sha256"' not in page


def test_page_versions(logged_in, gateway):
    response = logged_in.post("/tls/versions", data={"https_tls10": "on", "smtp_tls11": "on"})
    assert response.status_code == 400 and "TLS 1.0 can only be accepted together with TLS 1.1" in \
        response.get_data(as_text=True)
    assert logged_in.post("/tls/versions", data={"https_tls10": "on", "https_tls11": "on",
                                                 "smtp_tls11": "on"}).status_code == 302
    assert _request(gateway) == {"action": "versions", "https_min": "1.0", "smtp_min": "1.1"}


def test_page_in_a_cluster(logged_in, gateway):
    gateway.conf(HA_NODES="mx.example.com=10.0.0.1")
    page = logged_in.get("/tls/").get_data(as_text=True)
    assert "This gateway is a cluster member" in page
    assert logged_in.post("/tls/versions", data={}).status_code == 400


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def test_api(api, gateway, pki):
    state = api("GET", "/tls").get_json()
    assert state["settings"]["hostname"] == HOST and state["certificate"]["names"] == [HOST, "mail.example.com"]
    assert state["busy"] is False
    assert api("POST", "/tls/letsencrypt/test", json={"names": ["mail.example.com"]}).status_code == 202
    assert api("PUT", "/tls/versions", json={"https_min": "1.0", "smtp_min": "1.2"}).status_code == 409  # busy
    os.remove(gateway.config["TLS_REQUEST"])
    assert api("POST", "/tls/letsencrypt/apply", json={"names": ["x.example.com"]}).status_code == 409
    assert api("PUT", "/tls/versions", json={"https_min": "0.9", "smtp_min": "1.2"}).status_code == 422
    response = api("POST", "/tls/certificate", data={
        "certificate": (io.BytesIO(_pem(pki["leaf"], pki["inter"])), "cert.pem"),
        "key": (io.BytesIO(_pem(pki["leaf_key"])), "key.pem")}, content_type="multipart/form-data")
    body = response.get_json()
    assert response.status_code == 200 and body["errors"] == [] and len(body["sha256"]) == 64
    assert api("POST", "/tls/certificate/apply", json={"sha256": body["sha256"]}).status_code == 202
    os.remove(gateway.config["TLS_REQUEST"])
    bad = api("POST", "/tls/certificate", data={"certificate": (io.BytesIO(b"x"), "c.pem"),
                                                "key": (io.BytesIO(b"y"), "k.pem")},
              content_type="multipart/form-data")
    assert bad.status_code == 422 and "PEM" in bad.get_json()["error"]
