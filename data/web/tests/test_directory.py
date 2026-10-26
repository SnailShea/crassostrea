"""Recipients from directories: LDAP (with ldap3's mock server) and
Microsoft 365 (a fake Graph), the synchronisation and its safeguards."""
import pytest
from ldap3 import MOCK_SYNC, Connection, Server

from crassostrea.extensions import db
from crassostrea.models import Directory, Domain, Recipient
from crassostrea.services import directory as directory_service
from crassostrea.services import filters
from crassostrea.services.errors import ServiceError

BIND_DN = "cn=svc,dc=example,dc=com"


def ldap_entries(count, start=0):
    return {f"cn=u{i},ou=people,dc=example,dc=com": {
        "mail": f"User{i}@Example.com",
        "proxyAddresses": [f"SMTP:user{i}@example.com", f"smtp:alias{i}@example.com", f"smtp:u{i}@other.example",
                           "X500:/o=Example/cn=u", f"SIP:user{i}@example.com"]}
        for i in range(start, start + count)}


@pytest.fixture
def fake_ldap(monkeypatch):
    """The directory's LDAP server: entries is {dn: attributes}."""
    state = {"entries": ldap_entries(3), "password": "pw-4711"}

    def connect(directory):
        conn = Connection(Server("fake"), user=directory.bind_dn, password=directory.bind_password,
                          client_strategy=MOCK_SYNC, raise_exceptions=True)
        conn.strategy.add_entry(BIND_DN, {"userPassword": state["password"], "sn": "svc"})
        for dn, attributes in state["entries"].items():
            conn.strategy.add_entry(dn, attributes)
        return conn
    monkeypatch.setattr(directory_service, "_ldap_connection", connect)
    return state


@pytest.fixture
def ldap_domain(app):
    directory = directory_service.create_directory(
        name="AD", kind="ldap", ldap_urls="ldaps://dc1.example.com", bind_dn=BIND_DN, bind_password="pw-4711",
        base_dn="dc=example,dc=com")
    domain = Domain(name="example.com", destination_host="mx.internal", recipient_check="directory",
                    directory=directory)
    db.session.add_all([directory, domain])
    db.session.commit()
    return directory, domain


def addresses(domain):
    return {(r.address, r.source) for r in Recipient.query.filter_by(domain_id=domain.id)}


@pytest.mark.parametrize("value, expected", [
    ("SMTP:Alice@Example.com", "alice@example.com"), ("smtp:bob@example.com", "bob@example.com"),
    ("carol@example.com", "carol@example.com"), ("X500:/o=x/cn=y", None), ("sip:dave@example.com", None),
    ("not an address", None), (None, None),
])
def test_address(value, expected):
    assert directory_service._address(value) == expected


def test_validation(app):
    for data, field in [
        ({"name": "A", "kind": "ldap", "base_dn": "dc=x"}, "ldap_urls"),
        ({"name": "A", "kind": "ldap", "ldap_urls": "http://dc1", "base_dn": "dc=x"}, "ldap_urls"),
        ({"name": "A", "kind": "ldap", "ldap_urls": "ldap://dc1"}, "base_dn"),
        ({"name": "A", "kind": "ldap", "ldap_urls": "ldaps://dc1", "base_dn": "dc=x", "ldap_starttls": True},
         "ldap_starttls"),
        ({"name": "A", "kind": "ldap", "ldap_urls": "ldap://dc1", "base_dn": "dc=x", "ldap_filter": "(mail=*"},
         "ldap_filter"),
        ({"name": "A", "kind": "ldap", "ldap_urls": "ldap://dc1", "base_dn": "dc=x", "bind_dn": "cn=a"},
         "bind_password"),
        ({"name": "A", "kind": "ldap", "ldap_urls": "ldap://dc1", "base_dn": "dc=x", "ldap_attributes": "mail;x"},
         "ldap_attributes"),
        ({"name": "A", "kind": "m365", "tenant_id": "example.onmicrosoft.com", "client_id": "nope"}, "client_id"),
        ({"name": "A", "kind": "m365", "tenant_id": "example.onmicrosoft.com",
          "client_id": "11111111-2222-3333-4444-555555555555"}, "client_secret"),
        ({"name": "A", "kind": "x500"}, "kind"),
    ]:
        with pytest.raises(ServiceError) as exc:
            directory_service.create_directory(**data)
        assert exc.value.field == field, data
        db.session.rollback()
    directory = directory_service.create_directory(name="LDAP", kind="ldap", ldap_urls=" ldap://a  ldap://b:3268 ",
                                                   base_dn="dc=example,dc=com")
    assert (directory.ldap_urls, directory.ldap_filter, directory.ldap_attributes) == (
        "ldap://a ldap://b:3268", directory_service.AD_FILTER, "mail proxyAddresses")


def test_domain_needs_a_directory(app, ldap_domain):
    directory, domain = ldap_domain
    with pytest.raises(ServiceError) as exc:
        filters.update_domain(domain, directory_id=None)
    assert exc.value.field == "directory_id"
    db.session.rollback()
    with pytest.raises(ServiceError):
        filters.update_domain(domain, directory_id=999)
    db.session.rollback()
    filters.update_domain(domain, recipient_check="list", directory_id=None)
    db.session.commit()
    with pytest.raises(ServiceError) as exc:
        filters.update_domain(domain, recipient_check="directory")
    db.session.rollback()


def test_ldap_sync(app, fake_ldap, ldap_domain):
    directory, domain = ldap_domain
    db.session.add(Recipient(domain=domain, address="manual@example.com"))
    db.session.add(Recipient(domain=domain, address="user0@example.com"))
    db.session.commit()
    result = directory_service.sync(directory)
    assert result == {"example.com": {"added": 5, "removed": 0, "total": 6}}
    assert addresses(domain) == {("manual@example.com", "manual"), ("user0@example.com", "manual"),
                                 *{(f"{p}{i}@example.com", "directory") for p in ("user", "alias")
                                   for i in range(3) if (p, i) != ("user", 0)}}
    assert directory.sync_count == 6 and directory.sync_error == "" and directory.synced_at

    # paged: more entries than a page; one leaves
    fake_ldap["entries"] = ldap_entries(directory_service.PAGE_SIZE + 2, start=1)
    result = directory_service.sync(directory)["example.com"]
    assert result["removed"] == 1 and result["total"] == 2 * (directory_service.PAGE_SIZE + 2)
    assert ("alias0@example.com", "directory") not in addresses(domain)
    assert ("user0@example.com", "manual") in addresses(domain)


def test_safeguards(app, fake_ldap, ldap_domain):
    directory, domain = ldap_domain
    fake_ldap["entries"] = ldap_entries(10)
    directory_service.sync(directory)
    before = addresses(domain)
    fake_ldap["entries"] = ldap_entries(2)
    with pytest.raises(directory_service.DirectoryError, match="would lose 16 of its 20 recipients"):
        directory_service.sync(directory)
    assert addresses(domain) == before and "would lose" in db.session.get(Directory, directory.id).sync_error
    fake_ldap["entries"] = {}
    with pytest.raises(directory_service.DirectoryError, match="no addresses"):
        directory_service.sync(directory, force=True)
    fake_ldap["entries"] = ldap_entries(2)
    assert directory_service.sync(directory, force=True)["example.com"]["removed"] == 16
    fake_ldap["password"] = "changed"
    with pytest.raises(directory_service.DirectoryError, match="invalidCredentials"):
        directory_service.sync(directory)
    assert len(addresses(domain)) == 4


class FakeResponse:
    def __init__(self, status, body):
        self.status_code, self.body, self.text = status, body, str(body)

    def json(self):
        return self.body


class FakeGraph:
    def __init__(self, pages, token_status=200, status=200):
        self.pages, self.token_status, self.status, self.urls = pages, token_status, status, []

    def post(self, url, data=None, timeout=None):
        assert url.endswith("/example.onmicrosoft.com/oauth2/v2.0/token") and data["client_secret"] == "s3cret"
        if self.token_status != 200:
            return FakeResponse(self.token_status, {"error_description": "AADSTS7000215: Invalid client secret"})
        return FakeResponse(200, {"access_token": "tok"})

    def get(self, url, headers=None, timeout=None):
        assert headers["Authorization"] == "Bearer tok"
        self.urls.append(url)
        if self.status != 200:
            return FakeResponse(self.status, {"error": {"message": "Insufficient privileges"}})
        return FakeResponse(200, self.pages.get(url, {"value": []}))

    def close(self):
        pass


def m365(app):
    directory = directory_service.create_directory(name="M365", kind="m365", tenant_id="example.onmicrosoft.com",
                                                   client_id="11111111-2222-3333-4444-555555555555",
                                                   client_secret="s3cret")
    domain = Domain(name="example.com", destination_host="mx.internal", recipient_check="directory",
                    directory=directory)
    db.session.add_all([directory, domain])
    db.session.commit()
    return directory, domain


def test_microsoft_365(app, monkeypatch):
    directory, domain = m365(app)
    users = f"{directory_service.GRAPH}/users?$select=mail,proxyAddresses&$top=999"
    groups = f"{directory_service.GRAPH}/groups?$select=mail,proxyAddresses&$top=999"
    graph = FakeGraph({
        users: {"value": [{"mail": "Alice@example.com", "proxyAddresses": ["SMTP:alice@example.com",
                                                                           "smtp:a@example.com"]},
                          {"mail": None, "proxyAddresses": []}], "@odata.nextLink": "https://graph/next"},
        "https://graph/next": {"value": [{"mail": "guest@partner.example", "proxyAddresses": []}]},
        groups: {"value": [{"mail": "sales@example.com", "proxyAddresses": ["SMTP:sales@example.com"]}]},
    })
    monkeypatch.setattr(directory_service, "_session", lambda: graph)
    assert directory_service.preview(directory) == {
        "total": 4, "domains": {"example.com": 3},
        "sample": ["a@example.com", "alice@example.com", "sales@example.com"]}
    assert graph.urls == [users, "https://graph/next", groups]
    assert directory_service.sync(directory)["example.com"]["added"] == 3

    monkeypatch.setattr(directory_service, "_session", lambda: FakeGraph({}, status=403))
    with pytest.raises(directory_service.DirectoryError, match="403 Insufficient privileges.*User.Read.All"):
        directory_service.sync(directory)
    monkeypatch.setattr(directory_service, "_session", lambda: FakeGraph({}, token_status=401))
    with pytest.raises(directory_service.DirectoryError, match="Invalid client secret"):
        directory_service.preview(directory)


def test_pages(app, logged_in, fake_ldap):
    response = logged_in.post("/directories/new", data={
        "name": "AD", "kind": "ldap", "ldap_urls": "ldaps://dc1.example.com", "ldap_verify": "y",
        "bind_dn": BIND_DN, "bind_password": "pw-4711", "base_dn": "dc=example,dc=com"}, follow_redirects=True)
    assert "Directory AD added" in response.get_data(as_text=True)
    directory = Directory.query.one()
    page = logged_in.get(f"/directories/{directory.id}").get_data(as_text=True)
    assert "pw-4711" not in page and 'placeholder="unchanged"' in page
    # saving without a password keeps it
    logged_in.post(f"/directories/{directory.id}", data={
        "name": "AD", "kind": "ldap", "ldap_urls": "ldaps://dc1.example.com", "bind_dn": BIND_DN,
        "base_dn": "dc=example,dc=com"})
    assert db.session.get(Directory, directory.id).bind_password == "pw-4711"

    domain = filters.create_domain("example.com", destination_host="mx.internal", recipient_check="directory",
                                   directory_id=directory.id)
    db.session.commit()
    response = logged_in.post(f"/directories/{directory.id}/test", follow_redirects=True)
    assert "9 addresses found (example.com: 6)" in response.get_data(as_text=True)
    response = logged_in.post(f"/directories/{directory.id}/sync", follow_redirects=True)
    assert "example.com: 6 recipients (6 added, 0 removed)" in response.get_data(as_text=True)
    page = logged_in.get(f"/domains/{domain.id}").get_data(as_text=True)
    assert "Synchronised from" in page and '<span class="badge info">directory</span>' in page
    assert 'href="/directories/" class="active"' in logged_in.get("/directories/").get_data(as_text=True)
    response = logged_in.post(f"/directories/{directory.id}/delete", follow_redirects=True)
    assert "is used by example.com" in response.get_data(as_text=True)


def test_api(app, api, fake_ldap):
    response = api("POST", "/directories", json={
        "name": "AD", "kind": "ldap", "ldap_urls": "ldap://dc1.example.com", "ldap_starttls": True,
        "bind_dn": BIND_DN, "bind_password": "pw-4711", "base_dn": "dc=example,dc=com"})
    assert response.status_code == 201
    body = response.get_json()
    assert "bind_password" not in body and body["bind_password_set"] is True and body["ldap_starttls"] is True
    directory_id = body["id"]
    domain = api("POST", "/domains", json={"name": "example.com", "destination_host": "mx.internal",
                                           "recipient_check": "directory", "directory_id": directory_id}).get_json()
    assert domain["directory_id"] == directory_id
    # STARTTLS is not mocked: switch it off
    api("PATCH", f"/directories/{directory_id}", json={"ldap_starttls": False})
    assert api("POST", f"/directories/{directory_id}/test").get_json()["domains"] == {"example.com": 6}
    body = api("POST", f"/directories/{directory_id}/sync").get_json()
    assert body["domains"]["example.com"]["added"] == 6 and body["directory"]["sync_count"] == 6
    recipients = api("GET", f"/domains/{domain['id']}/recipients").get_json()["items"]
    assert {r["source"] for r in recipients} == {"directory"}
    fake_ldap["password"] = "changed"
    response = api("POST", f"/directories/{directory_id}/sync", json={"force": True})
    assert response.status_code == 502 and "invalidCredentials" in response.get_json()["error"]
    assert api("DELETE", f"/directories/{directory_id}").status_code == 409


def test_command(app, fake_ldap, ldap_domain):
    runner = app.test_cli_runner()
    result = runner.invoke(args=["sync-directories"])
    assert result.exit_code == 0 and "AD: example.com: 6 recipients (6 added, 0 removed)" in result.output
    fake_ldap["password"] = "changed"
    result = runner.invoke(args=["sync-directories"])
    assert result.exit_code == 1 and "not synchronised" in result.output


def test_ldap_server_down(app):
    directory = directory_service.create_directory(name="Down", kind="ldap",
                                                   ldap_urls="ldap://127.0.0.1:9 ldaps://127.0.0.1:9",
                                                   base_dn="dc=example,dc=com")
    with pytest.raises(directory_service.DirectoryError, match="^LDAP: "):
        directory_service.fetch(directory)
