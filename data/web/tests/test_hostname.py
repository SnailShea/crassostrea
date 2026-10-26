"""Hostname change requested in the web UI (applied by system/libexec/set-hostname)."""
import os

import pytest

from crassostrea.services import hostname, netcheck
from crassostrea.services.errors import ServiceError

LOCAL = "203.0.113.10"


@pytest.fixture
def dns(monkeypatch):
    """name -> addresses; this server has LOCAL."""
    records = {"mx.new.example": [LOCAL], "elsewhere.example": ["198.51.100.7"]}

    def addresses(name):
        if name == "broken.example":
            raise netcheck.LookupFailed("timeout")
        return records.get(name, [])
    monkeypatch.setattr(netcheck, "addresses", addresses)
    monkeypatch.setattr(netcheck, "is_local", lambda address: address == LOCAL)
    return records


@pytest.fixture
def gateway(app):
    app.config.update(HOSTNAME="mx.old.example", CLUSTER_NODES=[])
    return app


def _request_file(app):
    with open(app.config["HOSTNAME_REQUEST"]) as handle:
        return handle.read()


@pytest.mark.parametrize("name", ["localhost", "mx.example.com.", "-mx.example.com", "mx..example.com",
                                  "mx.example.123", "mx_1.example.com", "a" * 64 + ".example.com", "", None])
def test_invalid_names(name):
    with pytest.raises(ServiceError):
        hostname.normalize(name)


def test_request_change(gateway, dns):
    assert hostname.pending() is None
    assert hostname.request_change(" MX.New.Example ") == []
    assert _request_file(gateway) == "mx.new.example\n" and hostname.pending() == "mx.new.example"
    # the current name cancels a change that is not applied yet...
    hostname.request_change("mx.old.example")
    assert hostname.pending() == "mx.old.example"
    # ...and is refused once nothing is pending (set-hostname removed the request)
    os.remove(gateway.config["HOSTNAME_REQUEST"])
    with pytest.raises(ServiceError, match="already is"):
        hostname.request_change("mx.old.example")


@pytest.mark.parametrize("name, warning", [
    ("not-yet.example", "does not resolve yet"),
    ("elsewhere.example", "198.51.100.7, which is not an address of this server"),
    ("broken.example", "could not be looked up"),
])
def test_dns_warnings_do_not_block(gateway, dns, name, warning):
    warnings = hostname.request_change(name)
    assert len(warnings) == 1 and warning in warnings[0]
    assert hostname.pending() == name


def test_cluster_members_cannot_change_it(gateway, dns):
    gateway.config["CLUSTER_NODES"] = [("mx.old.example", "10.0.0.1"), ("mx2.old.example", "10.0.0.2")]
    with pytest.raises(ServiceError, match="cluster member") as error:
        hostname.request_change("mx.new.example")
    assert error.value.status == 409 and hostname.pending() is None


def test_settings_page(logged_in, gateway, dns):
    page = logged_in.get("/ip/").get_data(as_text=True)
    assert 'id="hostname"' in page and "mx.old.example" in page and 'name="host-hostname"' in page
    response = logged_in.post("/settings/hostname", data={"host-hostname": "not-yet.example"}, follow_redirects=True)
    page = response.get_data(as_text=True)
    assert "The gateway is switching to not-yet.example" in page and "does not resolve yet" in page
    assert "Switching to <span class=\"mono\">not-yet.example</span>" in page
    response = logged_in.post("/settings/hostname", data={"host-hostname": "bad_name"})
    assert response.status_code == 400 and "fully qualified host name" in response.get_data(as_text=True)


def test_settings_page_in_a_cluster(logged_in, gateway):
    gateway.config["CLUSTER_NODES"] = [("mx.old.example", "10.0.0.1"), ("mx2.old.example", "10.0.0.2")]
    page = logged_in.get("/ip/").get_data(as_text=True)
    assert "system/cluster.sh" in page and 'name="host-hostname"' not in page
    response = logged_in.post("/settings/hostname", data={"host-hostname": "mx.new.example"})
    assert response.status_code == 400 and hostname.pending() is None


def test_api(api, gateway, dns):
    assert api("GET", "/hostname").get_json() == {"hostname": "mx.old.example", "pending": None, "cluster": False}
    response = api("PUT", "/hostname", json={"hostname": "mx.new.example"})
    assert response.status_code == 202
    assert response.get_json() == {"hostname": "mx.old.example", "pending": "mx.new.example", "cluster": False,
                                   "warnings": []}
    assert api("PUT", "/hostname", json={"hostname": "x"}).status_code == 422
    assert api("PUT", "/hostname", json={}).status_code == 422
    gateway.config["CLUSTER_NODES"] = [("mx.old.example", "10.0.0.1")]
    assert api("PUT", "/hostname", json={"hostname": "mx.other.example"}).status_code == 409
