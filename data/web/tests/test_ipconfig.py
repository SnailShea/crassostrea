"""IP addressing page: state from NetworkManager, validation, requests to network-apply."""
import json
import os
import time

import pytest

from crassostrea.services import ipconfig
from crassostrea.services.errors import ServiceError

UUID = "3d0ed6a1-d9dd-36a1-99d6-8f282a52bbfb"
# nmcli -t output of the server this was written on
NMCLI = {
    ("-f", "DEVICE,TYPE,STATE,CONNECTION", "device"):
        "ens18:ethernet:connected:Services\ndocker0:bridge:connected (externally):docker0\n"
        "lo:loopback:connected (externally):lo\n",
    ("-f", "GENERAL.CON-UUID,IP4.GATEWAY,IP6.GATEWAY,IP4.ADDRESS,IP6.ADDRESS", "device", "show", "ens18"):
        f"GENERAL.CON-UUID:{UUID}\nIP4.ADDRESS[1]:69.2.160.252/28\nIP4.GATEWAY:69.2.160.241\n"
        "IP6.ADDRESS[1]:fe80::1269:91:a436:6b66/64\nIP6.ADDRESS[2]:2604:5c80:5c80::1234/64\nIP6.GATEWAY:fe80::1\n",
    ("-f", "connection.id,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv6.method,ipv6.addresses,ipv6.gateway,"
           "ipv6.dns", "connection", "show", UUID):
        "connection.id:Services\nipv4.method:manual\nipv4.addresses:69.2.160.252/28\nipv4.gateway:69.2.160.241\n"
        "ipv4.dns:69.2.160.53,69.2.160.54\nipv6.method:manual\nipv6.addresses:2604:5c80:5c80::1234/64\n"
        "ipv6.gateway:fe80::1\nipv6.dns:2604:5c80:5c80::1111\n",
}


@pytest.fixture
def host(app, config, monkeypatch):
    def nmcli(*args):
        if args not in NMCLI:
            raise ipconfig.NetworkStateError(f"unexpected nmcli {args}")
        return [tuple(line.split(":", 1)) for line in NMCLI[args].splitlines()]
    monkeypatch.setattr(ipconfig, "nmcli", nmcli)
    with open(config["CONF_FILE"], "w") as handle:
        handle.write("IPV4_ENABLED=true\nIPV6_ENABLED=true\nMANAGE_RESOLVER=y\nHA_NODES=\n")
    app.config["CLUSTER_NODES"] = []
    return app


def settings(**changes):
    values = {"ipv4": {"enabled": True, "method": "manual", "addresses": ["69.2.160.252/28"],
                       "gateway": "69.2.160.241", "dns": []},
              "ipv6": {"enabled": True, "method": "manual", "addresses": ["2604:5c80:5c80::1234/64"],
                       "gateway": "fe80::1", "dns": []}}
    for key, value in changes.items():
        family, field = key.split("__")
        values[family][field] = value
    return values


def _request(app):
    with open(app.config["IP_REQUEST"]) as handle:
        return json.load(handle)


def test_current(host):
    state = ipconfig.current()
    assert (state["device"], state["uuid"], state["name"]) == ("ens18", UUID, "Services")
    assert state["live6"] == ["fe80::1269:91:a436:6b66/64", "2604:5c80:5c80::1234/64"]
    assert state["ipv4"] == {"enabled": True, "method": "manual", "addresses": ["69.2.160.252/28"],
                             "gateway": "69.2.160.241", "dns": ["69.2.160.53", "69.2.160.54"]}
    assert state["ipv6"]["enabled"] and state["managed_resolver"] and not state["cluster"]


@pytest.mark.parametrize("changes, message", [
    ({"ipv4__enabled": False, "ipv6__enabled": False}, "cannot both be off"),
    ({"ipv4__addresses": ["69.2.160.252"]}, "not an IPv4 address with prefix length"),
    ({"ipv4__addresses": ["2001:db8::1/64"]}, "not an IPv4 address"),
    ({"ipv4__addresses": []}, "give 1 to 16 addresses"),
    ({"ipv4__addresses": ["69.2.160.240/28"]}, "network or broadcast"),
    ({"ipv4__addresses": ["127.0.0.2/8"]}, "cannot be the interface's address"),
    ({"ipv4__gateway": "10.0.0.1"}, "not in the network of an address"),
    ({"ipv4__gateway": "69.2.160.252"}, "the server's own address"),
    ({"ipv6__addresses": ["fe80::5/64"]}, "cannot be the interface's address"),
    ({"ipv6__gateway": "2001:db8::1"}, "not in the network of an address"),
    ({"ipv4__dns": ["2001:db8::53"]}, "not an IPv4 address"),
    ({"ipv4__dns": ["1.1.1.1", "1.0.0.1", "9.9.9.9", "8.8.8.8"]}, "at most 3"),
    ({"ipv4__method": "static"}, "method must be"),
])
def test_validation(host, changes, message):
    with pytest.raises(ServiceError, match=message):
        ipconfig.validate(settings(**changes))


def test_valid_settings(host):
    # one family off, automatic configuration, a link-local IPv6 gateway, no IPv6 gateway at all
    assert ipconfig.validate(settings(ipv6__enabled=False))["ipv6"] == {
        "enabled": False, "method": "manual", "addresses": [], "gateway": "", "dns": []}
    assert ipconfig.validate(settings(ipv4__enabled=False, ipv6__method="auto"))["ipv6"]["method"] == "auto"
    assert ipconfig.validate(settings(ipv6__gateway=""))["ipv6"]["gateway"] == ""
    values = ipconfig.validate(settings(ipv4__method="auto", ipv4__addresses=[]))
    assert values["ipv4"]["addresses"] == []


def test_request(host):
    ipconfig.request_change(settings(ipv6__enabled=False))
    request = _request(host)
    assert request["connection"] == UUID and request["device"] == "ens18"
    assert request["ipv6"]["enabled"] is False and request["ipv4"]["addresses"] == ["69.2.160.252/28"]
    with pytest.raises(ServiceError, match="still being applied"):
        ipconfig.request_change(settings())
    os.remove(host.config["IP_REQUEST"])  # network-apply consumed it
    with open(host.config["IP_STATUS"], "w") as handle:
        json.dump({"change": {"state": "running", "at": int(time.time()), "message": "testing"}}, handle)
    assert ipconfig.busy()
    with open(host.config["IP_STATUS"], "w") as handle:
        json.dump({"change": {"state": "running", "at": int(time.time()) - 3600, "message": "x"}}, handle)
    assert not ipconfig.busy() and ipconfig.status()["outcome"] == "stopped"


def test_cluster_members_cannot_change(host, config):
    with open(config["CONF_FILE"], "a") as handle:
        handle.write("HA_NODES=mx1.example.com=10.0.0.1\n")
    with pytest.raises(ServiceError, match="cluster member") as error:
        ipconfig.request_change(settings())
    assert error.value.status == 409


def test_page(logged_in, host):
    page = logged_in.get("/ip/").get_data(as_text=True)
    assert "2604:5c80:5c80::1234/64" in page and "ens18 · Services" in page
    assert page.count('data-keep-one="ip-family"') == 2 and 'name="ipv4_enabled" checked' in page
    assert "Not used while the gateway resolves names itself" in page
    assert "You are connected over IPv4 (127.0.0.1)" in page
    response = logged_in.post("/ip/", data={"ipv4_method": "manual", "ipv4_addresses": "69.2.160.252/28",
                                            "ipv4_gateway": "69.2.160.241", "ipv6_method": "manual"})
    assert response.status_code == 400 and "cannot both be off" in response.get_data(as_text=True)
    response = logged_in.post("/ip/", data={"ipv4_enabled": "on", "ipv4_method": "manual",
                                            "ipv4_addresses": "69.2.160.252/28\n69.2.160.253/28",
                                            "ipv4_gateway": "69.2.160.241", "ipv4_dns": "1.1.1.1, 9.9.9.9",
                                            "ipv6_method": "auto"})
    assert response.status_code == 302
    request = _request(host)
    assert request["ipv4"]["addresses"] == ["69.2.160.252/28", "69.2.160.253/28"]
    assert request["ipv4"]["dns"] == ["1.1.1.1", "9.9.9.9"] and request["ipv6"]["enabled"] is False


@pytest.mark.parametrize("change, outcome", [
    ({"state": "ok", "message": "Applied: IPv4 reaches the internet and names resolve."}, "applied"),
    ({"state": "failed", "message": "Reverted: IPv6 has no default route. The previous settings were restored."},
     "reverted"),
    ({"state": "failed", "message": "Nothing was changed: the gateway is not in the network"}, "refused"),
])
def test_page_shows_the_outcome(logged_in, host, change, outcome):
    with open(host.config["IP_STATUS"], "w") as handle:
        json.dump({"change": {**change, "at": int(time.time()), "log": "$ nmcli connection modify"}}, handle)
    fragment = logged_in.get("/ip/", headers={"X-Live-Fragment": "1"}).get_data(as_text=True)
    assert f">{outcome}</span>" in fragment and change["message"] in fragment and "nmcli connection modify" in fragment


def test_nmcli_failure_is_shown(logged_in, host, monkeypatch):
    def broken(*args):
        raise ipconfig.NetworkStateError("Cannot ask NetworkManager: not running")
    monkeypatch.setattr(ipconfig, "nmcli", broken)
    page = logged_in.get("/ip/").get_data(as_text=True)
    assert "Cannot ask NetworkManager: not running" in page and "Save and test" not in page


def test_api(api, host):
    state = api("GET", "/ip-config").get_json()
    assert state["state"]["device"] == "ens18" and state["change"] is None and state["busy"] is False
    assert api("PUT", "/ip-config", json=settings(ipv4__enabled=False, ipv6__enabled=False)).status_code == 422
    assert api("PUT", "/ip-config", json={"ipv4": settings()["ipv4"]}).status_code == 422
    response = api("PUT", "/ip-config", json=settings(ipv4__enabled=False))
    assert response.status_code == 202 and response.get_json()["ipv4"]["enabled"] is False
    assert _request(host)["ipv4"]["enabled"] is False


# ---------------------------------------------------------------------------
# Several interfaces
# ---------------------------------------------------------------------------

UUID2 = "8e1c7d2a-4b5f-4a6e-9c3d-2f1e0a9b8c7d"
TWO = {
    **NMCLI,
    ("-f", "DEVICE,TYPE,STATE,CONNECTION", "device"):
        "ens19:ethernet:connected:Backend\nens18:ethernet:connected:Services\n"
        "docker0:bridge:connected (externally):docker0\nlo:loopback:connected (externally):lo\n"
        "ens20:ethernet:unavailable:\n",
    ("-f", "GENERAL.CON-UUID,IP4.GATEWAY,IP6.GATEWAY,IP4.ADDRESS,IP6.ADDRESS", "device", "show", "ens19"):
        f"GENERAL.CON-UUID:{UUID2}\nIP4.ADDRESS[1]:10.0.0.5/24\nIP4.GATEWAY:\nIP6.GATEWAY:\n",
    ("-f", "connection.id,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv6.method,ipv6.addresses,ipv6.gateway,"
           "ipv6.dns", "connection", "show", UUID2):
        "connection.id:Backend\nipv4.method:manual\nipv4.addresses:10.0.0.5/24\nipv4.gateway:--\nipv4.dns:\n"
        "ipv6.method:disabled\nipv6.addresses:\nipv6.gateway:--\nipv6.dns:\n",
}


@pytest.fixture
def two(host, monkeypatch):
    def nmcli(*args):
        if args not in TWO:
            raise ipconfig.NetworkStateError(f"unexpected nmcli {args}")
        return [tuple(line.split(":", 1)) for line in TWO[args].splitlines()]
    monkeypatch.setattr(ipconfig, "nmcli", nmcli)
    return host


def backend(**changes):
    values = {"device": "ens19",
              "ipv4": {"enabled": True, "method": "manual", "addresses": ["10.0.0.5/24"], "gateway": "", "dns": []},
              "ipv6": {"enabled": False, "method": "manual", "addresses": [], "gateway": "", "dns": []}}
    for key, value in changes.items():
        family, field = key.split("__")
        values[family][field] = value
    return values


def test_interfaces(two):
    state = ipconfig.current()
    # the interface with the default route first; bridges, loopback and unavailable devices are left out
    assert [i["device"] for i in state["interfaces"]] == ["ens18", "ens19"]
    assert state["device"] == "ens18" and state["interfaces"][0]["default"] and state["others_enabled"]
    backend_state = ipconfig.current("ens19")
    assert backend_state["name"] == "Backend" and not backend_state["default"]
    assert backend_state["ipv4"]["gateway"] == "" and backend_state["ipv6"]["enabled"] is False
    with pytest.raises(ServiceError, match="no interface ens99") as error:
        ipconfig.current("ens99")
    assert error.value.status == 404


def test_an_interface_without_a_gateway(two):
    # an internal network: no gateway (network-apply's test reverts a change that leaves no way to the internet)
    assert ipconfig.request_change(backend())["ipv4"]["gateway"] == ""


def test_both_families_off_on_one_of_two(two):
    # ens18 keeps its addresses: ens19 may lose both
    families = ipconfig.request_change(backend(ipv4__enabled=False))
    assert families["device"] == "ens19"
    request = _request(two)
    assert request["device"] == "ens19" and request["connection"] == UUID2
    assert request["ipv4"]["enabled"] is False and request["ipv6"]["enabled"] is False
    os.remove(two.config["IP_REQUEST"])
    # and ens18 may lose both too, as ens19 keeps IPv4
    ipconfig.request_change({"device": "ens18", **settings(ipv4__enabled=False, ipv6__enabled=False)})
    assert _request(two)["device"] == "ens18"


def test_page_with_two_interfaces(logged_in, two):
    page = logged_in.get("/ip/?device=ens19").get_data(as_text=True)
    assert "<h2>Interfaces</h2>" in page and "default route" in page and "10.0.0.5/24" in page
    assert 'name="device" value="ens19"' in page and "ens19 · Backend" in page
    # both families may be off here: no keep-one rule
    assert 'data-keep-one="ip-family"' not in page and "another interface keeps an address" in page
    response = logged_in.post("/ip/", data={"device": "ens19", "ipv4_method": "manual", "ipv6_method": "manual"})
    assert response.status_code == 302 and response.headers["Location"].endswith("/ip/?device=ens19#change")
    assert _request(two)["ipv4"]["enabled"] is False
    page = logged_in.get("/ip/?device=nope").get_data(as_text=True)
    assert "There is no interface nope" in page and 'name="device" value="ens18"' in page


def test_api_with_two_interfaces(api, two):
    state = api("GET", "/ip-config?device=ens19").get_json()["state"]
    assert state["device"] == "ens19" and len(state["interfaces"]) == 2 and state["others_enabled"]
    assert api("GET", "/ip-config?device=ens99").status_code == 404
    response = api("PUT", "/ip-config", json=backend(ipv4__enabled=False))
    assert response.status_code == 202 and response.get_json()["device"] == "ens19"
    assert api("PUT", "/ip-config", json={**backend(), "device": 5}).status_code == 422
