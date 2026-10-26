"""system/libexec/network-apply's decisions with several interfaces: what it
accepts, which families the gateway uses and which it tests. nmcli, ip and
the reachability probe are replaced."""
import importlib.machinery
import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

HELPER = Path(__file__).resolve().parents[3] / "system" / "libexec" / "network-apply"
UUID1 = "3d0ed6a1-d9dd-36a1-99d6-8f282a52bbfb"
UUID2 = "8e1c7d2a-4b5f-4a6e-9c3d-2f1e0a9b8c7d"


def _load():
    sys.dont_write_bytecode = True
    loader = importlib.machinery.SourceFileLoader("network_apply", str(HELPER))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    module = importlib.util.module_from_spec(spec)
    loader.exec_module(module)
    return module


apply = _load()


@pytest.fixture
def host(monkeypatch):
    """ens18 (default route, both families) and ens19 (internal IPv4)."""
    outputs = {
        ("nmcli", "-t", "-f", "DEVICE,TYPE,STATE", "device"):
            "ens18:ethernet:connected\nens19:ethernet:connected\ndocker0:bridge:connected (externally)\n"
            "lo:loopback:connected (externally)\n",
        ("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", "ens18"): UUID1 + "\n",
        ("nmcli", "-g", "GENERAL.CON-UUID", "device", "show", "ens19"): UUID2 + "\n",
        ("nmcli", "-g", "ipv4.method,ipv4.gateway,ipv6.method,ipv6.gateway", "connection", "show", UUID1):
            "manual\n192.0.2.1\nauto\n\n",
        ("nmcli", "-g", "ipv4.method,ipv4.gateway,ipv6.method,ipv6.gateway", "connection", "show", UUID2):
            "manual\n\ndisabled\n\n",
        ("ip", "-o", "addr", "show", "dev", "ens18"):
            "2: ens18    inet 192.0.2.10/24 brd 192.0.2.255 scope global ens18\\n\n",
        ("ip", "-o", "addr", "show", "dev", "ens19"): "3: ens19    inet 10.0.0.5/24 scope global ens19\\n\n",
    }
    monkeypatch.setattr(apply, "query", lambda *argv: outputs.get(argv, ""))
    return outputs


def request(device="ens19", uuid=UUID2, **families):
    data = {"connection": uuid, "device": device,
            "ipv4": {"enabled": True, "method": "manual", "addresses": ["10.0.0.5/24"], "gateway": ""},
            "ipv6": {"enabled": False}}
    data.update(families)
    return json.dumps(data)


def test_interface_states(host):
    states = apply.interface_states()
    assert set(states) == {"ens18", "ens19"}
    assert states["ens18"][4] == (True, True) and states["ens18"][6] == (True, True)  # auto counts as a gateway
    assert states["ens19"][4] == (True, False) and states["ens19"][6] == (False, False)
    assert apply.families_of(states) == {4: (True, True), 6: (True, True)}


def test_both_off_while_another_interface_has_an_address(host):
    states = apply.interface_states()
    uuid, device, v4, v6 = apply.parse_request(request(ipv4={"enabled": False}), {}, states)
    assert (uuid, device, v4[0], v6[0]) == (UUID2, "ens19", False, False)
    # the last interface with an address must keep one
    states["ens18"][4] = states["ens18"][6] = (False, False)
    with pytest.raises(apply.Invalid, match="no other interface has an address"):
        apply.parse_request(request(ipv4={"enabled": False}), {}, states)


def test_unknown_interface_or_connection(host):
    states = apply.interface_states()
    with pytest.raises(apply.Invalid, match="not an interface NetworkManager manages"):
        apply.parse_request(request(device="docker0"), {}, states)
    with pytest.raises(apply.Invalid, match="not an interface NetworkManager manages"):
        apply.parse_request(request(uuid=UUID1), {}, states)


def test_nginx_bind_only_matters_on_its_interface(host):
    states = apply.interface_states()
    conf = {"HTTPS_BIND": "192.0.2.10"}
    # ens19 does not have the address nginx listens on
    apply.parse_request(request(ipv4={"enabled": False}), conf, states)
    with pytest.raises(apply.Invalid, match="HTTPS_BIND=192.0.2.10"):
        apply.parse_request(request("ens18", UUID1, ipv4={"enabled": True, "method": "manual",
                                                          "addresses": ["192.0.2.11/24"], "gateway": "192.0.2.1"}),
                            conf, states)


class Network:
    """ip route and the reachability of each family."""
    def __init__(self, routes=(4, 6), reachable=(4, 6)):
        self.routes, self.reachable = routes, reachable

    def run(self, *argv, check=True):
        version = int(argv[1][1])
        return subprocess.CompletedProcess(argv, 0, "default via x\n" if version in self.routes else "", "")

    def reaches(self, address, version):
        return version in self.reachable


@pytest.fixture
def network(monkeypatch):
    def use(**kwargs):
        net = Network(**kwargs)
        monkeypatch.setattr(apply, "run", net.run)
        monkeypatch.setattr(apply, "reaches", net.reaches)
        monkeypatch.setattr(apply, "TEST_TIME", 0)
        monkeypatch.setattr(apply.socket, "getaddrinfo", lambda *a: [])
        return net
    return use


def test_reachability(network):
    network()
    assert apply.test({4: (True, True), 6: (True, True)}) == []
    # IPv6 only on an internal interface: not tested
    network(routes=(4,), reachable=(4,))
    assert apply.test({4: (True, True), 6: (True, False)}) == []
    # a gateway but no route: a problem
    assert apply.test({4: (True, True), 6: (True, True)}) == ["IPv6 has no default route"]
    # no family reaches anything
    network(routes=(4,), reachable=())
    assert "IPv4 does not reach the internet" in apply.test({4: (True, True), 6: (False, False)})[0]
    # no gateway anywhere: the server would be cut off
    network(routes=(), reachable=())
    assert apply.test({4: (True, False), 6: (False, False)}) == [
        "no interface has a gateway: the server would not reach the internet"]
