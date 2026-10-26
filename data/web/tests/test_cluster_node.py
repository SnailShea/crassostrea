"""system/libexec/cluster-node applying a membership and writing a join
bundle, with configure.sh, cluster.sh, valkey-cli and systemctl replaced."""
import os
import subprocess
import time
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
NODE = REPO / "system" / "libexec" / "cluster-node"
TWO = "mx1.example.com=10.0.0.1,mx2.example.com=10.0.0.2"
THREE = TWO + ",mx3.example.com=10.0.0.3"


def stub(path, body):
    path.write_text("#!/bin/bash\n" + body)
    path.chmod(0o755)


@pytest.fixture
def node(tmp_path):
    """mx1's cluster-node in a scratch tree; returns a function that runs it until it exits."""
    bin_dir, src, state = tmp_path / "bin", tmp_path / "src", tmp_path / "state"
    for d in (bin_dir, src / "system", state, tmp_path / "web", tmp_path / "bundles", tmp_path / "postfix"):
        d.mkdir(parents=True)
    os.symlink(REPO / "system" / "lib", src / "system" / "lib")
    calls = tmp_path / "calls"
    stub(src / "system" / "configure.sh", f'echo "configure $*" >> {calls}\n')
    stub(src / "system" / "cluster.sh", f'echo "cluster $*" >> {calls}\necho "bundle of $2" > "$3"\n')
    stub(bin_dir / "valkey-cli", f'echo "valkey $*" >> {calls}\n')
    stub(bin_dir / "systemctl", f'echo "systemctl $*" >> {calls}\n')
    stub(bin_dir / "nginx", f'echo "nginx $*" >> {calls}\n')
    stub(bin_dir / "postfix", "")
    stub(bin_dir / "ip", "")
    (tmp_path / "source").write_text(str(src) + "\n")
    conf = tmp_path / "crassostrea.conf"
    conf.write_text(f"CRASSOSTREA_HOSTNAME=mx1.example.com\nHA_NODES={TWO}\nHA_WITNESS=\nREDISPASS=x\n")
    env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "CRASSOSTREA_HOSTNAME": "mx1.example.com",
           "HA_NODES": TWO, "HA_WITNESS": "", "HA_VIP": "", "REDISPASS": "x", "SF_CONF": str(conf),
           "SF_SOURCE_FILE": str(tmp_path / "source"), "CLUSTER_REQUEST": str(tmp_path / "web" / "request"),
           "CLUSTER_BUNDLE_REQUEST": str(tmp_path / "web" / "bundle"), "CLUSTER_BUNDLE_DIR": str(tmp_path / "bundles"),
           "CLUSTER_STATE_DIR": str(state), "CLUSTER_MAINT_CIDR": str(tmp_path / "postfix" / "maintenance.cidr"),
           "CLUSTER_PROBE_INTERVAL": "1"}

    def run(timeout=20):
        process = subprocess.Popen(["bash", str(NODE)], env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True)
        try:
            output, _ = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            process.terminate()
            output, _ = process.communicate()
        return output
    return tmp_path, run


def read(path):
    return path.read_text() if path.exists() else ""


def test_join_bundle_request(node):
    tmp, run = node
    (tmp / "web" / "bundle").write_text(f"members={THREE}\nwitness=\nhost=mx3.example.com\n")
    output = run()
    assert "Applying the membership" in output and "Restarting to use the new membership" in output
    conf = read(tmp / "crassostrea.conf")
    assert f"HA_NODES={THREE}" in conf and "HA_WITNESS=" in conf
    calls = read(tmp / "calls")
    assert "configure --no-restart" in calls and "cluster bundle mx3.example.com" in calls
    assert "valkey --tls" in calls and "SENTINEL SET crassostrea quorum 2" in calls
    assert "systemctl --no-block restart crassostrea-cluster.service" in calls
    # nginx follows the members (the other nodes answer ACME challenges)
    assert "nginx -t" in calls and "systemctl reload nginx.service" in calls
    assert read(tmp / "bundles" / "mx3.example.com.tar") == "bundle of mx3.example.com\n"
    assert not (tmp / "web" / "bundle").exists()


def test_membership_request(node):
    tmp, run = node
    (tmp / "web" / "request").write_text("members=mx1.example.com=10.0.0.1\nwitness=\n")
    run()
    assert "HA_NODES=mx1.example.com=10.0.0.1\n" in read(tmp / "crassostrea.conf")
    # one vote: a majority of one
    assert "SENTINEL SET crassostrea quorum 1" in read(tmp / "calls")


@pytest.mark.parametrize("request_, reason", [
    ("members=mx2.example.com=10.0.0.2\nwitness=\n", "no longer in the cluster's membership"),
    ("members=mx1.example.com=10.0.0.1;reboot\nwitness=\n", "Refused an invalid membership"),
    # system/lib/cluster.sh refuses an address used twice
    ("members=mx1.example.com=10.0.0.1,mx2.example.com=10.0.0.1\nwitness=\n", "does not accept it"),
])
def test_refused_memberships(node, request_, reason):
    tmp, run = node
    (tmp / "web" / "request").write_text(request_)
    run(timeout=4)
    assert f"HA_NODES={TWO}\n" in read(tmp / "crassostrea.conf")
    assert "configure" not in read(tmp / "calls")
    probe = read(tmp / "state" / "probe.json")
    assert reason in probe


def test_bundle_for_a_host_outside_the_membership(node):
    tmp, run = node
    (tmp / "web" / "bundle").write_text(f"members={TWO}\nwitness=\nhost=mx9.example.com\n")
    run(timeout=4)
    assert "the host is not in the membership" in read(tmp / "state" / "probe.json")
    assert not list((tmp / "bundles").iterdir())
