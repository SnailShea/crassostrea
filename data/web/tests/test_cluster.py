"""High availability: cluster settings, job locks and cluster pages."""
import json
import time

import pytest
import redis

from crassostrea import config as config_module
from crassostrea.services import store, system

from test_pages import backends_up, data  # noqa: F401 - fixtures

NODES = [("mx1.example.com", "10.0.0.1"), ("mx2.example.com", "10.0.0.2")]


@pytest.fixture
def cluster(app):
    app.config["CLUSTER_NODES"] = NODES
    app.config["CLUSTER_WITNESS"] = ("witness.example.com", "10.0.0.3")
    app.config["HOSTNAME"] = "mx1.example.com"
    return app


def test_members_from_environment(monkeypatch):
    monkeypatch.setenv("HA_NODES", "MX1.example.com=10.0.0.1, mx2.example.com=10.0.0.2,")
    assert config_module._members("HA_NODES") == NODES
    monkeypatch.delenv("HA_WITNESS", raising=False)
    assert config_module._members("HA_WITNESS") == []


def test_job_lock_is_exclusive(app):
    with store.job_lock("digests") as first:
        assert first
        with store.job_lock("digests") as second:
            assert not second
    with store.job_lock("digests") as again:
        assert again


def test_job_lock_without_redis(app, monkeypatch):
    def broken():
        raise redis.ConnectionError("down")
    monkeypatch.setattr(store, "get_redis", broken)
    # a single gateway runs the job anyway
    with store.job_lock("cleanup") as acquired:
        assert acquired
    # a cluster must not: another node might run it at the same time
    app.config["CLUSTER_NODES"] = NODES
    with pytest.raises(redis.ConnectionError):
        with store.job_lock("cleanup"):
            pass


@pytest.mark.parametrize("command, message", [("send-digests", "Another node is sending the digests"),
                                              ("cleanup", "Another node is running the cleanup")])
def test_jobs_skip_while_another_node_runs_them(app, fake_redis, command, message):
    fake_redis.set(f"SF_JOB_LOCK:{command}", "token-of-another-node", ex=60)
    result = app.test_cli_runner().invoke(args=[command])
    assert result.exit_code == 0 and message in result.output


def test_init_db_waits_for_another_node(app, fake_redis):
    fake_redis.set("SF_JOB_LOCK:init-db", "token-of-another-node", px=1500)
    started = time.monotonic()
    result = app.test_cli_runner().invoke(args=["init-db"])
    assert result.exit_code == 0, result.output
    assert time.monotonic() - started >= 1


class Replication:
    def __init__(self, info):
        self._info = info

    def info(self, section):
        assert section == "replication"
        return self._info


def test_cluster_status(cluster, monkeypatch):
    monkeypatch.setattr(store, "get_redis", lambda: Replication({
        "role": "master", "connected_slaves": 1,
        "slave0": {"ip": "10.0.0.2", "port": 6380, "state": "online", "offset": 1, "lag": 0}}))
    status = system.cluster_status()
    assert status["node"] == "mx1.example.com" and status["members"] == 3
    assert status["valkey"] == {"master": "mx1.example.com", "in_sync": 1, "expected": 1}
    # sqlite has no Galera status: reported, not raised
    assert status["database"] is None and "database cluster state" in status["errors"][0]


def test_cluster_status_single_gateway(app):
    assert system.cluster_status() is None


def test_cluster_pages(cluster, logged_in, backends_up, data, monkeypatch, fake_redis):  # noqa: F811
    monkeypatch.setattr(system, "cluster_status", lambda: {
        "node": "mx1.example.com", "members": 3, "errors": [],
        "database": {"size": 3, "status": "Primary", "state": "Synced"},
        "valkey": {"master": "mx2.example.com", "in_sync": 1, "expected": 1}})
    page = logged_in.get("/").data
    assert b"Cluster" in page and b"3 of 3 members" in page and b"master mx2.example.com" in page

    fake_redis.lpush("POSTFIX_MAILLOG", json.dumps({"time": str(int(time.time())), "program": "postfix/smtpd",
                                                    "message": "connect", "host": "mx2.example.com"}))
    logs = logged_in.get("/logs").data
    assert b"<th>Node</th>" in logs and b"mx2.example.com" in logs
    assert b"on mx1.example.com" in logged_in.get("/queue/").data


def test_single_gateway_pages(logged_in, backends_up, data):  # noqa: F811
    assert b"<h2>Cluster</h2>" not in logged_in.get("/").data
    assert b"<th>Node</th>" not in logged_in.get("/logs").data


# ---------------------------------------------------------------------------
# Cluster page: reports, state, maintenance, Valkey master
# ---------------------------------------------------------------------------

from datetime import timedelta  # noqa: E402

from crassostrea.extensions import db  # noqa: E402
from crassostrea.models import ClusterControl, ClusterReport, utcnow  # noqa: E402
from crassostrea.services import cluster as cluster_service, monitoring  # noqa: E402
from crassostrea.services.errors import ServiceError  # noqa: E402


def report(name, age=5, galera=None, valkey=None, probe_age=None, **extra):
    """Store a node's report as cluster-report would."""
    found = {"at": time.time() - (age if probe_age is None else probe_age), "maintenance": False,
             "valkey": valkey or {"role": "master" if name == "mx1.example.com" else "slave", "link": "up",
                                  "master": "10.0.0.1", "offset": 1000, "priority": 100},
             "sentinel": {"master": "10.0.0.1", "quorum": True, "message": "OK 3 usable Sentinels", "witness": True},
             "vip": None, "last_action": None, "promote": None}
    found.update(extra.pop("probe", {}))
    data = {"version": "abc1234", "deployed_at": int(time.time()) - 86400,
            "galera": galera or {"state": "Synced", "status": "Primary", "size": 3, "ready": True},
            "probe": found,
            "queue": {"counts": {"maildrop": 0, "incoming": 0, "active": 1, "deferred": 2, "hold": 0},
                      "oldest_deferred": 60},
            "services": [{"unit": "postfix.service", "state": "active"}], "scanned": 42,
            "load": [0.5, 0.4, 0.3], "cpus": 4, "memory_percent": 40.0,
            "disk": [{"path": "/", "used_percent": 50.0, "free_bytes": 10 ** 10}], "uptime": 3600}
    data.update(extra)
    db.session.merge(ClusterReport(hostname=name, updated_at=utcnow() - timedelta(seconds=age),
                                   data=json.dumps(data)))
    db.session.commit()


@pytest.fixture
def healthy(cluster):
    report("mx1.example.com")
    report("mx2.example.com")
    return cluster


def problem_keys(st):
    return {p["key"]: p["level"] for p in st["problems"]}


def test_healthy_cluster_state(healthy):
    st = cluster_service.state()
    assert st["level"] == "ok" and st["problems"] == []
    assert st["votes"] == {"total": 3, "quorum": 2, "present": 3}
    assert st["valkey_master"] == "mx1.example.com"
    assert st["witness"]["sentinel"] is True and st["witness"]["arbitrator"] is True
    mx1, mx2 = st["members"]
    assert mx1["self"] and not mx2["self"] and mx2["valkey"]["lag_bytes"] == 0


def test_single_gateway_has_no_cluster_state(app):
    assert cluster_service.state() is None


def test_missing_node_and_lost_vote(healthy):
    report("mx2.example.com", age=300)
    report("mx1.example.com", galera={"state": "Synced", "status": "Primary", "size": 2})
    st = cluster_service.state()
    keys = problem_keys(st)
    assert keys["node@mx2.example.com"] == "critical" and keys["database"] == "warning"
    assert "has not reported for 5 min" in st["problems"][0]["message"]
    assert st["level"] == "critical"
    # the witness still counts: two votes of three, without mx2
    assert st["witness"]["arbitrator"] is True


def test_no_majority_and_valkey_problems(healthy):
    report("mx1.example.com", galera={"state": "Initialized", "status": "non-Primary", "size": 1})
    report("mx2.example.com", galera={"state": "Initialized", "status": "non-Primary", "size": 1},
           valkey={"role": "master", "link": "", "offset": 5})
    keys = problem_keys(cluster_service.state())
    assert keys["database"] == "critical" and keys["database@mx1.example.com"] == "critical"
    assert keys["valkey"] == "critical"  # two masters
    assert keys["mail"] == "critical"  # no node in sync


def test_replica_link_witness_vip_versions_disk(healthy):
    healthy.config["CLUSTER_VIP"] = "192.0.2.10"
    report("mx2.example.com", version="def5678", galera={"state": "Synced", "status": "Primary", "size": 2},
           valkey={"role": "slave", "link": "down", "offset": 10},
           probe={"sentinel": {"quorum": False, "message": "NOQUORUM 1 usable Sentinels", "witness": False}},
           disk=[{"path": "/var", "used_percent": 95.0, "free_bytes": 1}])
    report("mx1.example.com", galera={"state": "Synced", "status": "Primary", "size": 2},
           probe={"sentinel": {"quorum": True, "message": "OK", "witness": False}})
    st = cluster_service.state()
    keys = problem_keys(st)
    assert {"valkey@mx2.example.com", "sentinel@mx2.example.com", "disk@mx2.example.com", "witness", "vip",
            "versions"} <= set(keys)
    assert "its Sentinel does not answer and the arbitrator is not in the database cluster" in \
        next(p["message"] for p in st["problems"] if p["key"] == "witness")
    assert st["vip"] == {"address": "192.0.2.10", "holders": []}


def test_versions_may_differ_during_an_update(healthy):
    report("mx2.example.com", version="def5678", deployed_at=int(time.time()) - 60)
    assert "versions" not in problem_keys(cluster_service.state())


def test_cluster_service_not_reporting(healthy):
    report("mx2.example.com", probe_age=600)
    assert problem_keys(cluster_service.state()) == {"probe@mx2.example.com": "warning"}


def test_report_once_publishes_and_requests(cluster, monkeypatch, tmp_path):
    from crassostrea.services import postfix_control, rspamd
    monkeypatch.setattr(postfix_control, "mail_queue", lambda: [
        {"queue_name": "deferred", "arrival_time": int(time.time()) - 120}])
    monkeypatch.setattr(system, "units", lambda: [{"unit": "postfix.service", "state": "failed"}])
    monkeypatch.setattr(rspamd.RspamdClient, "stat", lambda self: {"scanned": 7})
    (tmp_path / "version").write_text("v2-3-gabc\n1700000000\n")
    probe = {"at": int(time.time()), "maintenance": False, "valkey": {"role": "master", "link": "", "offset": 1}}
    (tmp_path / "cluster-probe.json").write_text(json.dumps(probe))
    request_file = tmp_path / "cluster-request"

    cluster_service._last_request.clear()
    assert cluster_service.report_once() is None and not request_file.exists()
    row = db.session.get(ClusterReport, "mx1.example.com")
    data = json.loads(row.data)
    assert data["version"] == "v2-3-gabc" and data["deployed_at"] == 1700000000
    assert data["queue"]["counts"]["deferred"] == 1 and data["queue"]["oldest_deferred"] >= 119
    assert data["services"] == [{"unit": "postfix.service", "state": "failed"}] and data["scanned"] == 7
    assert data["probe"]["valkey"]["role"] == "master" and data["galera"] is None  # sqlite

    db.session.add(ClusterControl(hostname="mx1.example.com", maintenance=True, changed_by="admin",
                                  promote_token="", changed_at=utcnow()))
    db.session.commit()
    assert cluster_service.report_once() == {"maintenance": "on"}
    assert request_file.read_text() == "maintenance=on\n"
    request_file.unlink()
    # not written again while the node applies it
    assert cluster_service.report_once() is None and not request_file.exists()
    # applied: nothing more to do
    (tmp_path / "cluster-probe.json").write_text(json.dumps({**probe, "maintenance": True}))
    assert cluster_service.report_once() is None and not cluster_service._last_request


def test_promote_request_until_done(cluster, tmp_path):
    cluster_service._last_request.clear()
    db.session.add(ClusterControl(hostname="mx1.example.com", maintenance=False, changed_by="",
                                  promote_token="0123456789abcdef", promote_at=utcnow()))
    db.session.commit()
    assert cluster_service.reconcile({"maintenance": False}) == {"promote": "0123456789abcdef"}
    assert (tmp_path / "cluster-request").read_text() == "promote=0123456789abcdef\n"
    assert cluster_service.reconcile({"promote": {"token": "0123456789abcdef", "ok": True}}) is None
    # a request that waited too long is dropped
    row = db.session.get(ClusterControl, "mx1.example.com")
    row.promote_token, row.promote_at = "fedcba9876543210", utcnow() - timedelta(minutes=10)
    db.session.commit()
    assert cluster_service.reconcile({}) is None


def test_maintenance_needs_another_node(healthy):
    report("mx2.example.com", galera={"state": "Joining", "status": "Primary", "size": 3})
    with pytest.raises(ServiceError, match="mx1.example.com is needed to accept mail"):
        cluster_service.set_maintenance("mx1.example.com", True, "admin")
    db.session.rollback()
    cluster_service.set_maintenance("MX1.example.com", True, "admin", force=True)
    db.session.commit()
    row = db.session.get(ClusterControl, "mx1.example.com")
    assert row.maintenance and row.changed_by == "admin"
    with pytest.raises(ServiceError, match="not a node"):
        cluster_service.set_maintenance("witness.example.com", True, "admin")


def test_maintenance_state_and_notice(healthy):
    cluster_service.set_maintenance("mx2.example.com", True, "admin")
    db.session.commit()
    st = cluster_service.state()
    mx2 = st["members"][1]
    assert mx2["maintenance"] and not mx2["maintenance_applied"]
    assert "mx2.example.com is in maintenance since" in st["notices"][0] and "(admin)" in st["notices"][0]
    assert st["problems"] == []  # applied within a minute
    row = db.session.get(ClusterControl, "mx2.example.com")
    row.changed_at = utcnow() - timedelta(minutes=5)
    db.session.commit()
    assert problem_keys(cluster_service.state()) == {"maintenance@mx2.example.com": "warning"}
    # every node in maintenance: no node accepts mail
    cluster_service.set_maintenance("mx1.example.com", True, "admin", force=True)
    db.session.commit()
    assert problem_keys(cluster_service.state())["mail"] == "critical"


def test_valkey_master_request(healthy):
    with pytest.raises(ServiceError, match="already is the Valkey master"):
        cluster_service.request_valkey_master("mx1.example.com", "admin")
    report("mx2.example.com", valkey={"role": "slave", "link": "down", "offset": 1})
    with pytest.raises(ServiceError, match="not connected"):
        cluster_service.request_valkey_master("mx2.example.com", "admin")
    report("mx2.example.com")
    row = cluster_service.request_valkey_master("mx2.example.com", "admin")
    db.session.commit()
    assert len(row.promote_token) == 16
    assert cluster_service.state()["members"][1]["promoting"]
    cluster_service.set_maintenance("mx2.example.com", True, "admin")
    assert row.promote_token == ""  # maintenance cancels it
    with pytest.raises(ServiceError, match="in maintenance"):
        cluster_service.request_valkey_master("mx2.example.com", "admin")


def test_cluster_page(healthy, logged_in, backends_up):  # noqa: F811
    # Monitoring → Cluster: the state, without actions
    page = logged_in.get("/cluster/").data.decode()
    assert "Healthy" in page and "3 of 3" in page and "mx2.example.com" in page and "witness.example.com" in page
    assert "arbitrator counted" in page and "Make Valkey master" not in page and 'href="/cluster/manage"' in page
    # Settings → Cluster: the actions
    page = logged_in.get("/cluster/manage").data.decode()
    assert "Make Valkey master" in page and 'class="active" aria-current="page">Cluster</a>' in page
    response = logged_in.post("/cluster/mx2.example.com/maintenance", data={"on": "1"})
    assert response.status_code == 302 and response.headers["Location"].endswith("/cluster/manage")
    assert db.session.get(ClusterControl, "mx2.example.com").maintenance
    assert "entering maintenance" in logged_in.get("/cluster/").data.decode()
    page = logged_in.get("/cluster/manage").data.decode()
    assert "entering maintenance" in page and "End maintenance" in page
    response = logged_in.post("/cluster/mx1.example.com/maintenance", data={"on": "1"}, follow_redirects=True)
    assert b"is needed to accept mail" in response.data
    logged_in.post("/cluster/mx2.example.com/maintenance", data={"on": "0"})
    assert not db.session.get(ClusterControl, "mx2.example.com").maintenance
    response = logged_in.post("/cluster/mx2.example.com/valkey-master", follow_redirects=True)
    assert b"Making mx2.example.com the Valkey master" in response.data
    # the live region alone
    fragment = logged_in.get("/cluster/manage", headers={"X-Live-Fragment": "1"}).data.decode()
    assert "<h1>" not in fragment and "becoming master" in fragment


def test_cluster_page_single_gateway(logged_in, monkeypatch):
    monkeypatch.setattr(cluster_service, "local_addresses", lambda: ["192.0.2.10"])
    page = logged_in.get("/cluster/").data.decode()
    assert "Single gateway" in page and 'href="/cluster/manage"' in page and "Create a cluster" not in page
    page = logged_in.get("/cluster/manage").data.decode()
    assert "Create a cluster" in page and "Join a cluster" in page and '<option value="192.0.2.10">' in page


def test_cluster_api(healthy, api):
    body = api("GET", "/cluster").get_json()
    assert body["cluster"] and body["level"] == "ok" and body["votes"]["present"] == 3
    assert [m["name"] for m in body["members"]] == ["mx1.example.com", "mx2.example.com"]
    assert body["members"][0]["reported_at"].endswith("Z")
    response = api("PUT", "/cluster/nodes/mx2.example.com/maintenance", json={"enabled": "yes"})
    assert response.status_code == 422
    response = api("PUT", "/cluster/nodes/mx2.example.com/maintenance", json={"enabled": True})
    assert response.status_code == 200 and response.get_json() == {"node": "mx2.example.com", "maintenance": True}
    assert api("PUT", "/cluster/nodes/mx1.example.com/maintenance", json={"enabled": True}).status_code == 409
    assert api("PUT", "/cluster/nodes/nope.example.com/maintenance", json={"enabled": True}).status_code == 404
    assert api("POST", "/cluster/nodes/mx2.example.com/valkey-master").status_code == 409  # in maintenance
    api("PUT", "/cluster/nodes/mx2.example.com/maintenance", json={"enabled": False})
    assert api("POST", "/cluster/nodes/mx2.example.com/valkey-master").status_code == 202


def test_cluster_api_single_gateway(api, monkeypatch):
    monkeypatch.setattr(cluster_service, "local_addresses", lambda: ["192.0.2.10"])
    assert api("GET", "/cluster").get_json() == {"cluster": False, "setup": None, "busy": False,
                                                 "addresses": ["192.0.2.10"]}
    assert api("PUT", "/cluster/nodes/mx1.example.com/maintenance", json={"enabled": True}).status_code == 409


def test_alerts_per_node(healthy, monkeypatch, fake_redis):
    from crassostrea.models import set_setting
    set_setting("alert_recipients", "ops@example.com")
    set_setting("alert_deferred_count", 2)
    db.session.commit()
    sent = []
    monkeypatch.setattr(monitoring, "_send", lambda recipients, failing, recovered: sent.append((failing, recovered)))
    results = monitoring.check()
    assert results["queue@mx1.example.com"]["ok"] is False and results["services@mx2.example.com"]["ok"]
    assert "queue" not in results and "services" not in results
    assert results["node@mx2.example.com"] == {"ok": True, "message": "Reports again"}
    assert monitoring.label("queue_age@mx2.example.com") == "Mail waiting (mx2.example.com)"

    failing, _ = monitoring.run_alerts()
    assert {name for name, _ in failing if "@" in name} == {"queue@mx1.example.com", "queue@mx2.example.com"}
    report("mx2.example.com", age=600)
    failing, recovered = monitoring.run_alerts()
    assert [name for name, _ in failing] == ["node@mx2.example.com"] and recovered == []
    # the checks of a node that does not report keep their state
    assert "queue@mx2.example.com" in monitoring.alert_state()
    report("mx2.example.com", queue={"counts": {"deferred": 0}, "oldest_deferred": 0})
    _, recovered = monitoring.run_alerts()
    assert {name for name, _ in recovered if "@" in name} == {"node@mx2.example.com", "queue@mx2.example.com"}


def test_cluster_metrics(healthy):
    text = monitoring.render(monitoring.collect())
    assert 'sf_cluster_member_reporting{member="mx2.example.com"} 1' in text
    assert 'sf_cluster_votes{kind="present"} 3' in text
    assert 'sf_cluster_member_valkey_master{member="mx1.example.com"} 1' in text
    assert 'sf_cluster_member_queue_messages{member="mx1.example.com",queue="deferred"} 2' in text
    assert 'sf_cluster_witness_up{component="sentinel"} 1' in text
    assert 'sf_cluster_problems{level="critical"} 0' in text


def test_cluster_report_command_needs_a_cluster(app):
    result = app.test_cli_runner().invoke(args=["cluster-report"])
    assert result.exit_code != 0 and "not part of a cluster" in result.output
