"""Hash lookups of attachments: settings with write-only keys, the map and
keys for rspamd, the Valkey script rspamd runs, lookups from the page and the API."""
import json
import os

import pytest

from crassostrea.extensions import db
from crassostrea.models import get_setting, set_setting
from crassostrea.services import hashcheck, netcheck
from crassostrea.services.maps import sync_all

SCRIPT = os.path.join(os.path.dirname(__file__), "..", "..", "conf", "rspamd", "lua", "hash_prepare.redis.lua")
EICAR_MD5 = "44d88612fea8a8f36de82e1278abb02f"
SHA = "a" * 64


class Response:
    def __init__(self, status, body):
        self.status_code, self.body = status, body

    def json(self):
        return self.body


def test_keys_are_write_only(app, api, fake_redis):
    body = api("PATCH", "/settings", json={"hashcheck_vt_key": "vt-secret-key", "hashcheck_mhr": True}).get_json()
    assert "hashcheck_vt_key" not in body and body["hashcheck_vt_key_set"] is True
    assert body["hashcheck_mb_key_set"] is False and body["hashcheck_mhr"] is True
    assert fake_redis.hgetall(hashcheck.KEYS) == {"virustotal": "vt-secret-key"}
    data = json.load(open(os.path.join(app.config["RSPAMD_MAP_DIR"], "attachment_analysis.json")))
    assert data["vt"]["enabled"] and not data["mb"]["enabled"] and data["mhr"]["enabled"]
    assert "vt-secret-key" not in json.dumps(data)
    assert api("PATCH", "/settings", json={"hashcheck_vt_key": "has spaces"}).status_code == 422
    api("PATCH", "/settings", json={"hashcheck_vt_key": ""})
    assert fake_redis.hgetall(hashcheck.KEYS) == {}


def test_prepare_script(app, fake_redis):
    script = fake_redis.register_script(open(SCRIPT).read())
    assert script(args=["100", "2", SHA]) == ["", "", "", "", "", "0"]
    fake_redis.hset(hashcheck.KEYS, mapping={"malwarebazaar": "mb", "virustotal": "vt"})
    fake_redis.set(f"sf_hash:mhr:{SHA}", "1:93% of antivirus engines")
    other, third = "b" * 64, "c" * 64
    assert script(args=["100", "2", SHA, other, third]) == [
        "mb", "vt", "1:93% of antivirus engines", "", "", "1", "", "", "", "1", "", "", "", "0"]
    # a cached VirusTotal verdict needs no request; the next minute has a new allowance
    fake_redis.set(f"sf_hash:vt:{third}", "0")
    assert script(args=["100", "2", third])[-1] == "0" and script(args=["101", "2", SHA])[-1] == "1"
    assert 0 < fake_redis.ttl("sf_vt_rate:100") <= 120


def test_lookups(app, monkeypatch):
    def lookup(name, rdtype):
        if name == f"{EICAR_MD5}.malware.hash.cymru.com":
            return ["1791835367 93"]
        raise netcheck.NoRecords(name)
    monkeypatch.setattr(netcheck, "lookup", lookup)
    monkeypatch.setattr(hashcheck.requests, "post", lambda url, **kw: Response(200, (
        {"query_status": "ok", "data": [{"signature": "AgentTesla"}]} if kw["data"]["hash"] == SHA
        else {"query_status": "hash_not_found"})))
    monkeypatch.setattr(hashcheck.requests, "get", lambda url, **kw: Response(200, {
        "data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}}) if url.endswith(SHA)
        else Response(404, {}))
    assert hashcheck.check(EICAR_MD5) == {}
    set_setting("hashcheck_mhr", 1)
    set_setting("hashcheck_mb_key", "mb")
    set_setting("hashcheck_vt_key", "vt")
    db.session.commit()
    assert hashcheck.check(EICAR_MD5.upper()) == {
        "mhr": {"malicious": True, "detail": "93% of antivirus engines"},
        "mb": {"malicious": False, "detail": "not known"}, "vt": {"malicious": False, "detail": "not known"}}
    assert hashcheck.check(SHA) == {
        "mhr": {"malicious": None, "detail": "needs the MD5 or SHA-1"},
        "mb": {"malicious": True, "detail": "AgentTesla"}, "vt": {"malicious": True, "detail": "12 engines"}}
    from crassostrea.services.errors import ServiceError
    with pytest.raises(ServiceError):
        hashcheck.check("xyz")


def test_page(app, logged_in, fake_redis):
    fake_redis.lpush(hashcheck.HITS, json.dumps({"at": 1792591519, "sha256": SHA, "file": "invoice.exe",
                                                 "source": "mhr", "detail": "93% of antivirus engines",
                                                 "from": "x@partner.example", "rcpt": "bob@example.com"}))
    page = logged_in.get("/attachments/").get_data(as_text=True)
    assert "invoice.exe" in page and "Team Cymru MHR" in page
    form = {"hash-hashcheck_mhr": "y", "hash-hashcheck_mhr_percent": "20", "hash-hashcheck_mhr_score": "15",
            "hash-hashcheck_mb_key": "mb-key", "hash-hashcheck_mb_score": "20", "hash-hashcheck_vt_key": "",
            "hash-hashcheck_vt_engines": "3", "hash-hashcheck_vt_score": "20", "hash-hashcheck_vt_per_minute": "4"}
    response = logged_in.post("/attachments/hashes", data=form, follow_redirects=True)
    assert "Hash lookups saved" in response.get_data(as_text=True)
    assert (get_setting("hashcheck_mhr_percent"), get_setting("hashcheck_mb_key")) == (20, "mb-key")
    # an empty key field keeps the key; the checkbox removes it
    logged_in.post("/attachments/hashes", data={**form, "hash-hashcheck_mb_key": ""})
    assert get_setting("hashcheck_mb_key") == "mb-key" and fake_redis.hget(hashcheck.KEYS, "malwarebazaar") == "mb-key"
    page = logged_in.get("/attachments/").get_data(as_text=True)
    assert 'placeholder="stored"' in page and "mb-key" not in page
    logged_in.post("/attachments/hashes", data={**form, "hash-hashcheck_mb_key": "", "hash-hashcheck_mb_remove": "y"})
    assert get_setting("hashcheck_mb_key") == ""
    response = logged_in.post("/attachments/hashes/check", data={"check-hash": "nothex"})
    assert response.status_code == 400 and "MD5, SHA-1 or SHA-256" in response.get_data(as_text=True)


def test_api(api, fake_redis, monkeypatch):
    fake_redis.lpush(hashcheck.HITS, json.dumps({"at": 1, "sha256": SHA, "file": "a.exe", "source": "vt",
                                                 "detail": "12 engines", "from": "", "rcpt": ""}))
    assert api("GET", "/hash-detections").get_json()["items"][0]["file"] == "a.exe"
    assert api("POST", "/hash-lookup", json={"hash": SHA}).get_json() == {}
    assert api("POST", "/hash-lookup", json={"hash": "zz"}).status_code == 422


def test_sync_survives_valkey_errors(app, monkeypatch):
    import redis as redis_module
    from crassostrea.services import store

    class Broken:
        def __getattr__(self, name):
            raise redis_module.ConnectionError("down")
    monkeypatch.setattr(store, "get_redis", lambda: Broken())
    assert sync_all() is False
    assert os.path.exists(os.path.join(app.config["RSPAMD_MAP_DIR"], "attachment_analysis.json"))
