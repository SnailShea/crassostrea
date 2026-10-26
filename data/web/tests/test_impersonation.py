"""Impersonation checks: the detectors (also against the Lua ones), protected
people, the map for rspamd, the page and the API."""
import json
import os
import shutil
import subprocess

import pytest

from crassostrea.extensions import db
from crassostrea.models import Domain, set_setting
from crassostrea.services import filters, impersonation
from crassostrea.services.errors import ServiceError

LUA = os.path.join(os.path.dirname(__file__), "..", "..", "conf", "rspamd", "lua", "impersonation.lua")
PROTECTED = ["example.com", "contoso.co.uk", "bigbank.com", "acme.io"]
DOMAINS = {
    "examp1e.com": "example.com", "example.net": "example.com", "exarnple.com": "example.com",
    "exampel.com": "example.com", "example.com.evil.test": "example.com", "mail.example.com": None,
    "contoso.com": "contoso.co.uk", "c0ntoso.co.uk": "contoso.co.uk", "bigbamk.com": "bigbank.com",
    "bigbank-secure.com": "bigbank.com", "acne.io": None, "other.org": None, "еxample.com": "example.com",
    "xample.com": "example.com", "examples.com": "example.com", "EXAMPLE.COM.": None, "partner.example": None,
}
NAMES = {("Jane Doe", "Jane Doe"): True, ('"Doe, Jane"', "Jane Doe"): True, ("Jane Doe (CEO)", "jane doe"): True,
         ("Janet Doe", "Jane Doe"): False, ("JANE  DOE via LinkedIn", "Jane Doe"): True, ("Jane", "Jane Doe"): False,
         ("J. Doe", "Jane Doe"): False, ("Dr. Jane Doe", "Jane Doe"): True}


@pytest.mark.parametrize("domain, expected", sorted(DOMAINS.items()))
def test_lookalike(domain, expected):
    assert impersonation.lookalike(domain, PROTECTED, {"partner.example"}) == expected


@pytest.mark.parametrize("display, name", sorted(NAMES))
def test_name_matches(display, name):
    assert impersonation.name_matches(display, name) is NAMES[(display, name)]


@pytest.mark.skipif(not shutil.which("rspamadm"), reason="rspamd is not installed")
def test_lua_detectors_agree(tmp_path):
    data = tmp_path / "data.json"
    data.write_text(json.dumps({"domains": sorted(DOMAINS), "protected": PROTECTED,
                                "names": [list(k) for k in sorted(NAMES)]}))
    script = tmp_path / "check.lua"
    script.write_text(f"""
local d = dofile({json.dumps(os.path.abspath(LUA))})
local ucl = require "ucl"
local parser = ucl.parser()
assert(parser:parse_file({json.dumps(str(data))}))
local input = parser:get_object()
local out = {{domains = {{}}, names = {{}}}}
for _, domain in ipairs(input.domains) do
  out.domains[domain] = d.lookalike(domain, input.protected, {{['partner.example'] = true}}) or false
end
for _, pair in ipairs(input.names) do
  out.names[#out.names + 1] = d.name_matches(pair[1], pair[2])
end
print(ucl.to_format(out, 'json'))
""")
    result = subprocess.run(["rspamadm", "lua", str(script)], capture_output=True, text=True, timeout=60,
                            cwd=tmp_path, check=False)
    found = json.loads(result.stdout[result.stdout.index("{"):])
    assert {k: v or None for k, v in found["domains"].items()} == DOMAINS
    assert found["names"] == [NAMES[k] for k in sorted(NAMES)]


def test_people_and_map(app):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    person = impersonation.add_person("  Jane   Doe ", "Jane.Doe@Gmail.com, jd@home.example")
    db.session.commit()
    assert (person.name, person.addresses) == ("Jane Doe", "jane.doe@gmail.com\njd@home.example")
    with pytest.raises(ServiceError) as exc:
        impersonation.add_person("jane doe")
    assert exc.value.status == 409
    for bad in ({"name": "J"}, {"name": "Jo Do", "addresses": "not-an-address"}):
        with pytest.raises(ServiceError):
            impersonation.add_person(**bad)
    db.session.rollback()
    filters.update_settings(impersonation_extra_domains="Brand.example", impersonation_exempt_domains="example.net",
                            impersonation_spoof_score=0)
    db.session.commit()
    data = json.loads(impersonation.build_json())
    assert data == {"people": [{"name": "Jane Doe", "addresses": ["jane.doe@gmail.com", "jd@home.example"]}],
                    "domains": ["brand.example", "example.com"], "exempt": ["example.net"],
                    "scores": {"name": 6.0, "lookalike": 6.0, "spoof": 0.0}}
    for changes in ({"impersonation_name_score": -1}, {"impersonation_spoof_score": "high"},
                    {"impersonation_extra_domains": "not a domain!"}):
        with pytest.raises(ServiceError):
            filters.update_settings(**changes)
    db.session.rollback()


def test_sender_test(app):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    impersonation.add_person("Jane Doe", "jane.doe@gmail.com")
    set_setting("impersonation_exempt_domains", "example.net")
    db.session.commit()
    result = impersonation.test("Jane Doe", "ceo@freemail.example")
    assert result["name"].name == "Jane Doe" and not result["own_domain"] and result["lookalike"] is None
    assert impersonation.test("Jane Doe", "jane.doe@gmail.com")["name"] is None
    assert impersonation.test("Jane Doe", "jane@example.com") == {"name": None, "own_domain": True,
                                                                   "lookalike": None}
    assert impersonation.test("", "billing@examp1e.com")["lookalike"] == "example.com"
    assert impersonation.test("", "billing@example.net")["lookalike"] is None


def test_page(app, logged_in):
    db.session.add(Domain(name="example.com", destination_host="mx.internal"))
    db.session.commit()
    response = logged_in.post("/impersonation/people", data={"person-name": "Jane Doe",
                                                             "person-addresses": "jane.doe@gmail.com"},
                              follow_redirects=True)
    assert "Jane Doe is protected" in response.get_data(as_text=True)
    path = os.path.join(app.config["RSPAMD_MAP_DIR"], "impersonation.json")
    assert json.load(open(path))["people"][0]["name"] == "Jane Doe"
    response = logged_in.post("/impersonation/settings", data={
        "impersonation_name_score": "15", "impersonation_lookalike_score": "4.5", "impersonation_spoof_score": "0",
        "impersonation_extra_domains": "brand.example", "impersonation_exempt_domains": ""}, follow_redirects=True)
    assert "Impersonation checks saved" in response.get_data(as_text=True)
    assert json.load(open(path))["scores"] == {"name": 15.0, "lookalike": 4.5, "spoof": 0.0}
    page = logged_in.post("/impersonation/test", data={"test-display_name": "Doe, Jane",
                                                       "test-address": "jane@exarnple.com"}).get_data(as_text=True)
    assert '<span class="badge bad">Jane Doe</span>' in page and "imitates example.com" in page
    assert 'href="/impersonation/" class="active"' in page
    person = impersonation.people()[0]
    logged_in.post(f"/impersonation/people/{person.id}/delete")
    assert json.load(open(path))["people"] == []


def test_api(api):
    response = api("POST", "/protected-people", json={"name": "Jane Doe", "addresses": ["jane.doe@gmail.com"]})
    assert response.status_code == 201
    person_id = response.get_json()["id"]
    assert api("POST", "/protected-people", json={"name": "JANE DOE"}).status_code == 409
    body = api("PATCH", f"/protected-people/{person_id}", json={"addresses": []}).get_json()
    assert body["addresses"] == []
    result = api("POST", "/impersonation/test", json={"name": "Jane Doe", "address": "x@freemail.example"})
    assert result.get_json() == {"person": "Jane Doe", "own_domain": False, "lookalike": None}
    assert api("POST", "/impersonation/test", json={"address": "nope"}).status_code == 422
    assert api("PATCH", "/settings", json={"impersonation_lookalike_score": 0}).get_json()[
        "impersonation_lookalike_score"] == 0
    assert api("DELETE", f"/protected-people/{person_id}").status_code == 204
