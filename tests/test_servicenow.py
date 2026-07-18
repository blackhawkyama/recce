"""ServiceNow recon tests — fully offline. Pure classification runs for real; the
network-touching fingerprint/probe run against a monkeypatched `_get` that returns
canned HTTP responses, so no packets leave the machine. The central discipline —
the ACL probe requests only sys_id and never surfaces field values — is asserted."""

from __future__ import annotations

import json

import pytest

from recce.recon import servicenow as sn
from recce.recon.servicenow import (
    _classify,
    acl_probe,
    build_servicenow_tools,
    fingerprint_instance,
    servicenow_acl_probe,
    servicenow_fingerprint,
)
from recce.recon.tools import build_registry, service_intel


# --- pure classification (no network) -------------------------------------


@pytest.mark.parametrize(
    "status,body,signal",
    [
        (200, '{"result": [{"sys_id": "abc"}]}', "READABLE-UNAUTH"),
        (200, '{"result": []}', "READABLE-UNAUTH"),
        (401, "", "requires-auth"),
        (302, "", "requires-auth"),
        (403, "", "blocked"),
        (404, "", "no-such-table"),
        (None, "", "unreachable"),
        (200, "<html>not json</html>", "200-non-json"),
    ],
)
def test_classify_maps_status_to_signal(status, body, signal):
    got, _rows = _classify(status, body)
    assert got == signal


def test_classify_reports_row_count_not_values():
    _sig, rows = _classify(200, '{"result": [{"sys_id": "a"}, {"sys_id": "b"}]}')
    assert rows == 2


# --- fingerprint (monkeypatched network) ----------------------------------


def _fake_get(mapping, default=(None, {}, "")):
    """Build a _get stand-in that dispatches on a substring of the URL."""
    def _g(url, timeout=8, read=4096):
        for needle, resp in mapping.items():
            if needle in url:
                return resp
        return default
    return _g


def test_fingerprint_reads_public_stats(monkeypatch):
    stats = "Instance name: acme\nBuild name: Xanadu\nBuild date: 06-19-2025\nCurrent node: app1.iad"
    monkeypatch.setattr(sn, "_get", _fake_get({
        "/stats.do": (200, {}, stats),
        "://": (200, {"set-cookie": "glide_user_route=abc; path=/"}, "<html>glide.ui</html>"),
    }))
    info = fingerprint_instance("acme.service-now.com")
    assert info["is_servicenow"] is True
    assert info["instance"] == "acme"
    assert info["build"] == "Xanadu"
    assert info["stats_public"] is True
    assert "stats.do:public" in info["markers"]


def test_fingerprint_unreachable_is_error(monkeypatch):
    monkeypatch.setattr(sn, "_get", _fake_get({}, default=(None, {}, "(timeout)")))
    info = fingerprint_instance("nope.service-now.com")
    assert "error" in info
    res = servicenow_fingerprint("nope.service-now.com")
    assert res.ok is False


# --- ACL probe (monkeypatched network) ------------------------------------


def test_acl_probe_flags_exposed_tables(monkeypatch):
    # sys_user + sys_db_object readable; everything else needs auth.
    def _g(url, timeout=8, read=4096):
        if "sys_user" in url and "sys_user_group" not in url:
            return (200, {}, '{"result": [{"sys_id": "u1"}]}')
        if "sys_db_object" in url:
            return (200, {}, '{"result": [{"sys_id": "t1"}]}')
        return (401, {}, "")
    monkeypatch.setattr(sn, "_get", _g)

    info = acl_probe("acme.service-now.com")
    exposed = {r["table"] for r in info["readable"]}
    assert exposed == {"sys_user", "sys_db_object"}


def test_acl_probe_requests_only_sys_id(monkeypatch):
    """The ethical core: every probe URL must scope to sys_id and one row, so no
    PII field is ever requested."""
    seen: list[str] = []

    def _g(url, timeout=8, read=4096):
        seen.append(url)
        return (401, {}, "")
    monkeypatch.setattr(sn, "_get", _g)

    acl_probe("acme.service-now.com")
    assert seen, "probe should issue requests"
    for url in seen:
        assert "sysparm_fields=sys_id" in url
        assert "sysparm_limit=1" in url


def test_probe_output_never_prints_field_values(monkeypatch):
    """Even when a table is exposed, the rendered output must not carry record data
    beyond a count — the response body could contain a value; assert it doesn't leak."""
    leaked = "totally-secret-email@victim.example"

    def _g(url, timeout=8, read=4096):
        # A hostile/verbose 200 that includes a value the tool must never echo.
        return (200, {}, json.dumps({"result": [{"sys_id": "x", "email": leaked}]}))
    monkeypatch.setattr(sn, "_get", _g)

    out = servicenow_acl_probe("acme.service-now.com").output
    assert leaked not in out
    assert "EXPOSED" in out


def test_acl_probe_custom_table_list(monkeypatch):
    seen: list[str] = []

    def _g(url, timeout=8, read=4096):
        seen.append(url)
        return (401, {}, "")
    monkeypatch.setattr(sn, "_get", _g)

    servicenow_acl_probe("acme.service-now.com", tables="incident, cmdb_ci")
    tables_hit = [u for u in seen]
    assert any("/table/incident" in u for u in tables_hit)
    assert any("/table/cmdb_ci" in u for u in tables_hit)
    assert not any("/table/sys_user?" in u for u in tables_hit)


# --- registry / intel integration -----------------------------------------


def test_servicenow_tools_registered():
    reg = build_registry(simulate=False)
    assert "servicenow_fingerprint" in reg
    assert "servicenow_acl_probe" in reg


def test_sim_tools_return_canned_output():
    tools = {t.name: t for t in build_servicenow_tools(simulate=True)}
    fp = tools["servicenow_fingerprint"].run({"target": "x"})
    assert fp.ok and "ServiceNow confirmed" in fp.output
    probe = tools["servicenow_acl_probe"].run({"target": "x"})
    assert probe.ok and "EXPOSED" in probe.output


def test_service_intel_has_servicenow_entry():
    out = service_intel("servicenow")
    assert "table ACL" in out or "Table REST API" in out
