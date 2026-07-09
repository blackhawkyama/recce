"""Web-surface recon tests — fully offline. Deterministic tools run for real;
network tools run in simulate mode; the agent loop drives a domain recon with a
scripted fake model and concludes with a filled `surface`."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from recce.agent import Agent
from recce.recon.tools import build_registry
from recce.recon.web import _split_hosts, rank_hosts, triage_hosts
from recce.report import render_writeup
from recce.types import ReconFindings, Surface


# --- fake client (mirrors test_agent) -------------------------------------


def use(tid, name, inp):
    return SimpleNamespace(type="tool_use", id=tid, name=name, input=inp)


def txt(t):
    return SimpleNamespace(type="text", text=t)


def resp(content, stop="tool_use"):
    return SimpleNamespace(content=content, stop_reason=stop)


class FakeClient:
    def __init__(self, script):
        self.messages = SimpleNamespace(
            calls=[],
            create=lambda **kw: (self.messages.calls.append(kw), script.pop(0))[1],
        )


# --- deterministic triage (real function, no network) ---------------------


def test_triage_ranks_interesting_hosts_first():
    hosts = "www.acme.example\nshop.acme.example\ndev.acme.example\napi-admin.acme.example"
    out = triage_hosts(hosts)
    # api-admin has two interesting tags → ranked above single-tag dev.
    prio = out.split("PRIORITISE")[1]
    assert prio.index("api-admin") < prio.index("dev.acme.example")
    # boring hosts land in the 'rest' bucket, not prioritised.
    assert "www.acme.example" in out.split("rest:")[1]


def test_triage_tags_the_keyword():
    out = triage_hosts("jenkins-ci.acme.example")
    assert "jenkins" in out and "ci" in out


def test_split_hosts_normalises_urls_and_dedups():
    got = _split_hosts("https://A.com:443/path,  a.com  http://b.com/ b.com")
    assert got == ["a.com", "b.com"]


def test_triage_empty_input():
    assert "No hostnames" in triage_hosts("   ")


def test_rank_hosts_structured():
    tagged, plain = rank_hosts(["api.x.com", "www.x.com", "dev-admin.x.com"])
    assert plain == ["www.x.com"]
    assert tagged[0][0] == "dev-admin.x.com"  # two tags → ranked first
    assert set(tagged[0][1]) == {"dev", "admin"}


# --- keyless passive sweep (CLI, offline via monkeypatch) -----------------


def test_cmd_sweep_writes_surface_writeup(tmp_path, monkeypatch):
    import recce.recon.web as web
    from recce.cli import build_parser

    monkeypatch.setattr(web, "collect_subdomains",
                        lambda d: (["api.x.com", "www.x.com", "vpn.x.com"], ["crt.sh"]))
    monkeypatch.setattr(web, "collect_wayback",
                        lambda d, limit=200: (["https://x.com/a"], ["https://x.com/admin?id=1"]))
    args = build_parser().parse_args(["sweep", "x.com", "-o", str(tmp_path)])
    assert args.func(args) == 0
    md = next(tmp_path.glob("*-sweep-*.md")).read_text()
    assert "## Attack surface" in md
    assert "api.x.com" in md and "vpn.x.com" in md
    assert "admin?id=1" in md
    assert next(tmp_path.glob("*-sweep-*.json")).exists()


def test_cmd_sweep_nothing_found_returns_1(tmp_path, monkeypatch):
    import recce.recon.web as web
    from recce.cli import build_parser

    monkeypatch.setattr(web, "collect_subdomains", lambda d: ([], []))
    args = build_parser().parse_args(["sweep", "x.com", "-o", str(tmp_path), "--no-wayback"])
    assert args.func(args) == 1


# --- fingerprint_waf core + `vet` triage (offline via monkeypatch) --------


def test_fingerprint_waf_reads_headers(monkeypatch):
    import recce.recon.web as web

    def fake_get(url, timeout=8, read=4096):
        return 403, {"server": "cloudflare", "cf-ray": "abc", "set-cookie": "__cf_bm=x"}, ""

    monkeypatch.setattr(web, "_get", fake_get)
    info = web.fingerprint_waf("api.x.com")
    assert info["status"] == 403 and "Cloudflare" in info["detected"]
    assert info["challenge"] is True


def test_fingerprint_waf_unreachable(monkeypatch):
    import recce.recon.web as web
    monkeypatch.setattr(web, "_get", lambda url, timeout=8, read=4096: (None, {}, "(err)"))
    assert "error" in web.fingerprint_waf("dead.x.com")


def _fake_fp(host):
    # dev-* is clean/alive; admin-* is Cloudflare-guarded; ghost-* is dead.
    if host.startswith("ghost"):
        return {"host": host, "error": "unreachable on https/http"}
    if host.startswith("admin"):
        return {"host": host, "scheme": "https", "status": 403, "server": "cloudflare",
                "detected": ["Cloudflare"], "heavy": [], "challenge": True, "verdict": "waf"}
    return {"host": host, "scheme": "https", "status": 200, "server": "nginx",
            "detected": [], "heavy": [], "challenge": False, "verdict": "clean"}


def test_vet_requires_authorized(tmp_path):
    from recce.cli import build_parser
    args = build_parser().parse_args(["vet", "x.com", "-o", str(tmp_path)])
    with pytest.raises(SystemExit):
        args.func(args)


def test_vet_from_domain_triages_and_writes(tmp_path, monkeypatch):
    import recce.recon.web as web
    from recce.cli import build_parser

    monkeypatch.setattr(web, "collect_subdomains",
                        lambda d: (["dev.x.com", "admin.x.com", "ghost.x.com", "www.x.com"], ["crt.sh"]))
    monkeypatch.setattr(web, "fingerprint_waf", _fake_fp)
    args = build_parser().parse_args(["vet", "x.com", "--authorized", "-o", str(tmp_path)])
    assert args.func(args) == 0
    md = next(tmp_path.glob("*-vet-*.md")).read_text()
    assert "WAF triage detail" in md
    assert "Clean & alive" in md and "dev.x.com" in md
    assert "Cloudflare" in md  # admin host shows guarded


def test_vet_exclude_filters_out_of_scope(tmp_path, monkeypatch):
    import recce.recon.web as web
    from recce.cli import build_parser

    seen = []
    monkeypatch.setattr(web, "collect_subdomains",
                        lambda d: (["dev.x.com", "customer.isp.x.com"], ["crt.sh"]))
    monkeypatch.setattr(web, "fingerprint_waf", lambda h: seen.append(h) or _fake_fp(h))
    args = build_parser().parse_args(
        ["vet", "x.com", "--authorized", "--exclude", "customer.", "-o", str(tmp_path)])
    assert args.func(args) == 0
    assert "dev.x.com" in seen and not any("customer." in h for h in seen)


# --- web tools are wired into the registry --------------------------------


def test_web_tools_registered():
    reg = build_registry(simulate=True)
    for name in ("subdomain_enum", "triage_hosts", "http_probe", "waf_check", "wayback_urls"):
        assert name in reg
    # host tools still present.
    assert "nmap_scan" in reg and "ftp_anon" in reg


def test_simulated_web_tools_run():
    reg = build_registry(simulate=True)
    assert "subdomains for acme.example" in reg.run("subdomain_enum", {"domain": "acme.example"}).output
    assert reg.run("waf_check", {"target": "acme.example"}).ok
    assert "responded" in reg.run("http_probe", {"targets": "a.com b.com"}).output
    assert "historical URLs" in reg.run("wayback_urls", {"domain": "acme.example"}).output


# --- a full domain-recon loop that fills the surface ----------------------


DOMAIN_CONCLUDE = {
    "summary": "acme.example exposes a dev host and an unauthenticated Jenkins.",
    "surface": {
        "subdomains": ["www.acme.example", "dev.acme.example", "jenkins-ci.acme.example"],
        "live_hosts": ["www.acme.example", "dev.acme.example", "jenkins-ci.acme.example"],
        "priority_hosts": ["jenkins-ci.acme.example", "dev.acme.example"],
        "notable_urls": ["https://dev.acme.example/admin/config.json"],
        "waf_notes": "Cloudflare on www only; dev/jenkins unprotected.",
    },
    "hypotheses": [
        {
            "title": "Exposed Jenkins dashboard",
            "service": "http/jenkins-ci",
            "evidence": "http_probe: 200 jenkins-ci … 'Dashboard [Jenkins]'",
            "rationale": "An unauthenticated Jenkins often allows script-console RCE.",
            "suggested_next_step": "browse https://jenkins-ci.acme.example/ — check /script auth",
            "confidence": "high",
        }
    ],
}


def _domain_client():
    return FakeClient(
        [
            resp([txt("Domain target — going passive first."),
                  use("t1", "subdomain_enum", {"domain": "acme.example"})]),
            resp([use("t2", "triage_hosts", {"hosts": "www.acme.example dev.acme.example jenkins-ci.acme.example"})]),
            resp([use("t3", "waf_check", {"target": "www.acme.example"})]),
            resp([use("t4", "http_probe", {"targets": "www.acme.example dev.acme.example jenkins-ci.acme.example"})]),
            resp([use("t5", "conclude", DOMAIN_CONCLUDE)]),
        ]
    )


def test_domain_recon_loop_fills_surface():
    agent = Agent(build_registry(simulate=True), client=_domain_client(), max_steps=10)
    run = agent.run("acme.example", authorized=True)
    assert run.stopped_reason == "concluded"
    assert run.findings.surface is not None
    assert "jenkins-ci.acme.example" in run.findings.surface.priority_hosts
    assert run.tool_calls() == 4  # subdomain, triage, waf, probe (conclude isn't a tool step)


def test_surface_renders_in_writeup():
    findings = ReconFindings.model_validate(DOMAIN_CONCLUDE)
    run = SimpleNamespace(
        findings=findings, target="acme.example", created_at="now", model="m",
        stopped_reason="concluded", tool_calls=lambda: 4,
    )
    md = render_writeup(run)
    assert "## Attack surface" in md
    assert "Priority hosts" in md and "jenkins-ci.acme.example" in md
    assert "Cloudflare" in md


def test_surface_optional_for_host_runs():
    # A host run with no surface must still validate and render cleanly.
    f = ReconFindings(summary="host box", open_ports=[{"port": 22, "service": "ssh"}])
    assert f.surface is None
    run = SimpleNamespace(findings=f, target="10.0.0.1", created_at="now", model="m",
                          stopped_reason="concluded", tool_calls=lambda: 1)
    assert "## Attack surface" not in render_writeup(run)
