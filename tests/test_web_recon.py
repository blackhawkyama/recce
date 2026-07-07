"""Web-surface recon tests — fully offline. Deterministic tools run for real;
network tools run in simulate mode; the agent loop drives a domain recon with a
scripted fake model and concludes with a filled `surface`."""

from __future__ import annotations

from types import SimpleNamespace

from recce.agent import Agent
from recce.recon.tools import build_registry
from recce.recon.web import _split_hosts, triage_hosts
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
