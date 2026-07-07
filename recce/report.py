"""Render a run two ways: the reasoning trail (what the agent did, step by step)
and a publish-ready write-up (recon → finding → impact → remediation)."""

from __future__ import annotations

from recce.types import ReconRun

# Generic, service-keyed remediation lines for the write-up's remediation section.
_REMEDIATION = {
    "ftp": "Disable anonymous FTP; require authentication; don't expose FTP publicly.",
    "telnet": "Disable Telnet entirely; use SSH with key auth.",
    "smb": "Disable null/guest sessions; restrict shares; patch SMB.",
    "redis": "Require AUTH, bind to localhost, enable protected-mode; never expose publicly.",
    "http": "Remove exposed admin paths and .git; enforce auth; keep the stack patched.",
    "ssh": "Key-only auth, no root login, fail2ban; keep OpenSSH patched.",
    "mysql": "No remote root; strong passwords; bind to localhost where possible.",
    "rsync": "Require auth on modules; restrict read/write; don't expose publicly.",
    "nfs": "Restrict exports by host; no world-writable exports; use NFSv4 + auth.",
}


def render_journal(run: ReconRun) -> str:
    lines = [f"Recon trail — {run.target}  (model {run.model})"]
    for s in run.steps:
        if s.kind == "assistant":
            lines.append(f"\n[think] {s.text}")
        else:
            r = s.tool_result
            status = "ok" if (r and r.ok) else "ERR"
            arg = " ".join(f"{k}={v}" for k, v in s.tool_input.items())
            lines.append(f"[tool] {s.tool_name}({arg}) -> {status}")
            if r:
                body = (r.output if r.ok else (r.error or "")).strip().splitlines()
                for bl in body[:6]:
                    lines.append(f"       {bl}")
                if len(body) > 6:
                    lines.append(f"       …(+{len(body) - 6} lines)")
    lines.append(f"\nstopped: {run.stopped_reason}")
    return "\n".join(lines)


def render_writeup(run: ReconRun) -> str:
    f = run.findings
    if f is None:
        return f"# Recon — {run.target}\n\n_No findings (stopped: {run.stopped_reason})._"

    out = [
        f"# Recon — {run.target}",
        f"\n_Drafted by recce · {run.created_at} · model {run.model} · "
        f"{run.tool_calls()} tool calls_",
        "\n## Summary",
        f.summary or "_(none)_",
    ]

    if f.open_ports:
        out += ["\n## Open ports", "", "| Port | Service | Version |", "|---|---|---|"]
        for p in f.open_ports:
            out.append(f"| {p.port} | {p.service} | {p.version or '—'} |")

    s = f.surface
    if s and (s.subdomains or s.live_hosts or s.priority_hosts or s.notable_urls or s.waf_notes):
        out.append("\n## Attack surface")
        if s.waf_notes:
            out.append(f"- **WAF/CDN:** {s.waf_notes}")
        if s.subdomains:
            out.append(f"- **Subdomains discovered ({len(s.subdomains)}):** "
                       + ", ".join(s.subdomains[:25])
                       + (" …" if len(s.subdomains) > 25 else ""))
        if s.live_hosts:
            out.append(f"- **Live hosts ({len(s.live_hosts)}):** " + ", ".join(s.live_hosts[:25]))
        if s.priority_hosts:
            out += ["- **Priority hosts (test first):**",
                    *[f"  - `{h}`" for h in s.priority_hosts]]
        if s.notable_urls:
            out += ["- **Notable URLs:**", *[f"  - `{u}`" for u in s.notable_urls[:15]]]

    out.append("\n## Foothold hypotheses (ranked)")
    if not f.hypotheses:
        out.append("_No hypotheses formed._")
    order = {"high": 0, "medium": 1, "low": 2}
    ranked = sorted(f.hypotheses, key=lambda h: order.get(h.confidence.value, 1))
    for i, h in enumerate(ranked, 1):
        out += [
            f"\n### {i}. {h.title}  _({h.confidence.value} confidence)_",
            f"- **Service:** {h.service}",
            f"- **Recon evidence:** {h.evidence}",
            f"- **Why it's a likely foothold (impact):** {h.rationale}",
            f"- **Suggested next step:** `{h.suggested_next_step}`",
        ]

    # Remediation, keyed off the services that came up.
    seen = {p.service.lower() for p in f.open_ports}
    seen |= {h.service.split("/")[0].lower() for h in f.hypotheses}
    rem = [f"- **{svc}** — {_REMEDIATION[key]}"
           for svc in sorted(seen)
           for key in [next((k for k in _REMEDIATION if k in svc), "")]
           if key]
    if rem:
        out += ["\n## Remediation", *rem]

    out += [
        "\n---",
        "_recce performs reconnaissance only. Hypotheses and suggested steps are "
        "for a human operator to validate and execute in an authorized engagement._",
    ]
    return "\n".join(out)
