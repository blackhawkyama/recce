# recce

An **autonomous reconnaissance agent** for authorized targets. Point it at a box
or a domain you're allowed to test; it runs a real agent loop — plan → enumerate
with read-only tools → reason over what it finds → form ranked foothold
hypotheses — and drafts a `recon → finding → impact → remediation` write-up.

It reads the target's shape and reconnoiters accordingly: a **single host/IP**
(an HTB/CTF box) gets drilled service-by-service; a **domain** (a bug-bounty
program) gets its wide surface mapped **passive-first** — subdomains from public
cert/DNS data, interesting-host triage, a bot-WAF pre-check, then a gentle
alive-probe — the way real bounty recon works.

> ⚠️ **Reconnaissance only. Authorized targets only.** recce enumerates and
> *proposes*; it never exploits. The loop stops at "here's the attack path and
> the command I'd run next," and a human decides whether to act. A real scan
> refuses to run without an explicit `--authorized` acknowledgement. Use it only
> on systems you own or are explicitly permitted to test (HTB/CTF machines, your
> own lab, a sanctioned engagement).

> **Built with AI assistance.** I designed and directed this project and its
> architecture; the implementation was written with an AI coding assistant
> (Claude Code).

## Why it's an *agent*, not a script

The model isn't called once — it drives a loop, and three things make that
orchestration real:

- **Tool-use loop** — it picks the next read-only tool based on what the last one
  actually returned (scan → see FTP → check anonymous login → look it up), rather
  than firing everything blindly.
- **Failure recovery** — a tool that errors (missing binary, timeout, refused
  connection) comes back as a normal result the agent reasons about; an API
  failure ends the run cleanly. One broken tool never crashes the run.
- **Structured termination** — it finishes by calling a `conclude` tool whose
  input is validated against a schema, so the hand-off is *data* (ranked
  hypotheses with evidence and a suggested next step), not free text.

The agent core (loop, tool registry, journal) is decoupled from the recon
toolset, so the same engine can drive other multi-step jobs.

## Quickstart

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"

pytest                              # full loop, offline (fake model, no key)

# Canned demo box (still calls the model — needs ANTHROPIC_API_KEY):
recce scan demo --simulate

# Real target you're authorized to test (needs nmap etc. + a key):
recce scan 10.10.10.10 --authorized
```

### Keyless recon (no model, no API key)

Two commands run the passive/gentle recon pipeline directly — handy for unattended
sweeps and for feeding a bug-bounty hunt:

```bash
# PASSIVE surface map — crt.sh + passive DNS + Wayback + triage. Safe on any domain.
recce sweep example.com

# ACTIVE-but-gentle WAF + liveness triage of the priority hosts from a sweep.
# One GET per host; --authorized gated; --exclude drops out-of-scope patterns.
recce vet runs/example.com-sweep-*.json --authorized --limit 20 --exclude customer.
```

`sweep → vet` gives you a ranked, WAF-vetted target list (clean & alive hosts to
test first) before you spend a minute in Burp.

Every run saves a JSON artifact and a Markdown write-up under `runs/`. Re-render
either later:

```bash
recce replay runs/<id>.json            # the write-up
recce replay runs/<id>.json --journal  # the step-by-step reasoning trail
```

## What a run produces

- **A reasoning trail** — every step: the agent's narration, each tool call, and
  its result. This is the audit log a reviewer reads to see *how* it concluded.
- **A write-up draft** — summary, open ports, ranked foothold hypotheses (each
  with evidence, impact, and the next command a human should try), and
  remediation. Ready to edit and publish.

## The recon tools (all read-only)

**Host tools** — drill a single box:

| Tool | What it does |
|---|---|
| `nmap_scan` | service/version scan (`nmap -sV`) |
| `http_enum` | headers, title, common paths (robots.txt, /admin, /.git) |
| `ftp_anon` | test anonymous FTP login, list the root |
| `smb_enum` | list SMB shares via a null session |
| `service_intel` | look up known common misconfigs + enumeration steps for a service (grounds hypotheses in fact, not invention) |

**Web tools** — map the wide surface of a domain, bug-bounty style, and respect
`THE LINE` (passive reads are safe anywhere; active probes are in-scope-only and
gentle):

| Tool | Line | What it does |
|---|---|---|
| `subdomain_enum` | passive | subdomains from cert transparency (crt.sh) + passive DNS (hackertarget) |
| `triage_hosts` | *no network* | rank hosts by attack-surface interest — dev/stage/api/admin/internal/vpn float up; the apex brand never inflates the score |
| `waf_check` | active (1 req) | fingerprint a bot-WAF/CDN before investing time; heavy WAF ⇒ deprioritise |
| `http_probe` | active, gentle | which hosts are alive — status, Server, title; capped + short-timeout |
| `wayback_urls` | passive | historical URLs from the Wayback CDX, interesting ones surfaced |

Web tools are pure stdlib (no extra binaries) and verify TLS with a real CA
bundle (`certifi`) so passive HTTPS recon works on any machine. Host tools shell
out and **degrade gracefully** when a binary or the network isn't there.
`--simulate` swaps in canned outputs for a coherent demo (a host box *and* a demo
domain), so the whole loop runs with no network, no nmap, and no root.

## Layout

```
recce/
  types.py         Pydantic model: Port / Surface / Hypothesis / ReconFindings / Step / ReconRun
  tools.py         Tool + ToolRegistry (the reusable agent-core hands)
  agent.py         the loop: plan → tool-use → observe → conclude, with recovery
  recon/tools.py   host recon tools (nmap/ftp/smb) + service-intel + simulate mode
  recon/web.py     web-surface recon (subdomain/triage/probe/waf/wayback), passive-first
  report.py        render the write-up (incl. the attack-surface map) and the trail
  cli.py           recce scan | replay  (with the authorization gate)
tests/             offline suite — fake model + simulated tools
```

## Status

v0.2 — agent core (loop, tool registry, journal); **two recon halves** (host
drill + passive-first web-surface mapping) in one registry the agent picks from by
target shape; structured hand-off with an attack-surface map; write-up renderer;
CLI with an authorization gate; tested offline (22 tests). Next: a live HTB run,
optional subfinder/amass depth with API keys, and tightening the hypothesis
prompt.
