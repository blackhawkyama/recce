# recce

An **autonomous reconnaissance agent** for authorized targets. Point it at a box
you're allowed to test; it runs a real agent loop — plan → enumerate with
read-only tools → reason over what it finds → form ranked foothold hypotheses —
and drafts a `recon → finding → impact → remediation` write-up.

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

| Tool | What it does |
|---|---|
| `nmap_scan` | service/version scan (`nmap -sV`) |
| `http_enum` | headers, title, common paths (robots.txt, /admin, /.git) |
| `ftp_anon` | test anonymous FTP login, list the root |
| `smb_enum` | list SMB shares via a null session |
| `service_intel` | look up known common misconfigs + enumeration steps for a service (grounds hypotheses in fact, not invention) |

Real tools shell out and **degrade gracefully** when a binary or the network
isn't there. `--simulate` swaps in canned outputs for a coherent demo box, so the
whole loop runs with no network, no nmap, and no root.

## Layout

```
recce/
  types.py         Pydantic model: Port / Hypothesis / ReconFindings / Step / ReconRun
  tools.py         Tool + ToolRegistry (the reusable agent-core hands)
  agent.py         the loop: plan → tool-use → observe → conclude, with recovery
  recon/tools.py   read-only recon tools + service-intel + simulate mode
  report.py        render the write-up and the reasoning trail
  cli.py           recce scan | replay  (with the authorization gate)
tests/             offline suite — fake model + simulated tools
```

## Status

v0.1 — agent core (loop, tool registry, journal), recon toolset with a simulate
mode, write-up renderer, CLI with an authorization gate, tested offline. Next:
more enumeration tools, a live HTB run, and tightening the hypothesis prompt.
