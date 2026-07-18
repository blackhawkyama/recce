"""Command line: run the recon agent against an authorized target, or replay a run.

    recce scan 10.10.10.10 --authorized      # real enumeration (needs nmap, a key)
    recce scan demo --simulate               # canned tool output (still calls the model)
    recce sweep example.com                  # passive-only surface map (no model/key)
    recce vet runs/<sweep>.json --authorized # WAF+liveness triage of priority hosts (active, gentle)
    recce replay runs/<id>.json              # re-render a saved run

Authorization gate: a real scan refuses to start without --authorized. recce only
enumerates — it never exploits — but scanning a host you don't own is still your
responsibility, so the flag makes that acknowledgement explicit and logged.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from recce.agent import Agent
from recce.recon.tools import build_registry
from recce.report import render_journal, render_writeup
from recce.types import ReconRun, Step

_BANNER = (
    "recce — reconnaissance only, authorized targets only. It enumerates and "
    "proposes; it does not exploit."
)


def _live(step: Step) -> None:
    if step.kind == "assistant":
        print(f"\n· {step.text}", file=sys.stderr)
    else:
        r = step.tool_result
        status = "ok" if (r and r.ok) else "ERR"
        arg = " ".join(f"{k}={v}" for k, v in step.tool_input.items())
        print(f"  → {step.tool_name}({arg}) [{status}]", file=sys.stderr)


def cmd_scan(args: argparse.Namespace) -> int:
    print(_BANNER, file=sys.stderr)
    if not args.simulate and not args.authorized:
        sys.exit(
            "refusing to scan: pass --authorized to confirm you have permission to "
            "test this target (or --simulate for a canned demo run)."
        )

    registry = build_registry(simulate=args.simulate)
    agent = Agent(registry, model=args.model, max_steps=args.max_steps)
    print(f"\nTarget: {args.target}  (max {args.max_steps} steps)\n", file=sys.stderr)

    run = agent.run(args.target, authorized=args.authorized or args.simulate, on_step=_live)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Build filenames by concatenation — never Path.with_suffix, which would treat
    # a dot in the target (10.10.10.10, example.com) as the extension and mangle it.
    stamp = run.created_at.replace(":", "").replace("-", "")[:15]
    slug = args.target.replace("/", "_").replace(":", "_")
    json_path = out_dir / f"{slug}-{stamp}.json"
    md_path = out_dir / f"{slug}-{stamp}.md"
    json_path.write_text(run.model_dump_json(indent=2))
    writeup = render_writeup(run)
    md_path.write_text(writeup)

    print(f"\n{render_journal(run)}", file=sys.stderr)
    print("\n" + "=" * 60)
    print(writeup)
    print("=" * 60)
    print(f"\nsaved: {json_path}  |  {md_path}", file=sys.stderr)
    return 0 if run.findings else 1


def cmd_sweep(args: argparse.Namespace) -> int:
    """Passive-only surface sweep: crt.sh + passive DNS + Wayback + deterministic
    triage, assembled into the same Surface/write-up a full run produces — but with
    no model, no API key, and no packets to the target beyond public OSINT lookups.
    Safe to run unattended on any domain; it's the recon-first step of the hunt."""
    from recce.recon.web import collect_subdomains, collect_wayback, rank_hosts
    from recce.types import ReconFindings, ReconRun, Surface

    domain = args.target
    print(_BANNER, file=sys.stderr)
    print(f"\nPassive sweep: {domain}  (no model · no key · public OSINT only)\n", file=sys.stderr)

    print("  → subdomain_enum (crt.sh + hackertarget)…", file=sys.stderr)
    subs, sources = collect_subdomains(domain)
    print(f"    {len(subs)} subdomains via {', '.join(sources) or '(none answered)'}", file=sys.stderr)

    tagged, _plain = rank_hosts(subs)
    priority = [h for h, _ in tagged]
    print(f"  → triage: {len(priority)} priority host(s)", file=sys.stderr)

    hot: list[str] = []
    if not args.no_wayback:
        print("  → wayback_urls (CDX history)…", file=sys.stderr)
        _all, hot = collect_wayback(domain, args.wayback_limit)
        print(f"    {len(hot)} interesting historical URL(s)", file=sys.stderr)

    if not subs and not hot:
        print(
            "\nNothing recovered — the passive sources may be rate-limiting. "
            "Retry shortly, or add subfinder/amass API keys for depth.",
            file=sys.stderr,
        )
        return 1

    summary = (
        f"Passive surface sweep of {domain}: {len(subs)} subdomains "
        f"({len(priority)} priority), {len(hot)} notable historical URL(s). "
        f"Sources: {', '.join(sources) or 'none'}. No hosts probed."
    )
    surface = Surface(
        subdomains=subs,
        priority_hosts=priority,
        notable_urls=hot[:15],
        waf_notes="(passive sweep — hosts not probed; run `recce scan --authorized` "
        "to fingerprint WAF + liveness on the priority hosts)",
    )
    run = ReconRun(
        target=domain,
        authorized=True,  # passive OSINT only — legal on any domain
        model="(passive sweep — no model)",
        findings=ReconFindings(summary=summary, surface=surface),
        stopped_reason="passive sweep complete",
        config={"mode": "sweep", "sources": sources},
    )

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    # Concatenate the extension — with_suffix would eat the dot in the domain.
    stamp = run.created_at.replace(":", "").replace("-", "")[:15]
    slug = domain.replace("/", "_").replace(":", "_")
    json_path = out_dir / f"{slug}-sweep-{stamp}.json"
    md_path = out_dir / f"{slug}-sweep-{stamp}.md"
    json_path.write_text(run.model_dump_json(indent=2))
    writeup = render_writeup(run)
    md_path.write_text(writeup)

    print("\n" + "=" * 60)
    print(writeup)
    print("=" * 60)
    print(f"\nsaved: {json_path}  |  {md_path}", file=sys.stderr)
    return 0


def cmd_vet(args: argparse.Namespace) -> int:
    """Active-but-gentle WAF + liveness triage of the priority hosts from a sweep:
    one GET per host, fingerprint the bot-WAF, and sort into clean-and-alive (test
    first) vs WAF-guarded vs unreachable. Sends live requests, so it's --authorized
    gated and honours an --exclude scope filter. Chains after `recce sweep`."""
    from recce.recon.web import collect_subdomains, fingerprint_waf, rank_hosts
    from recce.types import ReconFindings, ReconRun, Surface

    print(_BANNER, file=sys.stderr)
    if not args.authorized:
        sys.exit(
            "refusing to vet: `vet` sends live GET requests to each host. Pass "
            "--authorized to confirm these hosts are in scope for you to test."
        )

    # Source: a saved sweep .json (reuse its priority list) or a bare domain.
    src = args.source
    label = src
    priority: list[str] = []
    p = Path(src)
    if p.exists() and p.suffix == ".json":
        prior = ReconRun.model_validate_json(p.read_text())
        label = prior.target
        surf = prior.findings.surface if prior.findings else None
        if surf:
            priority = list(surf.priority_hosts) or list(surf.subdomains)
        print(f"loaded {len(priority)} priority host(s) from {p.name}", file=sys.stderr)
    else:
        print(f"deriving priority hosts for {src} (passive)…", file=sys.stderr)
        subs, _sources = collect_subdomains(src)
        priority = [h for h, _ in rank_hosts(subs)[0]]
        print(f"  {len(priority)} priority host(s) from {len(subs)} subdomains", file=sys.stderr)

    excl = [e.lower() for e in (args.exclude or [])]
    if excl:
        kept = [h for h in priority if not any(e in h.lower() for e in excl)]
        print(f"  scope filter dropped {len(priority) - len(kept)} host(s) matching {excl}",
              file=sys.stderr)
        priority = kept

    if not priority:
        print("no hosts to vet.", file=sys.stderr)
        return 1

    limit = max(1, int(args.limit))
    targets = priority[:limit]
    print(f"\nvetting {len(targets)} host(s)"
          + (f" (capped from {len(priority)})" if len(priority) > limit else "")
          + " — one gentle GET each\n", file=sys.stderr)

    results = []
    for i, h in enumerate(targets, 1):
        info = fingerprint_waf(h)
        results.append(info)
        if "error" in info:
            print(f"  [{i}/{len(targets)}] {h} — {info['error']}", file=sys.stderr)
        else:
            tag = ("HEAVY" if info["heavy"] else "WAF" if info["detected"]
                   else "CHALLENGE" if info["challenge"] else "CLEAN")
            marks = ",".join(info["detected"])
            print(f"  [{i}/{len(targets)}] {info['status']} {h} — {tag} {marks}".rstrip(),
                  file=sys.stderr)

    alive = [r for r in results if "error" not in r]
    clean = [r for r in alive if not r["detected"] and not r["challenge"]]
    waffed = [r for r in alive if r["detected"] or r["challenge"]]
    dead = [r for r in results if "error" in r]

    surface = Surface(
        live_hosts=[r["host"] for r in alive],
        priority_hosts=[r["host"] for r in clean],  # clean & alive ⇒ test first
        waf_notes=(f"{len(alive)}/{len(targets)} alive · {len(clean)} clean · "
                   f"{len(waffed)} WAF/challenge · {len(dead)} no-response"),
    )
    summary = (f"WAF triage of {label}: vetted {len(targets)} priority host(s). "
               f"{len(clean)} clean & alive (test first), {len(waffed)} WAF-guarded, "
               f"{len(dead)} unreachable.")
    run = ReconRun(target=label, authorized=True, model="(vet — no model)",
                   findings=ReconFindings(summary=summary, surface=surface),
                   stopped_reason="vet complete", config={"mode": "vet", "limit": limit})

    def _table(rows: list, title: str) -> list:
        if not rows:
            return []
        out = [f"\n### {title}", "", "| Status | Host | WAF/CDN | Server |", "|---|---|---|---|"]
        for r in rows:
            out.append(f"| {r['status']} | `{r['host']}` | {', '.join(r['detected']) or '—'} "
                       f"| {r['server'] or '—'} |")
        return out

    detail = ["\n## WAF triage detail"]
    detail += _table(sorted(clean, key=lambda r: r["host"]),
                     f"Clean & alive — test first ({len(clean)})")
    detail += _table(sorted(waffed, key=lambda r: r["host"]), f"WAF / challenge ({len(waffed)})")
    if dead:
        detail += [f"\n### No response ({len(dead)})", "",
                   ", ".join(f"`{r['host']}`" for r in dead)]
    writeup = render_writeup(run) + "\n" + "\n".join(detail)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    stamp = run.created_at.replace(":", "").replace("-", "")[:15]
    slug = label.replace("/", "_").replace(":", "_")
    json_path = out_dir / f"{slug}-vet-{stamp}.json"
    md_path = out_dir / f"{slug}-vet-{stamp}.md"
    json_path.write_text(run.model_dump_json(indent=2))
    md_path.write_text(writeup)

    print("\n" + "=" * 60)
    print(writeup)
    print("=" * 60)
    print(f"\nsaved: {json_path}  |  {md_path}", file=sys.stderr)
    return 0


def cmd_replay(args: argparse.Namespace) -> int:
    run = ReconRun.model_validate_json(Path(args.run).read_text())
    if args.journal:
        print(render_journal(run))
    else:
        print(render_writeup(run))
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="recce", description=__doc__.splitlines()[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("scan", help="run the recon agent on a target")
    s.add_argument("target", help="host/IP of the authorized target")
    s.add_argument("--authorized", action="store_true",
                   help="confirm you are authorized to test this target")
    s.add_argument("--simulate", action="store_true",
                   help="use canned tool output (still calls the model)")
    s.add_argument("--model", default="claude-opus-4-8")
    s.add_argument("--max-steps", type=int, default=12)
    s.add_argument("-o", "--out", default="runs")
    s.set_defaults(func=cmd_scan)

    w = sub.add_parser("sweep", help="passive-only surface map (no model/key, safe on any domain)")
    w.add_argument("target", help="domain to sweep passively")
    w.add_argument("--no-wayback", action="store_true", help="skip the Wayback CDX history pull")
    w.add_argument("--wayback-limit", type=int, default=200, help="max historical URLs (default 200)")
    w.add_argument("-o", "--out", default="runs")
    w.set_defaults(func=cmd_sweep)

    v = sub.add_parser("vet", help="active WAF+liveness triage of priority hosts (in-scope, --authorized)")
    v.add_argument("source", help="a sweep .json artifact, or a domain to derive priority hosts from")
    v.add_argument("--authorized", action="store_true",
                   help="confirm these hosts are in scope for you to actively test")
    v.add_argument("--limit", type=int, default=20, help="max hosts to probe (default 20)")
    v.add_argument("--exclude", action="append",
                   help="drop hosts containing this substring (repeatable) — for out-of-scope patterns")
    v.add_argument("-o", "--out", default="runs")
    v.set_defaults(func=cmd_vet)

    r = sub.add_parser("replay", help="re-render a saved run")
    r.add_argument("run", help="path to a runs/<id>.json")
    r.add_argument("--journal", action="store_true", help="show the reasoning trail")
    r.set_defaults(func=cmd_replay)

    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
