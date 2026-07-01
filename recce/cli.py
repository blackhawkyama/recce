"""Command line: run the recon agent against an authorized target, or replay a run.

    recce scan 10.10.10.10 --authorized      # real enumeration (needs nmap, a key)
    recce scan demo --simulate               # canned tool output (still calls the model)
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
    stamp = run.created_at.replace(":", "").replace("-", "")[:15]
    slug = args.target.replace("/", "_").replace(":", "_")
    base = out_dir / f"{slug}-{stamp}"
    base.with_suffix(".json").write_text(run.model_dump_json(indent=2))
    writeup = render_writeup(run)
    base.with_suffix(".md").write_text(writeup)

    print(f"\n{render_journal(run)}", file=sys.stderr)
    print("\n" + "=" * 60)
    print(writeup)
    print("=" * 60)
    print(f"\nsaved: {base}.json  |  {base}.md", file=sys.stderr)
    return 0 if run.findings else 1


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
