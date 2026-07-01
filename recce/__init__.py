"""recce — an autonomous reconnaissance agent for *authorized* targets.

Point it at a box you're allowed to test (an HTB machine, your own lab). It runs
a real agent loop — plan → enumerate with read-only tools → observe → form ranked
hypotheses about the likely foothold → hand off — and drafts a write-up in a
recon → finding → impact → remediation format.

It does reconnaissance only. It never exploits: the loop stops at "here's the
attack path and the command I'd run next," and a human pulls the trigger.

The agent core (loop, tool registry, journal) is decoupled from the recon
toolset, so the same engine can drive other multi-step jobs.
"""

from recce.types import (
    Confidence,
    Hypothesis,
    Port,
    ReconFindings,
    ReconRun,
    Step,
    ToolResult,
)

__all__ = [
    "Confidence",
    "Port",
    "Hypothesis",
    "ReconFindings",
    "ToolResult",
    "Step",
    "ReconRun",
]

__version__ = "0.1.0"
