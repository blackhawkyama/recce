"""Data model for a recon run. All Pydantic, so a run serializes to JSON and the
agent's structured hand-off is validated at the tool boundary."""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Any, Optional

from pydantic import BaseModel, Field


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Confidence(str, enum.Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Port(BaseModel):
    port: int
    service: str = "unknown"
    version: str = ""
    state: str = "open"


class Hypothesis(BaseModel):
    """A ranked theory about the likely foothold — the analytical payload the
    agent produces. `suggested_next_step` is the command a human would run next;
    the agent proposes, it does not execute."""

    title: str = Field(description="Short name for the attack path.")
    service: str = Field(description="Service/port this concerns, e.g. 'ftp/21'.")
    evidence: str = Field(description="What in the recon output supports this.")
    rationale: str = Field(description="Why this is a plausible foothold.")
    suggested_next_step: str = Field(
        description="The single command/action a human should try next (not run here)."
    )
    confidence: Confidence = Confidence.medium


class ReconFindings(BaseModel):
    """The agent's structured hand-off, produced when it calls `conclude`."""

    summary: str = Field(description="1-3 sentence read on the target.")
    open_ports: list[Port] = Field(default_factory=list)
    hypotheses: list[Hypothesis] = Field(default_factory=list)


class ToolResult(BaseModel):
    name: str
    ok: bool = True
    output: str = ""
    error: Optional[str] = None
    latency_s: Optional[float] = None

    def as_tool_content(self, limit: int = 8000) -> str:
        """Rendered form fed back to the model as a tool_result."""
        if not self.ok:
            return f"[tool error] {self.error or 'failed'}"
        text = self.output or "(no output)"
        return text if len(text) <= limit else text[:limit] + "\n…[truncated]"


class Step(BaseModel):
    """One entry in the audit trail — either the agent's narration or a tool call
    with its result. This is the reasoning log a reviewer reads after the fact."""

    index: int
    kind: str  # "assistant" | "tool"
    text: str = ""  # assistant narration, when kind == "assistant"
    tool_name: Optional[str] = None
    tool_input: dict[str, Any] = Field(default_factory=dict)
    tool_result: Optional[ToolResult] = None


class ReconRun(BaseModel):
    """The full artifact of one run: what was targeted, every step taken, the
    findings, and why it stopped."""

    target: str
    authorized: bool = False
    model: str = ""
    created_at: str = Field(default_factory=_utcnow)
    steps: list[Step] = Field(default_factory=list)
    findings: Optional[ReconFindings] = None
    stopped_reason: str = ""
    config: dict[str, Any] = Field(default_factory=dict)

    def tool_calls(self) -> int:
        return sum(1 for s in self.steps if s.kind == "tool")
