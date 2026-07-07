"""The agent loop.

A manual Anthropic tool-use loop, kept deliberately explicit so every part of
the orchestration is visible and testable:

    plan → the model calls read-only recon tools → we execute and feed results
    back → it reasons over them → when it has a read on the target it calls
    `conclude` with structured findings → we stop.

Three things make it an *agent* and not a single call:
  - a **step budget** bounds the loop and forces a graceful hand-off if hit;
  - **failure recovery** — a tool error comes back as a normal tool_result the
    model can react to, and API errors are caught and end the run cleanly;
  - a **structured termination** — `conclude` validates the model's hand-off
    against a schema, so the output is data, not prose.

The loop is domain-agnostic. Hand it any ToolRegistry and it runs; the recon
tools live in recce.recon.
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Optional

from recce.tools import ToolRegistry
from recce.types import ReconFindings, ReconRun, Step, ToolResult

_client_lock = threading.Lock()
_shared_client: Any = None


def _client() -> Any:
    global _shared_client
    with _client_lock:
        if _shared_client is None:
            import anthropic  # deferred so the package imports with no SDK/key

            _shared_client = anthropic.Anthropic()
        return _shared_client


SYSTEM_PROMPT = """\
You are a reconnaissance analyst operating ONLY against targets the operator has \
explicitly confirmed they are authorized to test (an HTB machine, a personal lab, \
a sanctioned bug-bounty program).

Your job is enumeration and analysis, not intrusion. Read the target's shape first:
- A single HOST/IP (an HTB/CTF box) → drill it: nmap_scan for services, then \
enumerate the interesting ones (http_enum, ftp_anon, smb_enum) and ground your \
reasoning with service_intel.
- A DOMAIN (a bug-bounty program) → map the WIDE surface, and START PASSIVE: \
subdomain_enum (public cert/DNS data, safe on any domain) → triage_hosts to rank \
what's worth a look → then, in-scope only and gently, waf_check the candidates \
(a heavy bot-WAF means deprioritise) and http_probe to see what's alive; \
wayback_urls surfaces forgotten endpoints. The bug is usually on the host nobody \
remembers, not the hardened front door.

THE LINE: passive tools (reading public data) are always fine; active tools (that \
send requests to the target) are for in-scope hosts only and must stay gentle — \
never DoS, brute force, credential-stuff, or take any state-changing action. You \
produce ranked hypotheses only. For each: the concrete evidence, why it's a \
plausible foothold, and the single next command a human should try. You stop at \
the hand-off; the human runs the exploit.

Work in small steps: run a tool, read the output, then decide the next based on \
what you actually found — don't fire every tool blindly. When you have enough to \
hand off, call `conclude`. For a domain, fill the `surface` (subdomains, live/\
priority hosts, notable URLs, WAF read); for a host, fill `open_ports`. Prefer a \
focused, well-evidenced hand-off over exhaustive scanning."""

CONCLUDE_TOOL = "conclude"


def _conclude_schema() -> dict[str, Any]:
    schema = ReconFindings.model_json_schema()
    return {
        "name": CONCLUDE_TOOL,
        "description": (
            "Finish the run and hand off structured findings: a summary, the open "
            "ports, and ranked foothold hypotheses. Call this once you've enumerated "
            "the useful services — do not exploit."
        ),
        "input_schema": schema,
    }


StepCallback = Callable[[Step], None]


class Agent:
    def __init__(
        self,
        registry: ToolRegistry,
        model: str = "claude-opus-4-8",
        max_steps: int = 12,
        max_tokens: int = 4096,
        system_prompt: str = SYSTEM_PROMPT,
        client: Any = None,
    ) -> None:
        self.registry = registry
        self.model = model
        self.max_steps = max_steps
        self.max_tokens = max_tokens
        self.system_prompt = system_prompt
        self._client = client  # inject for tests; else lazily shared

    def _api(self) -> Any:
        return self._client or _client()

    def _tools(self) -> list[dict[str, Any]]:
        return self.registry.anthropic_schemas() + [_conclude_schema()]

    def run(self, target: str, *, authorized: bool, on_step: Optional[StepCallback] = None) -> ReconRun:
        run = ReconRun(
            target=target,
            authorized=authorized,
            model=self.model,
            config={"max_steps": self.max_steps, "tools": self.registry.names()},
        )
        if not authorized:
            run.stopped_reason = "refused: target not marked authorized"
            return run

        def emit(step: Step) -> None:
            run.steps.append(step)
            if on_step:
                on_step(step)

        messages: list[dict[str, Any]] = [
            {
                "role": "user",
                "content": (
                    f"Target: {target}\n\nDecide whether this is a single host or a "
                    "domain, recon it accordingly (passive-first for a domain), and "
                    "hand off ranked foothold hypotheses. Authorized engagement."
                ),
            }
        ]
        tools = self._tools()
        idx = 0
        nudged = False

        for _ in range(self.max_steps):
            try:
                resp = self._api().messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    system=self.system_prompt,
                    tools=tools,
                    messages=messages,
                )
            except Exception as exc:  # noqa: BLE001 — end the run cleanly on API failure
                run.stopped_reason = f"api error: {type(exc).__name__}: {exc}"
                return run

            # Record any narration the model produced this turn.
            narration = "".join(
                b.text for b in resp.content if getattr(b, "type", None) == "text"
            ).strip()
            if narration:
                idx += 1
                emit(Step(index=idx, kind="assistant", text=narration))

            messages.append({"role": "assistant", "content": resp.content})

            tool_uses = [b for b in resp.content if getattr(b, "type", None) == "tool_use"]

            if not tool_uses:
                # Model ended without concluding — nudge once, then stop.
                if not nudged:
                    nudged = True
                    messages.append(
                        {
                            "role": "user",
                            "content": "Call `conclude` with your findings to hand off.",
                        }
                    )
                    continue
                run.stopped_reason = "model ended without concluding"
                return run

            # Execute tool calls; conclude terminates the loop.
            tool_results: list[dict[str, Any]] = []
            for tu in tool_uses:
                if tu.name == CONCLUDE_TOOL:
                    try:
                        run.findings = ReconFindings.model_validate(tu.input)
                        run.stopped_reason = "concluded"
                    except Exception as exc:  # noqa: BLE001
                        run.stopped_reason = f"conclude failed validation: {exc}"
                    return run

                result = self.registry.run(tu.name, tu.input or {})
                idx += 1
                emit(
                    Step(
                        index=idx,
                        kind="tool",
                        tool_name=tu.name,
                        tool_input=tu.input or {},
                        tool_result=result,
                    )
                )
                tool_results.append(
                    {
                        "type": "tool_result",
                        "tool_use_id": tu.id,
                        "content": result.as_tool_content(),
                        "is_error": not result.ok,
                    }
                )

            messages.append({"role": "user", "content": tool_results})

        # Budget exhausted without a conclude.
        if not run.stopped_reason:
            run.stopped_reason = f"step budget ({self.max_steps}) exhausted"
        return run
