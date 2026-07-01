"""Agent + tools tests, fully offline: the model is a scripted fake that emits
canned tool calls, and the recon tools run in simulate mode. No key, no network."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from recce.agent import Agent
from recce.recon.tools import build_registry, service_intel
from recce.report import render_journal, render_writeup
from recce.tools import Tool, ToolRegistry
from recce.types import ToolResult


# --- fake Anthropic client ------------------------------------------------


def txt(t: str):
    return SimpleNamespace(type="text", text=t)


def use(tid: str, name: str, inp: dict):
    return SimpleNamespace(type="tool_use", id=tid, name=name, input=inp)


def resp(content: list, stop: str = "tool_use"):
    return SimpleNamespace(content=content, stop_reason=stop)


class FakeMessages:
    def __init__(self, script, repeat_last=False, raises=None):
        self.script = list(script)
        self.repeat_last = repeat_last
        self.raises = raises
        self.calls: list[dict] = []

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.raises:
            raise self.raises
        if not self.script:
            if self.repeat_last:
                return self._last
            raise AssertionError("fake model script exhausted")
        self._last = self.script.pop(0)
        return self._last


class FakeClient:
    def __init__(self, script, **kw):
        self.messages = FakeMessages(script, **kw)


CONCLUDE_INPUT = {
    "summary": "FTP allows anonymous login and exposes a backup archive.",
    "open_ports": [
        {"port": 21, "service": "ftp", "version": "vsftpd 3.0.3"},
        {"port": 80, "service": "http", "version": "Apache 2.4.41"},
    ],
    "hypotheses": [
        {
            "title": "Anonymous FTP exposes backup",
            "service": "ftp/21",
            "evidence": "anonymous login ALLOWED; root lists backup_2026.zip",
            "rationale": "The archive may contain credentials or source.",
            "suggested_next_step": "ftp anonymous → get backup_2026.zip; inspect it",
            "confidence": "high",
        }
    ],
}


# --- happy path -----------------------------------------------------------


def _scripted_client():
    return FakeClient(
        [
            resp([txt("Scanning the target first."), use("t1", "nmap_scan", {"target": "demo"})]),
            resp([use("t2", "service_intel", {"service": "ftp"})]),
            resp([use("t3", "ftp_anon", {"target": "demo"})]),
            resp([use("t4", "conclude", CONCLUDE_INPUT)]),
        ]
    )


def test_agent_runs_loop_and_concludes():
    agent = Agent(build_registry(simulate=True), client=_scripted_client(), max_steps=8)
    run = agent.run("demo", authorized=True)

    assert run.stopped_reason == "concluded"
    assert run.findings is not None
    assert run.findings.hypotheses[0].confidence.value == "high"
    assert run.tool_calls() == 3  # nmap, service_intel, ftp_anon (conclude isn't a tool step)
    # narration captured as an assistant step
    assert any(s.kind == "assistant" and "Scanning" in s.text for s in run.steps)
    # the ftp tool actually ran in simulate mode
    ftp_step = next(s for s in run.steps if s.tool_name == "ftp_anon")
    assert "anonymous login ALLOWED" in ftp_step.tool_result.output


def test_authorization_gate_blocks_run():
    fake = _scripted_client()
    agent = Agent(build_registry(simulate=True), client=fake, max_steps=8)
    run = agent.run("demo", authorized=False)
    assert run.findings is None
    assert run.stopped_reason.startswith("refused")
    assert fake.messages.calls == []  # never called the model


# --- failure recovery -----------------------------------------------------


def test_tool_failure_is_recoverable():
    # smb_enum fails in simulate mode; the agent should get an error result and
    # still be able to conclude afterward.
    client = FakeClient(
        [
            resp([use("t1", "smb_enum", {"target": "demo"})]),
            resp([use("t2", "conclude", CONCLUDE_INPUT)]),
        ]
    )
    run = Agent(build_registry(simulate=True), client=client, max_steps=8).run("demo", authorized=True)
    smb = next(s for s in run.steps if s.tool_name == "smb_enum")
    assert smb.tool_result.ok is False
    assert run.stopped_reason == "concluded"  # recovered and finished


def test_unknown_tool_returns_error_not_crash():
    client = FakeClient(
        [
            resp([use("t1", "nonexistent_tool", {})]),
            resp([use("t2", "conclude", CONCLUDE_INPUT)]),
        ]
    )
    run = Agent(build_registry(simulate=True), client=client, max_steps=8).run("demo", authorized=True)
    bad = next(s for s in run.steps if s.tool_name == "nonexistent_tool")
    assert bad.tool_result.ok is False and "unknown tool" in bad.tool_result.error


def test_api_error_ends_run_cleanly():
    client = FakeClient([], raises=RuntimeError("network down"))
    run = Agent(build_registry(simulate=True), client=client, max_steps=8).run("demo", authorized=True)
    assert run.findings is None
    assert run.stopped_reason.startswith("api error")


def test_step_budget_exhausted():
    # Never concludes — keeps scanning. Budget must stop it.
    client = FakeClient(
        [resp([use("t1", "nmap_scan", {"target": "demo"})])], repeat_last=True
    )
    run = Agent(build_registry(simulate=True), client=client, max_steps=3).run("demo", authorized=True)
    assert run.findings is None
    assert "step budget" in run.stopped_reason
    assert run.tool_calls() == 3


def test_conclude_validation_failure():
    client = FakeClient([resp([use("t1", "conclude", {"open_ports": []})])])  # missing summary
    run = Agent(build_registry(simulate=True), client=client, max_steps=4).run("demo", authorized=True)
    assert run.findings is None
    assert "conclude failed validation" in run.stopped_reason


def test_nudge_when_model_ends_without_concluding():
    client = FakeClient(
        [
            resp([txt("All done, looks like FTP.")], stop="end_turn"),  # no conclude
            resp([use("t1", "conclude", CONCLUDE_INPUT)]),  # concludes after nudge
        ]
    )
    run = Agent(build_registry(simulate=True), client=client, max_steps=6).run("demo", authorized=True)
    assert run.stopped_reason == "concluded"


# --- tool registry + intel ------------------------------------------------


def test_tool_registry_wraps_exceptions():
    def boom(**kw):
        raise ValueError("kaboom")

    reg = ToolRegistry([Tool("boom", "d", {"type": "object", "properties": {}}, boom)])
    res = reg.run("boom", {})
    assert res.ok is False and "kaboom" in res.error


def test_tool_bad_arguments_recoverable():
    reg = build_registry(simulate=True)
    # ftp_anon takes target; call with a wrong kwarg
    res = reg.run("ftp_anon", {"nope": 1})
    assert res.ok is False and "bad arguments" in res.error


def test_service_intel_known_and_unknown():
    assert "anonymous" in service_intel("ftp").lower()
    assert "no curated intel" in service_intel("gopher").lower()


def test_duplicate_tool_rejected():
    with pytest.raises(ValueError):
        ToolRegistry([
            Tool("x", "d", {"type": "object", "properties": {}}, lambda: "a"),
            Tool("x", "d", {"type": "object", "properties": {}}, lambda: "b"),
        ])


# --- rendering ------------------------------------------------------------


def test_writeup_and_journal_render():
    run = Agent(build_registry(simulate=True), client=_scripted_client(), max_steps=8).run(
        "demo", authorized=True
    )
    md = render_writeup(run)
    assert "# Recon — demo" in md
    assert "Anonymous FTP exposes backup" in md
    assert "Suggested next step" in md
    assert "Remediation" in md  # ftp remediation keyed in
    trail = render_journal(run)
    assert "nmap_scan" in trail and "concluded" in trail
