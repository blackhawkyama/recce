"""Tool registry — the agent's hands.

A Tool wraps a plain Python function with the metadata Claude needs to call it
(name, description, JSON-schema inputs). The registry dispatches a call by name,
times it, and — crucially — turns any exception into a failed ToolResult instead
of propagating. That's what lets the agent *recover* from a tool blowing up
(a timeout, a missing binary, a refused connection) rather than crashing the run.
"""

from __future__ import annotations

import time
from typing import Any, Callable, Optional

from recce.types import ToolResult

# A tool function returns either a string (treated as successful output) or a
# fully-formed ToolResult (to signal a handled failure with ok=False).
ToolFn = Callable[..., "str | ToolResult"]


class Tool:
    def __init__(
        self,
        name: str,
        description: str,
        input_schema: dict[str, Any],
        fn: ToolFn,
    ) -> None:
        self.name = name
        self.description = description
        self.input_schema = input_schema
        self.fn = fn

    def to_anthropic(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "input_schema": self.input_schema,
        }

    def run(self, tool_input: dict[str, Any]) -> ToolResult:
        start = time.perf_counter()
        try:
            result = self.fn(**(tool_input or {}))
            elapsed = time.perf_counter() - start
            if isinstance(result, ToolResult):
                if result.latency_s is None:
                    result.latency_s = elapsed
                return result
            return ToolResult(name=self.name, ok=True, output=str(result), latency_s=elapsed)
        except TypeError as exc:
            # Almost always a bad-arguments call from the model — recoverable.
            return ToolResult(
                name=self.name,
                ok=False,
                error=f"bad arguments: {exc}",
                latency_s=time.perf_counter() - start,
            )
        except Exception as exc:  # noqa: BLE001 — a tool fault is data, not a crash
            return ToolResult(
                name=self.name,
                ok=False,
                error=f"{type(exc).__name__}: {exc}",
                latency_s=time.perf_counter() - start,
            )


class ToolRegistry:
    def __init__(self, tools: Optional[list[Tool]] = None) -> None:
        self._tools: dict[str, Tool] = {}
        for t in tools or []:
            self.add(t)

    def add(self, tool: Tool) -> None:
        if tool.name in self._tools:
            raise ValueError(f"duplicate tool name: {tool.name}")
        self._tools[tool.name] = tool

    def __contains__(self, name: str) -> bool:
        return name in self._tools

    def names(self) -> list[str]:
        return list(self._tools)

    def anthropic_schemas(self) -> list[dict[str, Any]]:
        return [t.to_anthropic() for t in self._tools.values()]

    def run(self, name: str, tool_input: dict[str, Any]) -> ToolResult:
        tool = self._tools.get(name)
        if tool is None:
            return ToolResult(name=name, ok=False, error=f"unknown tool: {name}")
        return tool.run(tool_input)


def tool(name: str, description: str, input_schema: dict[str, Any]) -> Callable[[ToolFn], Tool]:
    """Decorator sugar: turn a function into a Tool.

        @tool("nmap_scan", "Scan a host", {...})
        def nmap_scan(target: str) -> str: ...
    """

    def wrap(fn: ToolFn) -> Tool:
        return Tool(name=name, description=description, input_schema=input_schema, fn=fn)

    return wrap
