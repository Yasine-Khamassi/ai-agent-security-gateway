"""
Tool-authorization gateway for the agent.

The security thesis (OWASP LLM06 Excessive Agency / LLM01): the model will be
manipulated by injection sooner or later, and it must not matter, because the
dangerous action is stopped *outside* the model.

- insecure: the agent may call any tool with any argument, under the user's own
  authority, with no restrictions. Whatever the (possibly injected) model asks
  for, runs.
- hardened: a per-task allow-list, resource-level permissions (restricted assets
  need explicit authorization), human-in-the-loop for high-impact actions, and a
  tool-call log for attribution. Denied calls never execute.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.tools import TOOLS, is_restricted_asset


@dataclass
class ToolCall:
    tool: str
    args: dict
    allowed: bool
    reason: str
    result: str = ""


@dataclass
class Gateway:
    defended: bool
    # Tools the current task is allowed to use (hardened mode only).
    allowed_tools: set[str] = field(default_factory=lambda: {"read_docs", "create_ticket"})
    # High-impact tools that require human approval (none granted in this lab).
    approved_high_impact: set[str] = field(default_factory=set)
    log: list[ToolCall] = field(default_factory=list)

    def execute(self, tool: str, args: dict) -> ToolCall:
        call = self._decide(tool, args)
        if call.allowed:
            fn = TOOLS[tool]["fn"]
            try:
                call.result = str(fn(**args))
            except TypeError as exc:
                call.allowed, call.reason, call.result = False, "bad_arguments", str(exc)
        self.log.append(call)
        return call

    def _decide(self, tool: str, args: dict) -> ToolCall:
        if tool not in TOOLS:
            return ToolCall(tool, args, False, "unknown_tool")
        if not self.defended:
            return ToolCall(tool, args, True, "insecure_allow_all")
        # hardened checks
        if tool not in self.allowed_tools:
            return ToolCall(tool, args, False, "not_in_task_allowlist")
        if TOOLS[tool]["impact"] == "high" and tool not in self.approved_high_impact:
            return ToolCall(tool, args, False, "high_impact_needs_approval")
        if tool == "query_inventory" and is_restricted_asset(args.get("asset_id", "")):
            return ToolCall(tool, args, False, "restricted_resource")
        return ToolCall(tool, args, True, "ok")

    def restricted_was_accessed(self) -> bool:
        """Ground truth: did any executed call read a restricted asset?"""
        return any(
            c.allowed and c.tool == "query_inventory" and is_restricted_asset(c.args.get("asset_id", ""))
            for c in self.log
        )
