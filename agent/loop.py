"""Planner -> tool loop with step/token/time budgets, an agent-side allow-list and a human-approval gate."""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Literal

import anyio
from mcp import Client

from .llm import EVENT_ID_RE, LLMProvider

# Read-only MCP tools the agent may call without approval.
READ_ONLY_TOOLS = frozenset(
    {"search_logs", "get_host_timeline", "lookup_ioc", "correlate_events", "propose_detection_rule"}
)
# Agent-local tool for containment actions. It never executes anything: it only records a recommendation,
# and every call must pass the human-approval gate.
ACTION_TOOL = {
    "name": "request_response_action",
    "description": "Recommend a containment action (requires human approval; recorded, never executed).",
    "input_schema": {
        "type": "object",
        "properties": {
            "action": {"type": "string", "enum": ["block_ip", "isolate_host", "disable_account"]},
            "target": {"type": "string", "maxLength": 100},
            "justification": {"type": "string", "maxLength": 500},
        },
        "required": ["action", "target", "justification"],
    },
}
MAX_TOOL_RESULT_CHARS = 60_000  # what the model sees from one tool result

SYSTEM_PROMPT = """You are a threat hunter working only on synthetic lab logs through read-only tools.
Plan a hunt from the hypothesis, call tools to gather evidence, and pivot on what you find (IPs, users, hosts,
times). Cite event_ids you actually saw in tool results; do not invent them. Draft a Sigma rule with
propose_detection_rule for the main behaviour you confirm. You may recommend containment with
request_response_action; a human approves or denies it. When done, reply with a short summary and one fenced
```json block: {"summary": str, "findings": [{"technique": "Txxxx[.xxx]", "title": str,
"evidence": [event_id, ...], "confidence": "low|medium|high"}]}."""


@dataclass
class Budgets:
    max_steps: int = 12
    max_tokens: int = 200_000
    max_seconds: float = 300.0
    max_tokens_per_call: int = 16_000


class ApprovalGate:
    """Human-in-the-loop decision for risky actions. 'deny' is the default (and what tests use)."""

    def __init__(self, policy: Literal["deny", "approve", "prompt"] = "deny", ask=input):
        self.policy, self._ask = policy, ask

    def decide(self, name: str, args: dict) -> bool:
        if self.policy == "approve":
            return True
        if self.policy == "prompt":
            return self._ask(f"Approve {name} {json.dumps(args)}? [y/N] ").strip().lower() == "y"
        return False


@dataclass
class HuntReport:
    hypothesis: str
    provider: str
    summary: str = ""
    findings: list = field(default_factory=list)
    rules: list = field(default_factory=list)
    actions: list = field(default_factory=list)
    stop_reason: str = ""
    steps: int = 0
    tool_calls: int = 0
    input_tokens: int = 0
    output_tokens: int = 0
    elapsed_s: float = 0.0
    trace: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def parse_final(text: str) -> dict:
    """Take the last fenced json block (or bare JSON object) with a 'findings' key."""
    for blob in reversed(re.findall(r"```json\s*(\{.*?\})\s*```", text, re.S) or [text]):
        try:
            doc = json.loads(blob)
        except json.JSONDecodeError:
            continue
        if isinstance(doc, dict) and isinstance(doc.get("findings"), list):
            return doc
    return {"summary": text.strip()[:500], "findings": []}


class HuntAgent:
    def __init__(
        self, provider: LLMProvider, session: Client, budgets: Budgets | None = None, gate: ApprovalGate | None = None
    ):
        self.llm, self.session = provider, session
        self.budgets, self.gate = budgets or Budgets(), gate or ApprovalGate()

    async def _tools(self) -> list[dict]:
        listed = await self.session.list_tools()
        tools = [
            {"name": t.name, "description": t.description or "", "input_schema": t.input_schema}
            for t in listed.tools
            if t.name in READ_ONLY_TOOLS
        ]
        return tools + [ACTION_TOOL]

    async def _run_tool(self, name: str, args: dict, report: HuntReport) -> tuple[str, bool]:
        if name == ACTION_TOOL["name"]:
            approved = self.gate.decide(name, args)
            report.actions.append({**args, "decision": "approved" if approved else "denied"})
            msg = "approved by a human and recorded (no automated execution)" if approved else "denied by human gate"
            return json.dumps({"status": msg}), not approved
        if name not in READ_ONLY_TOOLS:
            return json.dumps({"error": f"tool {name!r} is not on the agent allow-list"}), True
        result = await self.session.call_tool(name, args)
        if result.structured_content is not None:  # compact JSON: same data, far fewer tokens
            text = json.dumps(result.structured_content, separators=(",", ":"))
        else:
            text = "".join(getattr(c, "text", "") for c in result.content)
        if not result.is_error and name == "propose_detection_rule":
            report.rules.append(json.loads(text))
        if len(text) > MAX_TOOL_RESULT_CHARS:
            text = text[:MAX_TOOL_RESULT_CHARS] + "...[truncated by agent]"
        return text, bool(result.is_error)

    async def run(self, hypothesis: str) -> HuntReport:
        b = self.budgets
        report = HuntReport(hypothesis=hypothesis, provider=self.llm.name)
        tools = await self._tools()
        messages: list = [{"role": "user", "content": f"Hypothesis / threat-intel brief: {hypothesis}"}]
        seen_ids: set[str] = set()
        t0 = time.monotonic()
        final_text = ""

        def remaining() -> float:
            return b.max_seconds - (time.monotonic() - t0)

        try:
            while True:
                if report.steps >= b.max_steps:
                    report.stop_reason = "step_budget"
                    break
                used = report.input_tokens + report.output_tokens
                if used >= b.max_tokens:
                    report.stop_reason = "token_budget"
                    break
                if remaining() <= 0:
                    raise TimeoutError
                with anyio.fail_after(remaining()):
                    resp = await self.llm.complete(
                        SYSTEM_PROMPT, messages, tools, min(b.max_tokens_per_call, b.max_tokens - used)
                    )
                report.steps += 1
                report.input_tokens += resp.input_tokens
                report.output_tokens += resp.output_tokens
                report.trace.append(
                    {"step": report.steps, "text": resp.text[:500], "tool_calls": [asdict(c) for c in resp.tool_calls]}
                )
                messages.append({"role": "assistant", "content": resp.content})
                if resp.stop_reason == "refusal":
                    report.stop_reason = "refusal"
                    break
                if not resp.tool_calls:
                    final_text = resp.text
                    report.stop_reason = "completed"
                    break
                results = []
                for call in resp.tool_calls:  # all results go back in one user message
                    with anyio.fail_after(max(remaining(), 0.001)):
                        text, is_err = await self._run_tool(call.name, call.input, report)
                    report.tool_calls += 1
                    seen_ids.update(EVENT_ID_RE.findall(text))
                    report.trace[-1].setdefault("results", []).append(
                        {"tool": call.name, "error": is_err, "chars": len(text)}
                    )
                    results.append({"type": "tool_result", "tool_use_id": call.id, "content": text, "is_error": is_err})
                messages.append({"role": "user", "content": results})
        except TimeoutError:
            report.stop_reason = "time_budget"

        final = parse_final(final_text)
        report.summary = final.get("summary", "")
        for f in final["findings"]:
            ev = [e for e in f.get("evidence", []) if isinstance(e, str)]
            # Grounding check: evidence must have appeared in a tool result during this hunt.
            report.findings.append({**f, "evidence": ev, "verified": bool(ev) and set(ev) <= seen_ids})
        report.elapsed_s = round(time.monotonic() - t0, 3)
        return report
