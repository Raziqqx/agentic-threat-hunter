"""Pluggable LLM providers: Anthropic (real API, key from the environment) or a deterministic mock.

Both speak the Anthropic Messages shape: `messages` is a list of {"role", "content": [blocks]}.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Protocol

DEFAULT_MODEL = "claude-opus-5-5"


@dataclass
class ToolCall:
    id: str
    name: str
    input: dict


@dataclass
class LLMResponse:
    content: list  # assistant content blocks, appended verbatim to the history
    text: str
    tool_calls: list[ToolCall]
    input_tokens: int
    output_tokens: int
    stop_reason: str


class LLMProvider(Protocol):
    name: str

    async def complete(self, system: str, messages: list, tools: list[dict], max_tokens: int) -> LLMResponse: ...


class AnthropicProvider:
    """Claude via the official SDK. Reads ANTHROPIC_API_KEY from the environment; never stores it."""

    name = "anthropic"

    def __init__(self, model: str = DEFAULT_MODEL):
        from anthropic import AsyncAnthropic

        self.model = model
        self.client = AsyncAnthropic()

    async def complete(self, system, messages, tools, max_tokens) -> LLMResponse:
        resp = await self.client.beta.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            system=system,
            tools=tools,
            messages=messages,
            output_config={"effort": "medium"},
            # Re-run on a fallback model if the primary declines (e.g. a security-topic false positive).
            betas=["server-side-fallback-2026-07-01"],
            fallbacks="default",
        )
        text = "".join(b.text for b in resp.content if b.type == "text")
        calls = [ToolCall(b.id, b.name, dict(b.input)) for b in resp.content if b.type == "tool_use"]
        return LLMResponse(
            resp.content, text, calls, resp.usage.input_tokens, resp.usage.output_tokens, resp.stop_reason or "end_turn"
        )


def _tok(obj) -> int:
    """Deterministic token estimate for the mock (~4 chars per token)."""
    return max(1, len(json.dumps(obj, default=str)) // 4)


@dataclass
class MockProvider:
    """Scripted, deterministic hunter for the SSH brute-force playbook.

    It is not a lookup of the answers: every pivot (source IP, account, host, timestamps) is derived from
    the tool results it receives, so it exercises the real loop, tools and safeguards end to end.
    """

    name: str = "mock"
    threshold: int = 20  # failed logins from one source that count as brute force
    phase: int = 0
    facts: dict = field(default_factory=dict)
    _n: int = 0

    def _last_results(self, messages) -> list[dict]:
        last = messages[-1]
        out = []
        if last["role"] == "user" and isinstance(last["content"], list):
            for b in last["content"]:
                if b.get("type") == "tool_result" and not b.get("is_error"):
                    try:
                        out.append(json.loads(b["content"]))
                    except (json.JSONDecodeError, TypeError):
                        pass
        return out

    def _call(self, name, args, messages, note):
        self._n += 1
        blocks = [
            {"type": "text", "text": note},
            {"type": "tool_use", "id": f"mock_{self._n}", "name": name, "input": args},
        ]
        return LLMResponse(
            blocks, note, [ToolCall(f"mock_{self._n}", name, args)], _tok(messages), _tok(blocks), "tool_use"
        )

    def _final(self, messages):
        f = self.facts
        findings = []
        if f.get("ip"):
            findings.append(
                {
                    "technique": "T1110.001",
                    "title": f"SSH brute force from {f['ip']}",
                    "evidence": f["fail_ids"][:10],
                    "confidence": "high",
                }
            )
        if f.get("success"):
            s = f["success"]
            findings.append(
                {
                    "technique": "T1078",
                    "title": f"Login as {s['user']} on {s['host']} after brute force",
                    "evidence": [s["event_id"]],
                    "confidence": "high",
                }
            )
        if f.get("lateral"):
            lat = f["lateral"]
            findings.append(
                {
                    "technique": "T1021.004",
                    "title": f"Lateral SSH to {lat['host']}",
                    "evidence": [lat["event_id"]],
                    "confidence": "medium",
                }
            )
        if f.get("exfil"):
            findings.append(
                {
                    "technique": "T1048",
                    "title": "Large outbound transfer to the attacker",
                    "evidence": f["exfil"],
                    "confidence": "high",
                }
            )
        summary = f"Hypothesis {'confirmed' if findings else 'not supported'} by the logs."
        text = summary + "\n```json\n" + json.dumps({"summary": summary, "findings": findings}) + "\n```"
        blocks = [{"type": "text", "text": text}]
        return LLMResponse(blocks, text, [], _tok(messages), _tok(blocks), "end_turn")

    async def complete(self, system, messages, tools, max_tokens) -> LLMResponse:
        res = self._last_results(messages)
        f, r = self.facts, (res[0] if res else {})
        if self.phase == 0:
            self.phase = 1
            return self._call(
                "search_logs",
                {"log_type": "auth", "contains": "Failed password", "limit": 200},
                messages,
                "Look for many failed SSH logins from one source.",
            )
        if self.phase == 1:
            fails = Counter(e["src_ip"] for e in r.get("events", []))
            noisy = sorted(ip for ip, n in fails.items() if n >= self.threshold)
            if not noisy:
                return self._final(messages)
            ip = max(noisy, key=lambda i: fails[i])
            f.update(ip=ip, noisy=noisy, fail_ids=[e["event_id"] for e in r["events"] if e["src_ip"] == ip])
            self.phase = 2
            return self._call("lookup_ioc", {"indicator": ip}, messages, f"{ip} has {fails[ip]} failures; check intel.")
        if self.phase == 2:
            f["ioc"] = r.get("matches", [])
            self.phase = 3
            return self._call(
                "search_logs",
                {"log_type": "auth", "ip": f["ip"], "contains": "Accepted", "limit": 20},
                messages,
                "Did any attempt succeed?",
            )
        if self.phase == 3:
            if not r.get("events"):
                self.phase = 6  # no successful login: skip straight to the rule
            else:
                s = f["success"] = r["events"][0]
                self.phase = 4
                return self._call(
                    "search_logs",
                    {"log_type": "auth", "user": s["user"], "contains": "Accepted", "start": s["ts"], "limit": 20},
                    messages,
                    f"Where did {s['user']} log in next?",
                )
        if self.phase == 4:
            src = f["success"]
            nxt = [e for e in r.get("events", []) if e["host"] != src["host"] and e["src_ip"].startswith("10.")]
            if nxt:
                f["lateral"] = nxt[0]
                self.phase = 5
                return self._call(
                    "get_host_timeline",
                    {"host": nxt[0]["host"], "start": nxt[0]["ts"], "limit": 60},
                    messages,
                    f"Inspect {nxt[0]['host']} after the lateral login.",
                )
            self.phase = 6
        if self.phase == 5:
            user = f["lateral"]["user"]
            f["exfil"] = [
                e["event_id"]
                for e in r.get("events", [])
                if (e["log_type"] == "conn" and e["dst_ip"] == f["ip"])
                or (e["log_type"] == "process" and e["user"] == user and f["ip"] in e["cmdline"])
            ]
            self.phase = 6
        if self.phase == 6:
            self.phase = 7
            return self._call(
                "propose_detection_rule",
                {
                    "title": "SSH brute force from known noisy sources",
                    "technique": "T1110.001",
                    "log_type": "auth",
                    "selection": {"outcome": "failure", "src_ip": f["noisy"]},
                    "description": "Failed SSH logins from sources seen brute-forcing during the hunt.",
                },
                messages,
                "Draft a detection rule.",
            )
        if self.phase == 7:
            f["rule"] = r
            self.phase = 8
            return self._call(
                "request_response_action",
                {"action": "block_ip", "target": f["ip"], "justification": "Confirmed brute force source"},
                messages,
                "Recommend blocking the source (needs human approval).",
            )
        return self._final(messages)


def make_provider(kind: str = "auto", model: str = DEFAULT_MODEL) -> LLMProvider:
    """'auto' picks Anthropic when ANTHROPIC_API_KEY is set, otherwise the mock."""
    if kind == "anthropic" or (kind == "auto" and os.environ.get("ANTHROPIC_API_KEY")):
        return AnthropicProvider(model)
    if kind in ("mock", "auto"):
        return MockProvider()
    raise ValueError(f"unknown provider {kind!r}")


EVENT_ID_RE = re.compile(r"\b(?:auth|process|conn|web)-\d{6}\b")
