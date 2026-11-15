"""Single-prompt baseline: one LLM call with a log sample, no tools, no pivots.

The prompt holds the hypothesis plus a seeded uniform random sample of events from the hypothesis' log types,
filled up to the same character budget the agent may see from one tool result (60 K chars). The model must
answer in one shot with findings and Sigma rules.

`MockBaselineProvider` is the deterministic stand-in. It is a deliberately *fair* strawman: it applies the same
brute-force heuristic as the agent's mock (`agent.llm.MockProvider`) to the events in the prompt, with the
failure threshold scaled down by the sampling fraction so sampling alone does not hide the attack, and it emits
the same shape of rule. What it lacks is exactly what the agent adds: it cannot query for the events it was not
shown, so it cannot pivot from the source IP to the account, the next host or the exfil connection.
"""

from __future__ import annotations

import json
import random
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path

from agent.llm import EVENT_ID_RE, LLMResponse, _tok
from agent.loop import MAX_TOOL_RESULT_CHARS, parse_final
from service import sigma

BASELINE_SYSTEM = """You are a threat hunter working only on synthetic lab logs. You get a hypothesis and a random
sample of log events (JSON lines). You have no tools. Reply with a short summary and one fenced ```json block:
{"summary": str, "findings": [{"technique": "Txxxx[.xxx]", "title": str, "evidence": [event_id, ...],
"confidence": "low|medium|high"}], "rules": [<Sigma rule as a YAML string>]}. Cite only event_ids in the sample."""

SAMPLE_HEADER = "Sample: {n} of {total} events from log types {types}."


def build_prompt(hypothesis: str, events: list[dict], log_types: list[str], seed: int) -> tuple[str, set[str]]:
    """Return the user prompt and the event ids it contains."""
    pool = [e for e in events if e["log_type"] in log_types]
    rng = random.Random(seed)
    order = rng.sample(range(len(pool)), len(pool))
    picked, size = [], 0
    for i in order:
        line = json.dumps(pool[i], separators=(",", ":"))
        if size + len(line) + 1 > MAX_TOOL_RESULT_CHARS:
            break
        picked.append(i)
        size += len(line) + 1
    picked.sort()  # chronological, like a log excerpt
    lines = [json.dumps(pool[i], separators=(",", ":")) for i in picked]
    header = SAMPLE_HEADER.format(n=len(lines), total=len(pool), types=",".join(log_types))
    prompt = f"Hypothesis / threat-intel brief: {hypothesis}\n{header}\n<logs>\n" + "\n".join(lines) + "\n</logs>"
    return prompt, {pool[i]["event_id"] for i in picked}


@dataclass
class MockBaselineProvider:
    """Deterministic one-shot hunter. Same heuristic as the agent mock, restricted to the sample."""

    name: str = "mock-baseline"
    threshold: int = 20  # same as MockProvider: failures from one source in the *full* logs
    min_threshold: int = 3
    facts: dict = field(default_factory=dict)

    async def complete(self, system, messages, tools, max_tokens) -> LLMResponse:
        prompt = messages[-1]["content"]
        n, total = map(int, re.search(r"Sample: (\d+) of (\d+) events", prompt).groups())
        body = prompt.split("<logs>\n", 1)[1].rsplit("\n</logs>", 1)[0]
        events = [json.loads(line) for line in body.splitlines() if line]
        auth = [e for e in events if e["log_type"] == "auth"]
        # Scale the threshold by the sampling fraction so the strawman is not beaten by sampling alone.
        thr = max(self.min_threshold, round(self.threshold * n / max(total, 1)))
        fails = Counter(e["src_ip"] for e in auth if e["outcome"] == "failure")
        noisy = sorted(ip for ip, c in fails.items() if c >= thr)
        findings, rules = [], []
        if noisy:
            ip = max(noisy, key=lambda i: fails[i])
            fail_ids = [e["event_id"] for e in auth if e["src_ip"] == ip and e["outcome"] == "failure"]
            findings.append(
                {"technique": "T1110.001", "title": f"SSH brute force from {ip}", "evidence": fail_ids[:10]}
            )
            ok = [e for e in auth if e["src_ip"] == ip and e["outcome"] == "success"]
            if ok:
                findings.append(
                    {"technique": "T1078", "title": "Login after brute force", "evidence": [ok[0]["event_id"]]}
                )
            exfil = [e["event_id"] for e in events if e["log_type"] == "conn" and e["dst_ip"] == ip]
            if exfil:
                findings.append({"technique": "T1048", "title": "Outbound transfer to attacker", "evidence": exfil})
            rule = {
                "title": "SSH brute force from noisy sources",
                "id": "00000000-0000-0000-0000-000000000000",
                "technique": "T1110.001",
                "log_type": "auth",
                "selection": {"outcome": "failure", "src_ip": noisy},
                "description": "Failed SSH logins from sources that looked noisy in the sample.",
            }
            rules.append(sigma.to_yaml(rule))
        for f in findings:
            f["confidence"] = "medium"
        summary = f"{len(findings)} findings from a sample of {n} events (threshold {thr})."
        text = (
            summary + "\n```json\n" + json.dumps({"summary": summary, "findings": findings, "rules": rules}) + "\n```"
        )
        blocks = [{"type": "text", "text": text}]
        return LLMResponse(blocks, text, [], _tok(messages), _tok(blocks), "end_turn")


async def run_baseline(provider, hypothesis: str, events: list[dict], log_types: list[str], seed: int) -> dict:
    """One call, then the same grounding check as the agent (evidence must be in what the model was shown)."""
    t0 = time.monotonic()
    prompt, shown = build_prompt(hypothesis, events, log_types, seed)
    resp = await provider.complete(BASELINE_SYSTEM, [{"role": "user", "content": prompt}], [], 8_000)
    final = parse_final(resp.text)
    findings = []
    for f in final["findings"]:
        ev = [e for e in f.get("evidence", []) if isinstance(e, str) and EVENT_ID_RE.fullmatch(e)]
        findings.append({**f, "evidence": ev, "verified": bool(ev) and set(ev) <= shown})
    return {
        "findings": findings,
        "rules": [r for r in final.get("rules", []) if isinstance(r, str)],
        "steps": 1,
        "tool_calls": 0,
        "input_tokens": resp.input_tokens,
        "output_tokens": resp.output_tokens,
        "elapsed_s": round(time.monotonic() - t0, 4),
        "sample_events": len(shown),
    }


def load_events(data_dir: Path) -> list[dict]:
    from service.store import LogStore

    return LogStore(data_dir).events
