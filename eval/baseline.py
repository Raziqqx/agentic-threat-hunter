"""Single-prompt baseline: one LLM call with a log sample, no tools, no pivots.

The prompt holds the hypothesis plus a seeded uniform random sample of events from the hypothesis' log types,
filled up to the same character budget the agent may see from one tool result (60 K chars) by default, or to a
larger budget for the budget-matched variant in the eval. The model must answer in one shot with findings and
Sigma rules.

`MockBaselineProvider` is the deterministic stand-in. It is a deliberately *fair* strawman: it applies the same
heuristics as the agent's mock (`agent.llm.MockProvider`), one per hypothesis (brute force, web shell, credential
dumping + cron + beacon, password spraying), to the events in the prompt, with count thresholds scaled down by the
sampling fraction so sampling alone does not hide the attack, and it emits the same rules. What it lacks is exactly
what the agent adds: it cannot query for the events it was not shown, so it cannot pivot (IP -> account -> host,
web shell -> spawned processes, cron entry -> implant -> beacons).
"""

from __future__ import annotations

import json
import random
import re
import time
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from agent.llm import (
    CRON_ENTRY_RE,
    DOWNLOADERS,
    EVENT_ID_RE,
    LLMResponse,
    _tok,
    minutes_before,
    route,
    shell_in_query,
    spawned_by_web_server,
)
from agent.loop import MAX_TOOL_RESULT_CHARS, parse_final
from service import sigma

BASELINE_SYSTEM = """You are a threat hunter working only on synthetic lab logs. You get a hypothesis and a random
sample of log events (JSON lines). You have no tools. Reply with a short summary and one fenced ```json block:
{"summary": str, "findings": [{"technique": "Txxxx[.xxx]", "title": str, "evidence": [event_id, ...],
"confidence": "low|medium|high"}], "rules": [<Sigma rule as a YAML string>]}. Cite only event_ids in the sample."""

SAMPLE_HEADER = "Sample: {n} of {total} events from log types {types}."


def build_prompt(
    hypothesis: str, events: list[dict], log_types: list[str], seed: int, budget_chars: int = MAX_TOOL_RESULT_CHARS
) -> tuple[str, set[str]]:
    """Return the user prompt and the event ids it contains (sample filled up to `budget_chars`)."""
    pool = [e for e in events if e["log_type"] in log_types]
    rng = random.Random(seed)
    order = rng.sample(range(len(pool)), len(pool))
    picked, size = [], 0
    for i in order:
        line = json.dumps(pool[i], separators=(",", ":"))
        if size + len(line) + 1 > budget_chars:
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
    spray_users: int = 15  # same as MockProvider: distinct accounts failing from one source in the full logs
    exploit_window_min: int = 30  # same as MockProvider
    min_threshold: int = 3
    facts: dict = field(default_factory=dict)

    async def complete(self, system, messages, tools, max_tokens) -> LLMResponse:
        prompt = messages[-1]["content"]
        n, total = map(int, re.search(r"Sample: (\d+) of (\d+) events", prompt).groups())
        body = prompt.split("<logs>\n", 1)[1].rsplit("\n</logs>", 1)[0]
        events = [json.loads(line) for line in body.splitlines() if line]
        hypothesis = prompt.split("\n", 1)[0]
        play = {"webshell": self._webshell, "credpersist": self._credpersist, "spray": self._spray}.get(
            route(hypothesis), self._bruteforce
        )
        # Scale count thresholds by the sampling fraction so the strawman is not beaten by sampling alone.
        findings, rules, thr = play(events, lambda full: max(self.min_threshold, round(full * n / max(total, 1))))
        for f in findings:
            f["confidence"] = "medium"
        summary = f"{len(findings)} findings from a sample of {n} events (threshold {thr})."
        text = (
            summary + "\n```json\n" + json.dumps({"summary": summary, "findings": findings, "rules": rules}) + "\n```"
        )
        blocks = [{"type": "text", "text": text}]
        return LLMResponse(blocks, text, [], _tok(messages), _tok(blocks), "end_turn")

    @staticmethod
    def _rule(title, technique, log_type, selection, description) -> str:
        return sigma.to_yaml(
            {
                "title": title,
                "id": "00000000-0000-0000-0000-000000000000",
                "technique": technique,
                "log_type": log_type,
                "selection": selection,
                "description": description,
            }
        )

    def _webshell(self, events, scale):
        """Same heuristics as MockProvider._webshell, applied only to the sampled web and process events."""
        findings, rules = [], []
        shells = [e for e in events if e["log_type"] == "web" and shell_in_query(e["uri"])]
        if shells:
            e0 = shells[0]
            ip, host, path = e0["src_ip"], e0["host"], urlsplit(e0["uri"]).path
            shells = [e for e in shells if e["src_ip"] == ip and e["host"] == host]
            findings.append(
                {"technique": "T1505.003", "title": f"Web shell {path}", "evidence": [e["event_id"] for e in shells]}
            )
            lo, t0, t1 = minutes_before(shells[0]["ts"], self.exploit_window_min), shells[0]["ts"], shells[-1]["ts"]
            prior = [
                e["event_id"]
                for e in events
                if e["log_type"] == "web"
                and e["src_ip"] == ip
                and lo <= e["ts"] <= t0
                and urlsplit(e["uri"]).path != path
            ]
            if prior:
                findings.append({"technique": "T1190", "title": "Exploitation before the web shell", "evidence": prior})
            procs = [
                e
                for e in events
                if e["log_type"] == "process" and e["host"] == host and t0 <= e["ts"] <= t1 and spawned_by_web_server(e)
            ]
            dl = [e["event_id"] for e in procs if any(d in e["cmdline"] for d in DOWNLOADERS)]
            sh = [e["event_id"] for e in procs if e["event_id"] not in dl]
            if sh:
                findings.append({"technique": "T1059.004", "title": "Shell spawned by the web server", "evidence": sh})
            if dl:
                findings.append({"technique": "T1105", "title": "Tool download", "evidence": dl})
            rules.append(
                self._rule(
                    "Requests to a web shell path", "T1505.003", "web", {"uri|startswith": path}, "Web shell path."
                )
            )
        return findings, rules, None

    def _credpersist(self, events, scale):
        """Same heuristics as MockProvider._credpersist, applied only to the sampled process and conn events."""
        findings, rules = [], []
        proc = [e for e in events if e["log_type"] == "process"]
        shadow = [e["event_id"] for e in proc if "/etc/shadow" in e["cmdline"]]
        if shadow:
            findings.append({"technique": "T1003.008", "title": "/etc/shadow read", "evidence": shadow})
        cron = [(e, m.group(1)) for e in proc if (m := CRON_ENTRY_RE.search(e["cmdline"]))]
        if cron:
            (c0, implant), host = cron[0], cron[0][0]["host"]
            findings.append(
                {"technique": "T1053.003", "title": f"Cron job runs {implant}", "evidence": [c0["event_id"]]}
            )
            runs = [e for e in proc if e["host"] == host and e["image"] == implant]
            run_ts = {e["ts"] for e in runs}
            beacons = [
                e["event_id"]
                for e in events
                if e["log_type"] == "conn"
                and e["host"] == host
                and e["ts"] in run_ts
                and not e["dst_ip"].startswith("10.")
            ]
            if runs or beacons:
                ids = [e["event_id"] for e in runs] + beacons
                findings.append({"technique": "T1071.001", "title": f"{implant} runs and beacons", "evidence": ids})
        if shadow:
            rules.append(
                self._rule(
                    "Read of /etc/shadow", "T1003.008", "process", {"cmdline|contains": "/etc/shadow"}, "Shadow read."
                )
            )
        return findings, rules, None

    def _spray(self, events, scale):
        """Same heuristics as MockProvider._spray, with the distinct-account threshold scaled to the sample."""
        findings, rules = [], []
        thr = scale(self.spray_users)
        auth = [e for e in events if e["log_type"] == "auth"]
        users: dict[str, set] = {}
        for e in auth:
            if e["outcome"] == "failure" and "Failed password" in e["message"]:
                users.setdefault(e["src_ip"], set()).add(e["user"])
        spray = sorted(ip for ip, u in users.items() if len(u) >= thr)
        if spray:
            ip = max(spray, key=lambda i: len(users[i]))
            ids = [e["event_id"] for e in auth if e["src_ip"] == ip and e["outcome"] == "failure"]
            findings.append({"technique": "T1110.003", "title": f"Password spraying from {ip}", "evidence": ids})
            ok = [e for e in auth if e["src_ip"] == ip and e["outcome"] == "success"]
            if ok:
                s = ok[0]
                findings.append({"technique": "T1078", "title": "Login after spraying", "evidence": [s["event_id"]]})
                new = [
                    e["event_id"]
                    for e in events
                    if e["log_type"] == "process"
                    and e["host"] == s["host"]
                    and e["ts"] >= s["ts"]
                    and "useradd" in e["cmdline"]
                ]
                if new:
                    findings.append({"technique": "T1136.001", "title": "Local account created", "evidence": new})
            rules.append(
                self._rule(
                    "SSH password spraying sources",
                    "T1110.003",
                    "auth",
                    {"outcome": "failure", "src_ip": spray},
                    "Failed SSH logins from sources that failed for many accounts in the sample.",
                )
            )
        return findings, rules, thr

    def _bruteforce(self, events, scale):
        auth = [e for e in events if e["log_type"] == "auth"]
        thr = scale(self.threshold)
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
        return findings, rules, thr


async def run_baseline(
    provider,
    hypothesis: str,
    events: list[dict],
    log_types: list[str],
    seed: int,
    budget_chars: int = MAX_TOOL_RESULT_CHARS,
) -> dict:
    """One call, then the same grounding check as the agent (evidence must be in what the model was shown)."""
    t0 = time.monotonic()
    prompt, shown = build_prompt(hypothesis, events, log_types, seed, budget_chars)
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
