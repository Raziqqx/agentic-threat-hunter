"""Pluggable LLM providers: Anthropic (real API, key from the environment) or a deterministic mock.

Both speak the Anthropic Messages shape: `messages` is a list of {"role", "content": [blocks]}.
"""

from __future__ import annotations

import json
import os
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Protocol
from urllib.parse import parse_qsl, urlsplit

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


# Generic hunting heuristics shared by the agent mock and the baseline mock. None of them name ground-truth values.
WEB_SERVERS = ("php-fpm", "php-cgi", "apache2", "httpd", "nginx")  # parents that should not spawn shells
SHELL_CMDS = {"id", "whoami", "uname", "cat", "ls", "pwd", "wget", "curl", "sh", "bash", "nc"}
DOWNLOADERS = ("wget ", "curl ")
CRON_ENTRY_RE = re.compile(r"(?:[\d*/,-]+\s+){5}(/[^\s'\";]+)")  # "*/30 * * * * /path" -> /path


def shell_in_query(uri: str) -> bool:
    """True if a query-string value starts with a shell command (web-shell style `?c=id`)."""
    return any(v.split() and v.split()[0] in SHELL_CMDS for _, v in parse_qsl(urlsplit(uri).query))


def minutes_before(ts: str, minutes: int) -> str:
    """ISO-8601 'Z' timestamp `minutes` earlier, in the logs' own format."""
    t = datetime.fromisoformat(ts.replace("Z", "+00:00")) - timedelta(minutes=minutes)
    return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"


def spawned_by_web_server(e: dict) -> bool:
    return e["parent_image"].rsplit("/", 1)[-1] in WEB_SERVERS


def route(hypothesis: str) -> str:
    """Pick a mock playbook from the hypothesis wording (what a hunter would read), not from the labels."""
    h = hypothesis.lower()
    if "web shell" in h or "web server" in h:
        return "webshell"
    if "credential dump" in h or "beacon" in h:
        return "credpersist"
    if "spray" in h:
        return "spray"
    return "bruteforce"


def _tok(obj) -> int:
    """Deterministic token estimate for the mock (~4 chars per token)."""
    return max(1, len(json.dumps(obj, default=str)) // 4)


@dataclass
class MockProvider:
    """Scripted, deterministic hunter with four playbooks (SSH brute force, web shell, credential dumping and
    cron persistence with beaconing, password spraying), chosen from the hypothesis text.

    It is not a lookup of the answers: every pivot (source IP, account, host, timestamps) is derived from
    the tool results it receives, so it exercises the real loop, tools and safeguards end to end.
    """

    name: str = "mock"
    threshold: int = 20  # failed logins from one source that count as brute force
    exploit_window_min: int = 30  # how far before the first web-shell hit to look for the exploit
    spray_users: int = 15  # distinct accounts failing from one source that count as spraying
    playbook: str = ""
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

    def _add(self, technique, title, ids, confidence="high"):
        if ids:
            self.facts.setdefault("findings", []).append(
                {"technique": technique, "title": title, "evidence": list(ids), "confidence": confidence}
            )

    def _final(self, messages):
        f = self.facts
        findings = list(f.get("findings", []))
        if f.get("fail_ids"):
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
        if not self.playbook:
            first = messages[0]["content"]
            self.playbook = route(first if isinstance(first, str) else json.dumps(first))
        res = self._last_results(messages)
        r = res[0] if res else {}
        if self.playbook == "webshell":
            return self._webshell(r, messages)
        if self.playbook == "credpersist":
            return self._credpersist(r, messages)
        if self.playbook == "spray":
            return self._spray(r, messages)
        return self._bruteforce(r, messages)

    def _webshell(self, r, messages):
        """Shell commands in web query strings -> attacker IP -> earlier exploitation -> spawned processes."""
        f = self.facts
        if self.phase == 0:
            self.phase = 1
            return self._call(
                "search_logs",
                {"log_type": "web", "contains": ".php?", "limit": 200},
                messages,
                "Look for script requests whose parameters carry shell commands.",
            )
        if self.phase == 1:
            shells = [e for e in r.get("events", []) if shell_in_query(e["uri"])]
            if not shells:
                return self._final(messages)
            e0 = shells[0]
            shells = [e for e in shells if e["src_ip"] == e0["src_ip"] and e["host"] == e0["host"]]
            f.update(ip=e0["src_ip"], host=e0["host"], path=urlsplit(e0["uri"]).path)
            f.update(t0=shells[0]["ts"], t1=shells[-1]["ts"])
            self._add("T1505.003", f"Web shell {f['path']} on {f['host']}", [e["event_id"] for e in shells])
            self.phase = 2
            return self._call(
                "search_logs",
                {
                    "log_type": "web",
                    "ip": f["ip"],
                    "start": minutes_before(f["t0"], self.exploit_window_min),
                    "end": f["t0"],
                    "limit": 200,
                },
                messages,
                f"What did {f['ip']} do in the 30 minutes before the first shell request?",
            )
        if self.phase == 2:
            prior = [e["event_id"] for e in r.get("events", []) if urlsplit(e["uri"]).path != f["path"]]
            self._add("T1190", f"Exploitation of {f['host']} by {f['ip']}", prior, "medium")
            self.phase = 3
            return self._call(
                "search_logs",
                {"log_type": "process", "host": f["host"], "start": f["t0"], "end": f["t1"], "limit": 200},
                messages,
                "Which processes did the web server spawn while the shell was used?",
            )
        if self.phase == 3:
            procs = [e for e in r.get("events", []) if spawned_by_web_server(e)]
            dl = [e["event_id"] for e in procs if any(d in e["cmdline"] for d in DOWNLOADERS)]
            self._add(
                "T1059.004",
                "Shell commands spawned by the web server",
                [e["event_id"] for e in procs if e["event_id"] not in dl],
            )
            f["dl"] = dl
            self.phase = 4
            return self._call(
                "search_logs",
                {"log_type": "conn", "host": f["host"], "ip": f["ip"], "start": f["t0"], "limit": 50},
                messages,
                "Did the host connect back to the attacker?",
            )
        if self.phase == 4:
            self._add(
                "T1105", "Tool download from the attacker", f["dl"] + [e["event_id"] for e in r.get("events", [])]
            )
            self.phase = 5
            return self._call(
                "propose_detection_rule",
                {
                    "title": "Requests to a known web shell path",
                    "technique": "T1505.003",
                    "log_type": "web",
                    "selection": {"uri|startswith": f["path"]},
                    "description": "Requests to the web shell found during the hunt.",
                },
                messages,
                "Draft a detection rule.",
            )
        if self.phase == 5:
            self.phase = 6
            return self._call(
                "request_response_action",
                {"action": "block_ip", "target": f["ip"], "justification": "Web shell operator"},
                messages,
                "Recommend blocking the operator (needs human approval).",
            )
        return self._final(messages)

    def _credpersist(self, r, messages):
        """/etc/shadow read -> crontab change on that host -> the scheduled binary -> its outbound beacons."""
        f = self.facts
        if self.phase == 0:
            self.phase = 1
            return self._call(
                "search_logs",
                {"log_type": "process", "contains": "/etc/shadow", "limit": 50},
                messages,
                "Look for reads of the password hash file.",
            )
        if self.phase == 1:
            ev = r.get("events", [])
            if not ev:
                return self._final(messages)
            f.update(host=ev[0]["host"], t0=ev[0]["ts"])
            self._add("T1003.008", f"/etc/shadow read on {f['host']}", [e["event_id"] for e in ev])
            self.phase = 2
            return self._call(
                "search_logs",
                {"log_type": "process", "host": f["host"], "contains": "crontab", "start": f["t0"], "limit": 50},
                messages,
                f"Any persistence on {f['host']} afterwards?",
            )
        if self.phase == 2:
            cron = [(e, m.group(1)) for e in r.get("events", []) if (m := CRON_ENTRY_RE.search(e["cmdline"]))]
            self.phase = 6
            if cron:
                f["implant"] = cron[0][1]
                self._add("T1053.003", f"Cron job runs {f['implant']}", [e["event_id"] for e, _ in cron])
                self.phase = 3
                return self._call(
                    "search_logs",
                    {
                        "log_type": "process",
                        "host": f["host"],
                        "contains": f["implant"],
                        "start": f["t0"],
                        "limit": 200,
                    },
                    messages,
                    f"How often does {f['implant']} run?",
                )
        if self.phase == 3:
            runs = [e for e in r.get("events", []) if e["image"] == f["implant"]]
            self._add("T1071.001", f"Scheduled {f['implant']} executions", [e["event_id"] for e in runs], "medium")
            self.phase = 6
            if runs:
                f["run_ts"] = {e["ts"] for e in runs}
                self.phase = 4
                return self._call(
                    "search_logs",
                    {"log_type": "conn", "host": f["host"], "start": runs[0]["ts"], "end": runs[0]["ts"], "limit": 20},
                    messages,
                    "What did the first run connect to?",
                )
        if self.phase == 4:
            ext = [e for e in r.get("events", []) if not e["dst_ip"].startswith("10.")]
            self.phase = 6
            if ext:
                f["c2"] = ext[0]["dst_ip"]
                self.phase = 5
                return self._call(
                    "search_logs",
                    {"log_type": "conn", "host": f["host"], "ip": f["c2"], "limit": 200},
                    messages,
                    f"All connections from {f['host']} to {f['c2']}.",
                )
        if self.phase == 5:
            beacons = [e["event_id"] for e in r.get("events", []) if e["ts"] in f["run_ts"]]
            self._add("T1071.001", f"Periodic beacons to {f['c2']}", beacons)
            self.phase = 6
        if self.phase == 6:
            self.phase = 7
            return self._call(
                "propose_detection_rule",
                {
                    "title": "Read of /etc/shadow",
                    "technique": "T1003.008",
                    "log_type": "process",
                    "selection": {"cmdline|contains": "/etc/shadow"},
                    "description": "Any process reading the local password hash file.",
                },
                messages,
                "Draft a detection rule.",
            )
        if self.phase == 7:
            self.phase = 8
            return self._call(
                "request_response_action",
                {"action": "isolate_host", "target": f["host"], "justification": "Credential dumping and C2 beaconing"},
                messages,
                "Recommend isolating the host (needs human approval).",
            )
        return self._final(messages)

    def _spray(self, r, messages):
        """Failed logins for many accounts from one source -> its successful login -> new local accounts."""
        f = self.facts
        if self.phase == 0:
            self.phase, f["fails"] = 1, {}
            return self._call(
                "search_logs",
                {"log_type": "auth", "contains": "Failed password", "limit": 200},
                messages,
                "Collect failed SSH logins.",
            )
        if self.phase == 1:
            ev = r.get("events", [])
            new = [e for e in ev if e["event_id"] not in f["fails"]]
            f["fails"].update((e["event_id"], e) for e in ev)
            if r.get("truncated") and new:  # page forward by time until everything has been seen
                return self._call(
                    "search_logs",
                    {"log_type": "auth", "contains": "Failed password", "start": ev[-1]["ts"], "limit": 200},
                    messages,
                    "More failures; next page.",
                )
            users: dict[str, set] = {}
            for e in f["fails"].values():
                users.setdefault(e["src_ip"], set()).add(e["user"])
            spray = sorted(ip for ip, u in users.items() if len(u) >= self.spray_users)
            if not spray:
                return self._final(messages)
            ip = max(spray, key=lambda i: len(users[i]))
            f.update(ip=ip, spray=spray)
            ids = [e["event_id"] for e in f["fails"].values() if e["src_ip"] == ip]
            self._add("T1110.003", f"Password spraying from {ip} ({len(users[ip])} accounts)", ids)
            self.phase = 2
            return self._call(
                "search_logs",
                {"log_type": "auth", "ip": ip, "contains": "Accepted", "limit": 20},
                messages,
                "Did any sprayed account log in?",
            )
        if self.phase == 2:
            self.phase = 4
            if r.get("events"):
                s = r["events"][0]
                self._add("T1078", f"Login as {s['user']} on {s['host']} after spraying", [s["event_id"]])
                self.phase = 3
                return self._call(
                    "search_logs",
                    {"log_type": "process", "host": s["host"], "contains": "useradd", "start": s["ts"], "limit": 20},
                    messages,
                    f"Were accounts created on {s['host']} afterwards?",
                )
        if self.phase == 3:
            self._add("T1136.001", "Local account created", [e["event_id"] for e in r.get("events", [])])
            self.phase = 4
        if self.phase == 4:
            self.phase = 5
            return self._call(
                "propose_detection_rule",
                {
                    "title": "SSH password spraying sources",
                    "technique": "T1110.003",
                    "log_type": "auth",
                    "selection": {"outcome": "failure", "src_ip": f["spray"]},
                    "description": "Failed SSH logins from sources that failed for many accounts.",
                },
                messages,
                "Draft a detection rule.",
            )
        if self.phase == 5:
            self.phase = 6
            return self._call(
                "request_response_action",
                {"action": "block_ip", "target": f["ip"], "justification": "Password spraying source"},
                messages,
                "Recommend blocking the source (needs human approval).",
            )
        return self._final(messages)

    def _bruteforce(self, r, messages):
        f = self.facts
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
