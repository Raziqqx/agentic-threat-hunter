import json

import pytest
from mcp import Client

from agent.llm import LLMResponse, MockProvider, ToolCall, make_provider
from agent.loop import ApprovalGate, Budgets, HuntAgent, parse_final
from service.server import build_server

pytestmark = pytest.mark.anyio
HYPOTHESIS = "SSH brute force against internet-facing servers followed by data theft"


@pytest.fixture
def labels(dataset):
    doc = json.loads((dataset / "labels.json").read_text())
    return {c["chain_id"]: {s["technique"]: set(s["event_ids"]) for s in c["steps"]} for c in doc["chains"]}


async def run_hunt(dataset, tmp_path, provider=None, budgets=None, gate=None, hypothesis=HYPOTHESIS):
    server = build_server(dataset, tmp_path / "audit.jsonl")
    async with Client(server) as session:
        agent = HuntAgent(provider or MockProvider(), session, budgets, gate)
        return await agent.run(hypothesis)


def assert_grounded_and_correct(report, chain_labels, techniques):
    """Every finding is verified, cites only ground-truth events for its technique, and all techniques are hit."""
    assert report.stop_reason == "completed"
    assert {f["technique"] for f in report.findings} == set(techniques)
    for f in report.findings:
        assert f["verified"], f
        assert set(f["evidence"]) <= chain_labels[f["technique"]], f["technique"]


async def test_end_to_end_mock_hunt_finds_chain_c1(dataset, tmp_path, labels):
    report = await run_hunt(dataset, tmp_path)
    assert report.stop_reason == "completed"
    techs = {f["technique"]: f for f in report.findings}
    assert set(techs) == {"T1110.001", "T1078", "T1021.004", "T1048"}
    c1 = labels["C1"]
    for tech, f in techs.items():
        assert f["verified"], f  # every cited event was seen in a tool result
        assert set(f["evidence"]) <= c1[tech], tech  # and is ground-truth evidence for that technique
    # A proposed rule was dry-run and covers the C1 brute-force events.
    assert len(report.rules) == 1
    rule = report.rules[0]
    assert rule["rule"]["technique"] == "T1110.001" and rule["dry_run_hits"] >= len(c1["T1110.001"])
    # The containment recommendation hit the gate and was auto-denied.
    assert report.actions == [
        {
            "action": "block_ip",
            "target": "203.0.113.66",
            "justification": "Confirmed brute force source",
            "decision": "denied",
        }
    ]
    # Every MCP call was audited server-side.
    audit = (tmp_path / "audit.jsonl").read_text().splitlines()
    assert len(audit) == report.tool_calls - len(report.actions)


async def test_approval_flag_approves(dataset, tmp_path):
    report = await run_hunt(dataset, tmp_path, gate=ApprovalGate("approve"))
    assert report.actions[0]["decision"] == "approved"


async def test_prompt_gate_uses_answer(dataset, tmp_path):
    report = await run_hunt(dataset, tmp_path, gate=ApprovalGate("prompt", ask=lambda _: "n"))
    assert report.actions[0]["decision"] == "denied"


async def test_step_budget(dataset, tmp_path):
    report = await run_hunt(dataset, tmp_path, budgets=Budgets(max_steps=2))
    assert report.stop_reason == "step_budget" and report.steps == 2 and report.findings == []


async def test_token_budget(dataset, tmp_path):
    report = await run_hunt(dataset, tmp_path, budgets=Budgets(max_tokens=500))
    assert report.stop_reason == "token_budget" and report.steps == 2  # step 2 reads the 169 failures


class SlowProvider(MockProvider):
    async def complete(self, *a, **k):
        import anyio

        await anyio.sleep(5)


async def test_time_budget(dataset, tmp_path):
    report = await run_hunt(dataset, tmp_path, provider=SlowProvider(), budgets=Budgets(max_seconds=0.2))
    assert report.stop_reason == "time_budget" and report.elapsed_s < 2


class RogueProvider(MockProvider):
    """Tries a tool outside the allow-list, then cites evidence it never saw."""

    async def complete(self, system, messages, tools, max_tokens):
        if len(messages) == 1:
            call = ToolCall("r1", "delete_logs", {"host": "web-01"})
            return LLMResponse(
                [{"type": "tool_use", "id": "r1", "name": "delete_logs", "input": call.input}],
                "",
                [call],
                10,
                10,
                "tool_use",
            )
        text = (
            '```json\n{"summary": "x", "findings": [{"technique": "T1078", "title": "t", '
            '"evidence": ["auth-000001"]}]}\n```'
        )
        return LLMResponse([{"type": "text", "text": text}], text, [], 10, 10, "end_turn")


async def test_disallowed_tool_and_unverified_evidence(dataset, tmp_path):
    report = await run_hunt(dataset, tmp_path, provider=RogueProvider())
    assert report.trace[0]["results"][0]["error"] is True
    assert report.findings[0]["verified"] is False
    assert not (tmp_path / "audit.jsonl").exists()  # the server never saw the call


def test_parse_final_and_provider_selection(monkeypatch):
    assert parse_final('ok ```json\n{"findings": []}\n```')["findings"] == []
    assert parse_final("no json")["findings"] == []
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    assert make_provider("auto").name == "mock"


async def test_mock_web_shell_playbook_finds_chain_c2(dataset, tmp_path, labels):
    report = await run_hunt(
        dataset, tmp_path, hypothesis="Exploitation of the public web server leading to a web shell"
    )
    assert_grounded_and_correct(report, labels["C2"], ["T1505.003", "T1190", "T1059.004", "T1105"])
    # The web-shell rule matches exactly the shell requests.
    rule = report.rules[0]
    assert rule["rule"]["technique"] == "T1505.003" and rule["dry_run_hits"] == len(labels["C2"]["T1505.003"])
    assert [a["action"] for a in report.actions] == ["block_ip"]


async def test_mock_credential_persistence_playbook_finds_chain_c3(dataset, tmp_path, labels):
    report = await run_hunt(
        dataset, tmp_path, hypothesis="Credential dumping and persistence followed by command-and-control beaconing"
    )
    assert_grounded_and_correct(report, labels["C3"], ["T1003.008", "T1053.003", "T1071.001"])
    beacons = {e for f in report.findings if f["technique"] == "T1071.001" for e in f["evidence"]}
    assert beacons == labels["C3"]["T1071.001"]  # every implant run and its beacon, via the cron pivot
    assert report.rules[0]["dry_run_hits"] == len(labels["C3"]["T1003.008"])
    assert [a["action"] for a in report.actions] == ["isolate_host"]


async def test_mock_password_spray_playbook_finds_chain_c4(dataset, tmp_path, labels):
    report = await run_hunt(
        dataset, tmp_path, hypothesis="Password spraying against SSH and creation of new local accounts"
    )
    assert_grounded_and_correct(report, labels["C4"], ["T1110.003", "T1078", "T1136.001"])
    spray = next(f for f in report.findings if f["technique"] == "T1110.003")
    assert set(spray["evidence"]) == labels["C4"]["T1110.003"]
    assert report.rules[0]["dry_run_hits"] == len(labels["C4"]["T1110.003"])
