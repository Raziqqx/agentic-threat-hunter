import csv

import anyio

from eval.run_eval import evaluate


def test_eval_writes_results_and_agent_beats_baseline(tmp_path):
    anyio.run(evaluate, [7], "mock", tmp_path)
    rows = list(csv.DictReader(open(tmp_path / "eval_techniques.csv")))
    by = {(r["system"], r["technique"]): r for r in rows}
    agent, base = by[("agent", "T1110.001")], by[("baseline", "T1110.001")]
    assert float(agent["rule_recall"]) == 1.0 and int(agent["invalid_rules"]) == 0
    assert sum(int(r["detected"]) for r in rows if r["system"] == "agent") > sum(
        int(r["detected"]) for r in rows if r["system"] == "baseline"
    )
    cost = {r["system"]: r for r in csv.DictReader(open(tmp_path / "eval_cost.csv"))}
    assert cost["baseline"]["llm_calls"] == "1" and cost["baseline"]["tool_calls"] == "0"
    assert cost["agent"]["tokens_are_estimates"] == "1"
    assert "Per-technique" in (tmp_path / "eval.md").read_text()
