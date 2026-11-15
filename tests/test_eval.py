import csv

import anyio

from eval.run_eval import evaluate


def test_eval_writes_results_and_agent_beats_baseline(tmp_path):
    anyio.run(evaluate, [7], "mock", tmp_path)
    rows = list(csv.DictReader(open(tmp_path / "eval_techniques.csv")))
    by = {(r["system"], r["technique"]): r for r in rows}
    agent = by[("agent", "T1110.001")]
    assert float(agent["rule_recall"]) == 1.0 and int(agent["invalid_rules"]) == 0
    assert sum(int(r["detected"]) for r in rows if r["system"] == "agent") > sum(
        int(r["detected"]) for r in rows if r["system"] == "baseline"
    )
    cost = {r["system"]: r for r in csv.DictReader(open(tmp_path / "eval_cost.csv")) if r["hypothesis"] == "H1"}
    assert cost["baseline"]["llm_calls"] == "1" and cost["baseline"]["tool_calls"] == "0"
    assert cost["agent"]["tokens_are_estimates"] == "1"
    assert {r["hypothesis"] for r in rows} == {"H1", "H2", "H3", "H4"}  # every playbook runs on the mock
    assert "baseline_matched" in cost
    md = (tmp_path / "eval.md").read_text()
    assert "Per-technique" in md and "not LLM hunting capability" in md and "Unequal budget" in md
