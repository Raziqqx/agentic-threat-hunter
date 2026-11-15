"""Baseline vs agent evaluation: per-technique precision/recall, evidence correctness, cost and latency.

python -m eval.run_eval [--seeds 7 21 42] [--provider mock|anthropic] [--out results]

For each seed a fresh dataset is generated, then each hypothesis is hunted by the single-prompt baseline and
by the agent. Every proposed rule is parsed by the Sigma validator and run over the full logs; hits are scored
against the ground-truth labels. With the mock provider only hypotheses marked `"mock": true` are run, because
the mock implements one playbook (SSH brute force); the real provider runs them all.
"""

from __future__ import annotations

import argparse
import csv
import json
import tempfile
import time
from collections import defaultdict
from datetime import UTC, datetime
from pathlib import Path
from statistics import mean

import anyio
from mcp import Client

from agent.llm import MockProvider, make_provider
from agent.loop import HuntAgent
from datagen.generate import generate
from service.server import build_server

from .baseline import MockBaselineProvider, load_events, run_baseline
from .sigma_validator import SigmaError, parse_rule

HYPOTHESES = Path(__file__).with_name("hypotheses.json")


def load_labels(data_dir: Path) -> tuple[dict[str, set[str]], dict[str, list[str]]]:
    """Ground truth per technique (union over chains) and the techniques of each chain."""
    doc = json.loads((data_dir / "labels.json").read_text())
    gt: dict[str, set[str]] = defaultdict(set)
    chains = {}
    for c in doc["chains"]:
        chains[c["chain_id"]] = [s["technique"] for s in c["steps"]]
        for s in c["steps"]:
            gt[s["technique"]].update(s["event_ids"])
    return gt, chains


def rule_hits(rules_yaml: list[str], events: list[dict]) -> tuple[dict[str, set[str]], int]:
    """Validate and run each rule; returns hits per tagged technique and the number of invalid rules."""
    hits: dict[str, set[str]] = defaultdict(set)
    invalid = 0
    for text in rules_yaml:
        try:
            rule = parse_rule(text)
        except SigmaError:
            invalid += 1
            continue
        ids = set(rule.hits(events))
        for t in rule.techniques:
            hits[t] |= ids
    return hits, invalid


def _ratio(num: int, den: int) -> float | None:
    return round(num / den, 4) if den else None


def score(hunt: dict, techniques: list[str], gt: dict[str, set[str]], events: list[dict]) -> list[dict]:
    hits, invalid = rule_hits(hunt["rules"], events)
    rows = []
    for t in techniques:
        truth = gt[t]
        cited = {e for f in hunt["findings"] if f.get("technique") == t for e in f["evidence"]}
        h = hits.get(t, set())
        rows.append(
            {
                "technique": t,
                "gt_events": len(truth),
                "rule_hits": len(h),
                "rule_tp": len(h & truth),
                "rule_precision": _ratio(len(h & truth), len(h)),
                "rule_recall": round(len(h & truth) / len(truth), 4),
                "cited": len(cited),
                "cited_tp": len(cited & truth),
                "evidence_precision": _ratio(len(cited & truth), len(cited)),
                "detected": int(bool(cited & truth)),
                "invalid_rules": invalid,
            }
        )
    return rows


async def run_agent(provider, data_dir: Path, hypothesis: str, audit: Path) -> dict:
    t0 = time.monotonic()
    async with Client(build_server(data_dir, audit)) as session:
        report = (await HuntAgent(provider, session).run(hypothesis)).to_dict()
    report["wall_s"] = round(time.monotonic() - t0, 4)  # includes MCP session setup
    report["rules"] = [r["sigma_yaml"] for r in report["rules"]]
    return report


async def evaluate(seeds: list[int], provider_kind: str, out: Path) -> dict:
    hyps = json.loads(HYPOTHESES.read_text())
    if provider_kind == "mock":
        hyps = [h for h in hyps if h["mock"]]
    tech_rows, cost_rows = [], []
    with tempfile.TemporaryDirectory() as tmp:
        for seed in seeds:
            data_dir = Path(tmp) / f"seed{seed}"
            generate(seed, data_dir)
            gt, chains = load_labels(data_dir)
            events = load_events(data_dir)
            for h in hyps:
                if provider_kind == "mock":
                    agent_llm, base_llm = MockProvider(), MockBaselineProvider()
                else:
                    agent_llm, base_llm = make_provider(provider_kind), make_provider(provider_kind)
                t0 = time.monotonic()
                base = await run_baseline(base_llm, h["text"], events, h["log_types"], seed)
                base["wall_s"] = round(time.monotonic() - t0, 4)
                agent = await run_agent(agent_llm, data_dir, h["text"], Path(tmp) / f"audit-{seed}-{h['id']}.jsonl")
                for system, hunt in (("baseline", base), ("agent", agent)):
                    meta = {"seed": seed, "hypothesis": h["id"], "system": system}
                    tech_rows += [meta | r for r in score(hunt, chains[h["chain"]], gt, events)]
                    cost_rows.append(
                        meta
                        | {
                            "llm_calls": hunt["steps"],
                            "tool_calls": hunt["tool_calls"],
                            "input_tokens": hunt["input_tokens"],
                            "output_tokens": hunt["output_tokens"],
                            "tokens_are_estimates": int(provider_kind == "mock"),
                            "wall_s": hunt["wall_s"],
                            "findings": len(hunt["findings"]),
                            "grounded_findings": sum(f["verified"] for f in hunt["findings"]),
                            "rules": len(hunt["rules"]),
                        }
                    )
    out.mkdir(parents=True, exist_ok=True)
    _write_csv(out / "eval_techniques.csv", tech_rows)
    _write_csv(out / "eval_cost.csv", cost_rows)
    (out / "eval.md").write_text(render_md(tech_rows, cost_rows, seeds, provider_kind))
    return {"techniques": tech_rows, "cost": cost_rows}


def _write_csv(path: Path, rows: list[dict]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def _mean(vals) -> str:
    vals = [v for v in vals if v is not None]
    return f"{mean(vals):.3f}" if vals else "n/a"


def render_md(tech_rows: list[dict], cost_rows: list[dict], seeds: list[int], provider: str) -> str:
    est = " (estimated, ~4 chars/token)" if provider == "mock" else ""
    lines = [
        "# Evaluation: single-prompt baseline vs agent",
        "",
        f"Generated by `make eval` on {datetime.now(UTC):%Y-%m-%d %H:%M UTC}. Provider: `{provider}`. "
        f"Seeds: {', '.join(map(str, seeds))}. Values are means over seeds; `n/a` = no rule/evidence for that "
        "technique, so precision is undefined. Rule metrics come from running each proposed rule through the "
        "Sigma validator over the full logs. Per-run rows: `eval_techniques.csv`, `eval_cost.csv`.",
        "",
        "## Per-technique precision / recall",
        "",
        "| Hyp | Technique | GT events | Base rule P | Base rule R | Agent rule P | Agent rule R "
        "| Base evidence P | Agent evidence P | Base detected | Agent detected |",
        "|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    groups: dict[tuple, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for r in tech_rows:
        groups[(r["hypothesis"], r["technique"])][r["system"]].append(r)
    for (hyp, tech), by in groups.items():
        b, a = by["baseline"], by["agent"]
        lines.append(
            f"| {hyp} | {tech} | {a[0]['gt_events']} "
            f"| {_mean(r['rule_precision'] for r in b)} | {_mean(r['rule_recall'] for r in b)} "
            f"| {_mean(r['rule_precision'] for r in a)} | {_mean(r['rule_recall'] for r in a)} "
            f"| {_mean(r['evidence_precision'] for r in b)} | {_mean(r['evidence_precision'] for r in a)} "
            f"| {_mean(r['detected'] for r in b)} | {_mean(r['detected'] for r in a)} |"
        )
    lines += [
        "",
        "## Summary per system",
        "",
        "| System | Techniques detected | Evidence P (micro) | Rule P (micro) | Rule R (micro) | LLM calls "
        f"| Tool calls | Tokens in{est} | Tokens out{est} | Wall s (mean) | Wall s (max) | Grounded findings |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for system in ("baseline", "agent"):
        t = [r for r in tech_rows if r["system"] == system]
        c = [r for r in cost_rows if r["system"] == system]
        tp_rule, tp_ev = sum(r["rule_tp"] for r in t), sum(r["cited_tp"] for r in t)
        lines.append(
            f"| {system} | {sum(r['detected'] for r in t)}/{len(t)} "
            f"| {_mean([_ratio(tp_ev, sum(r['cited'] for r in t))])} "
            f"| {_mean([_ratio(tp_rule, sum(r['rule_hits'] for r in t))])} "
            f"| {_mean([_ratio(tp_rule, sum(r['gt_events'] for r in t))])} "
            f"| {_mean(r['llm_calls'] for r in c)} | {_mean(r['tool_calls'] for r in c)} "
            f"| {_mean(r['input_tokens'] for r in c)} | {_mean(r['output_tokens'] for r in c)} "
            f"| {_mean(r['wall_s'] for r in c)} | {max(r['wall_s'] for r in c):.3f} "
            f"| {sum(r['grounded_findings'] for r in c)}/{sum(r['findings'] for r in c)} |"
        )
    lines += [
        "",
        "Micro averages pool every (seed, technique) row of a system. Wall time for the agent includes starting "
        "the in-process MCP session; the mock makes no network calls, so latency here is tool and loop overhead, "
        "not model latency.",
        "",
    ]
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--seeds", type=int, nargs="+", default=[7, 21, 42])
    ap.add_argument("--provider", choices=["mock", "anthropic"], default="mock")
    ap.add_argument("--out", type=Path, default=Path("results"))
    args = ap.parse_args()
    anyio.run(evaluate, args.seeds, args.provider, args.out)
    print((args.out / "eval.md").read_text())


if __name__ == "__main__":
    main()
