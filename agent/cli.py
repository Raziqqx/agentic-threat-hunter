"""Run one hunt: spawns the MCP server over stdio and drives it with the agent.

python -m agent.cli --hypothesis "SSH brute force against internet-facing servers" [--approve]
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import anyio
from mcp import Client, StdioServerParameters

from .llm import DEFAULT_MODEL, make_provider
from .loop import ApprovalGate, Budgets, HuntAgent


async def hunt(args) -> dict:
    params = StdioServerParameters(
        command=sys.executable, args=["-m", "service.server", "--data", str(args.data), "--audit", str(args.audit)]
    )
    gate = ApprovalGate("approve" if args.approve else "prompt" if args.interactive else "deny")
    budgets = Budgets(max_steps=args.max_steps, max_tokens=args.max_tokens, max_seconds=args.max_seconds)
    async with Client(params) as session:
        report = await HuntAgent(make_provider(args.provider, args.model), session, budgets, gate).run(args.hypothesis)
    return report.to_dict()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--hypothesis", required=True)
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--audit", type=Path, default=Path("results/audit.jsonl"))
    ap.add_argument("--out", type=Path, default=Path("results/runs"))
    ap.add_argument("--provider", choices=["auto", "mock", "anthropic"], default="auto")
    ap.add_argument("--model", default=DEFAULT_MODEL)
    ap.add_argument("--approve", action="store_true", help="approve gated containment recommendations")
    ap.add_argument("--interactive", action="store_true", help="ask on the terminal for each gated action")
    ap.add_argument("--max-steps", type=int, default=12)
    ap.add_argument("--max-tokens", type=int, default=200_000)
    ap.add_argument("--max-seconds", type=float, default=300.0)
    args = ap.parse_args()
    report = anyio.run(hunt, args)
    args.out.mkdir(parents=True, exist_ok=True)
    path = args.out / f"hunt-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.json"
    path.write_text(json.dumps(report, indent=2, default=str))
    print(
        f"{report['stop_reason']}: {len(report['findings'])} findings, {len(report['rules'])} rules, "
        f"{report['steps']} steps, {report['input_tokens'] + report['output_tokens']} tokens -> {path}"
    )
    for f in report["findings"]:
        print(f"  [{f['technique']}] {f['title']} (verified={f['verified']}, evidence={len(f['evidence'])})")
    for a in report["actions"]:
        print(f"  action {a['action']} {a['target']}: {a['decision']}")


if __name__ == "__main__":
    main()
