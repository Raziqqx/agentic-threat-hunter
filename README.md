# agentic-threat-hunter

An LLM agent that hunts for attacker activity in security logs. It works through a safeguarded, read-only
MCP server, proposes Sigma detection rules, and is scored against a single-prompt baseline on labelled
MITRE ATT&CK attack chains.

> **Read this first: every number below comes from the mock LLM provider.** The mock is a set of
> author-scripted heuristic playbooks. It pivots only on values returned by tool calls, never on the labels,
> but a human wrote the pivots. So the results show that the pipeline, the MCP tools, the safeguards and the
> scoring work end to end. They do **not** measure LLM hunting capability.
> The real Anthropic provider is implemented (`agent/llm.py`) but **has never been run**, because no API key
> was available.

## What it is

- **Synthetic log generator** (`datagen/`): four seeded JSONL logs (auth, process, conn, web), with four
  labelled attack chains covering 15 technique steps (14 distinct ATT&CK techniques), false-positive bait, and a deliberately partial IOC feed.
- **MCP server** (`service/`): five read-only tools (`search_logs`, `get_host_timeline`, `lookup_ioc`,
  `correlate_events`, `propose_detection_rule`). It has a tool allow-list, strict input validation, result-size
  caps and a JSONL audit log.
- **Agent** (`agent/`): a manual planner-to-tool loop with step, token and wall-time budgets. It also has an
  agent-side allow-list, a human-approval gate for containment recommendations, and an evidence-grounding check.
- **Eval** (`eval/`): agent vs single-prompt baseline vs budget-matched baseline over three seeds. It reports
  per-technique precision and recall for the proposed Sigma rules, evidence precision, cost and latency.

## Why it's hard

- An agent that reads attacker-controlled log text is open to prompt injection. The safeguards have to bound what
  a hijacked model can *do*, even though they cannot stop it from *saying* the wrong thing (see the threat model
  in `DECISIONS.md`).
- Finding a full attack chain means pivoting: IP, then account, then host, then process. A single prompt over a
  sample of the logs cannot fetch the events it was not shown.
- Rules are scored as deployable artefacts. A separate Sigma validator parses the emitted YAML and runs it over
  the full logs. Unsupported Sigma features raise an error instead of silently scoring zero hits.
- Precision needs real noise. Benign typo logins, nightly internal backups and benign outbound HTTPS are planted
  so that a lazy rule loses precision.

## See it working

No GUI: the project is a command-line agent, so "seeing it" means a terminal transcript plus the files it writes.
A captured run of these steps is in [docs/demo_transcript.md](docs/demo_transcript.md). Mock provider, no key needed.

1. **Run one hunt.**
   ```bash
   make venv && make hunt
   ```
   You should see `completed: 4 findings, 1 rules, 8 steps, ... tokens -> results/runs/hunt-<time>.json`, then four
   findings (T1110.001, T1078, T1021.004, T1048), each with `verified=True`, and
   `action block_ip 203.0.113.66: denied` (the human gate denies by default).
2. **Replay what the agent did, step by step, and the Sigma rule it wrote.**
   ```bash
   .venv/bin/python -c "import json,glob; r=json.load(open(sorted(glob.glob('results/runs/hunt-*.json'))[-1])); [print(t['step'], [c['name'] for c in t['tool_calls']], t['text'][:60]) for t in r['trace']]; print(r['rules'][0]['sigma_yaml'])"
   ```
   You should see 8 numbered steps (search_logs, lookup_ioc, search_logs, search_logs, get_host_timeline,
   propose_detection_rule, request_response_action, then the final answer), followed by a Sigma YAML rule tagged
   `attack.t1110.001`.
3. **Read the audit log the MCP server wrote.**
   ```bash
   tail -n 3 results/audit.jsonl
   ```
   You should see one JSON line per tool call with `tool`, `args`, `status: "ok"`, `result_bytes`, `truncated`
   and `duration_ms`.
4. **Approve a containment action through the human gate.**
   ```bash
   echo y | .venv/bin/python -m agent.cli --data data --provider mock --interactive --hypothesis "SSH brute force against internet-facing servers"
   ```
   You should see the prompt `Approve request_response_action {...}? [y/N]` and, at the end,
   `action block_ip 203.0.113.66: approved`. Nothing is executed; the decision is only recorded.
5. **Run the evaluation and open the report.**
   ```bash
   make eval
   ```
   The tables print to the terminal and are written to `results/eval.md`. You should see the agent at 42/45
   techniques detected against 1/45 (baseline) and 5/45 (baseline_matched). Only the wall-time columns change
   between runs.

Each hunt writes a JSON trace to `results/runs/` and appends every MCP tool call to `results/audit.jsonl`.

## Quick start

```bash
make venv            # Python 3.12 venv + requirements
make test            # pytest
make lint            # ruff check + format check
make reproduce       # wipe data/, lint, test, regenerate data, eval, one demo hunt (mock)
```

Useful flags for `python -m agent.cli`:

- `--provider auto|mock|anthropic`: `auto` uses Anthropic only if `ANTHROPIC_API_KEY` is set.
- `--approve`: approve gated containment recommendations.
- `--interactive`: ask on the terminal for each gated action. The default policy is deny.
- `--max-steps`, `--max-tokens`, `--max-seconds`: the hunt budgets.

To measure a real model, set `ANTHROPIC_API_KEY` and run `python -m eval.run_eval --provider anthropic`.
This has not been done yet.

## Key results (mock provider, seeds 7, 21, 42)

Source: `results/eval.md`. Each system faces 45 (seed, technique) cases: 15 technique rows times 3 seeds.

| System | Techniques detected | Evidence P (micro) | Rule P (micro) | Rule R (micro) | LLM calls | Tool calls | Tokens in (est.) | Wall s (mean) |
|---|---|---|---|---|---|---|---|---|
| baseline | 1/45 | 1.000 | 1.000 | 0.115 | 1.000 | 0.000 | 17,575 | 0.010 |
| baseline_matched | 5/45 | 0.492 | 0.488 | 0.432 | 1.000 | 0.000 | 84,221 | 0.024 |
| agent | 42/45 | 1.000 | 0.841 | 0.458 | 7.250 | 6.250 | 71,959 | 0.171 |

All 45 of the agent's findings passed the grounding check (45/45 grounded).

How to read it honestly:

- **Mock caveat.** These numbers validate the pipeline, not an LLM. See the box at the top.
- **Budget gap.** The plain baseline sees about 17,575 estimated input tokens per hunt. The agent uses about
  71,959, because it re-sends its growing history on every call. `baseline_matched` gives the baseline a sample
  sized to the agent's input tokens. It reaches 5/45 detections, against the agent's 42/45. Token counts are
  ~4 chars/token estimates, and no dollar cost is quoted.
- **T1560.001 (archive before exfiltration) is never detected** by any system on any seed. Finding it needs a
  process-log pivot that the playbook does not make.
- **Agent rule precision on T1110.001 is 0.800.** The brute-force rule's "noisy sources" list also contains the
  password-spray source, which is labelled T1110.003. This over-generalisation is real, and it is left visible.
- Wall times for the mock cover only tool and loop overhead, not model latency.

## Safeguards at a glance

| Control | Where |
|---|---|
| Read-only tools; only the audit log is written | `service/server.py` |
| Tool allow-list at registration (`--allow` / `ATH_ALLOWED_TOOLS`) plus an agent-side check | `service/server.py`, `agent/loop.py` |
| Input validation, 200-event limit, 60 KB result cap, audit JSONL | `service/safeguards.py` |
| Step / token / wall-time budgets | `agent/loop.py` |
| Human-approval gate (records decisions, never executes them) | `agent/loop.py` |
| Evidence grounding (cited ids must have appeared in a tool result) | `agent/loop.py` |

These controls do not stop a hijacked model from reporting wrong conclusions, and they do not cover approver
error. Read the full threat model in `DECISIONS.md`.

## Repository layout

```
datagen/generate.py        seeded log + label + IOC generator
service/                   MCP server, store, safeguards, dry-run Sigma matcher
agent/                     LLM providers (Anthropic + mock), tool loop, CLI
eval/                      baseline, Sigma validator, eval runner, hypotheses.json
results/                   eval.md, CSVs, hunt traces, audit log
docs/                      FEATURES.md, DESIGN.md, demo_transcript.md
```

CI (`.github/workflows/ci.yml`) runs ruff, pytest and a `make data eval` smoke test with `ANTHROPIC_API_KEY`
forced empty, then uploads the eval outputs as an artifact.

