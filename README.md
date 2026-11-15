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
  labelled attack chains covering 14 technique steps, false-positive bait, and a deliberately partial IOC feed.
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

## Demo

There are no screenshots yet. To record a demo, run these commands from a clean checkout (mock provider, no key needed):

```bash
make venv
make hunt            # generates data, runs one SSH brute-force hunt, writes results/runs/hunt-*.json
make eval            # writes results/eval.md, eval_techniques.csv, eval_cost.csv
```

Each hunt writes a JSON trace to `results/runs/` and appends every tool call to `results/audit.jsonl`.

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
docs/                      FEATURES.md, DESIGN.md, INTERVIEW_NOTES.md
```

CI (`.github/workflows/ci.yml`) runs ruff, pytest and a `make data eval` smoke test with `ANTHROPIC_API_KEY`
forced empty, then uploads the eval outputs as an artifact.

## Target roles

AI security engineer, detection engineer or threat hunter, ML/LLM agent engineer, and security tooling engineer.
The project shows MCP tool design under adversarial input, agent safeguards, Sigma rule engineering, and an
honest eval methodology.

More detail: [docs/FEATURES.md](docs/FEATURES.md), [docs/DESIGN.md](docs/DESIGN.md),
[docs/INTERVIEW_NOTES.md](docs/INTERVIEW_NOTES.md), [RESUME_BULLETS.md](RESUME_BULLETS.md).
