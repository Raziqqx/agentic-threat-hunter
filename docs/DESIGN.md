# Design

> All measured numbers in this document come from `results/eval.md`. They were produced with the **mock LLM
> provider**, so they validate the pipeline, not LLM capability. The Anthropic provider is implemented but has
> not been run, because no API key was available.

## Key decisions

| Decision | Why | Alternatives considered |
|---|---|---|
| Synthetic, seeded logs with labels kept outside the logs | Gives exact ground truth, no licence to track, and byte-identical reruns | Public datasets: no per-event ATT&CK labels for our chains, and licence overhead |
| False-positive bait in the data | Without it, rule precision would be trivially 1.0 | Clean attack-only data |
| Official `mcp` SDK (FastMCP, async), store queries in worker threads | Standard protocol; the event loop is never blocked | A custom JSON-RPC server; direct function calls |
| Read-only tools; `propose_detection_rule` only drafts and dry-runs | A hijacked model's worst tool call is a read of synthetic logs | Tools with write or response actions on the server |
| Allow-list applied at registration | A disallowed tool does not exist for the client | Checking the allow-list at call time only |
| Manual tool loop instead of the SDK tool runner | Budgets, the gate and grounding all sit in one place, shared by both providers | The SDK tool runner |
| Approval gate as an agent-local tool that only records | Keeps the server read-only; injected "block this IP" requests cannot run on their own | A server-side action tool |
| Separate Sigma validator that parses the emitted YAML | Scores the deployable artefact; unsupported features fail loudly | Reusing the server's dry-run matcher |
| Cost reported as calls and tokens, with no dollar figure | A dollar figure for mock tokens would be invented | Estimated pricing |

## Trade-offs

- **In-memory store, no index.** This is simple and fast enough at the current data size. It would not scale to
  real log volumes.
- **Small Sigma subset.** The subset leaves out aggregations (`| count()`), `timeframe`, `near` and `cidr`. Rules
  that need thresholds cannot be expressed, which is why the brute-force rule lists noisy source IPs instead of
  counting failures.
- **Truncating results** (200 events, 60 KB) protects the context and the budget. The cost is that the agent may
  miss events and has to page or narrow its queries.
- **Mock token counts** are ~4 chars/token estimates. They are useful for comparing the systems, but they are not
  billing data.

## Baseline vs improved

There are three systems, three seeds and 45 (seed, technique) cases per system (`results/eval.md`):

| System | Detected | Evidence P | Rule P | Rule R | Tokens in (est.) |
|---|---|---|---|---|---|
| baseline (one prompt, one-tool-result-sized sample) | 1/45 | 1.000 | 1.000 | 0.115 | 17,575 |
| baseline_matched (sample sized to agent's tokens) | 5/45 | 0.492 | 0.488 | 0.432 | 84,221 |
| agent (tool loop) | 42/45 | 1.000 | 0.841 | 0.458 | 71,959 |

The baseline is a deliberately fair strawman. Its mock runs the same heuristics as the agent's mock on a sample,
with thresholds scaled to the sampling fraction. Its only handicap is the one under test: it cannot pivot to
events it was not shown. Even with a budget-matched sample, it detects 5/45, and its evidence precision falls to
0.492.

The agent uses about 4x the plain baseline's input tokens, because it re-sends its growing history on every call.
That budget gap is why `baseline_matched` exists. It averages 7.25 LLM calls and 6.25 tool calls per hunt.

## Known limitations

- **Mock results only.** The mock playbooks were written by the author. They show that tools, safeguards and
  scoring work end to end, and that pivoting beats sampling *for these heuristics*. They say nothing about how a
  real model would hunt.
- **The real provider has not been run.** `--provider anthropic` is implemented in `agent/llm.py` and wired into
  the eval, but it has never been run, because no API key was available.
- **T1560.001 (archive) is never detected** by any system on any seed. Finding it needs a process-log pivot that
  the brute-force playbook does not make.
- **Rule recall is low for chain steps.** Many techniques (T1078, T1021.004, T1048, T1071.001, ...) get cited
  evidence but no rule, so the agent's micro rule recall is 0.458.
- **Rule over-generalisation.** On T1110.001, agent rule precision is 0.800, because the "noisy sources" list also
  contains the password-spray source (labelled T1110.003).
- **Grounding is weak evidence.** It proves a cited id was seen, not that it supports the claim.
- **The safeguards do not stop wrong conclusions.** Prompt injection can still steer what gets reported, and the
  approval gate depends on the human. The audit log is append-only by convention, not tamper-evident. With a real
  provider, log contents are sent to the API. See the threat model in `DECISIONS.md`.
- **Synthetic data only.** Rule precision on real traffic is unknown.

## Next steps

1. Run `python -m eval.run_eval --provider anthropic` across all four hypotheses and publish the results next to
   the mock numbers.
2. Add a prompt-injection test set: plant instructions in user agents, URIs and command lines, then measure
   suppressed or false findings.
3. Extend the validator with `| count()` and `timeframe`, so rules can use thresholds instead of IP lists.
4. Make the audit log tamper-evident (hash chaining).
5. Add an index to the store and test on larger generated volumes.
