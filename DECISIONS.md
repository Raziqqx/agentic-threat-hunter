# Decisions

## M1 — datagen
- **Synthetic only.** All logs come from `datagen/generate.py`; no third-party dataset, so no licence to track. External
  addresses use the RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24): never routable.
- **One seeded `random.Random`** drives everything; events are sorted by timestamp (stable) and only then get
  `event_id`s (`<log_type>-NNNNNN`), so ids and bytes are identical for a seed. Tests compare SHA-256 hashes.
- **Labels live outside the logs** (`labels.json`, per chain → technique → event ids). Generator tags events with a
  private `_label` that is stripped before writing; a test asserts it never leaks.
- **Four chains, 15 technique steps (14 distinct techniques):** C1 SSH brute force → valid account → lateral SSH → archive → exfil
  (T1110.001, T1078, T1021.004, T1560.001, T1048); C2 web exploit → web shell → commands → tool transfer (T1190,
  T1505.003, T1059.004, T1105); C3 shadow dump → cron persistence → HTTPS beacon (T1003.008, T1053.003, T1071.001);
  C4 password spray → valid account → local account (T1110.003, T1078, T1136.001).
- **Deliberate false-positive bait:** benign typo login failures, nightly large internal backup transfers, benign
  outbound HTTPS. Without it rule precision would be trivially 1.0.
- **Dataset is not committed** (6.4 MB at seed 7, scale 1.0); `make data` regenerates it in ~1 s.
- **IOC feed is partial on purpose:** it covers some attacker infrastructure plus decoys never seen in the logs,
  and omits the C4 spray source, so intel alone cannot solve every hunt.

## M2 — MCP service
- **Official `mcp` SDK, FastMCP, async.** Store queries run in a worker thread (`anyio.to_thread`) so the event loop
  is never blocked. Logs are loaded once into memory (fits easily at this size); an index is not needed yet.
- **Read-only by construction:** no tool writes anything except the audit log. `propose_detection_rule` only drafts
  and dry-runs a rule.
- **Allow-list at registration:** only tools named in the allow-list (`--allow` / `ATH_ALLOWED_TOOLS`) are registered,
  so a disallowed tool does not exist for the client. Unknown names in the allow-list fail at startup.
- **Validation:** strict patterns for host, user, IP, ATT&CK id and ISO timestamps; length caps and no control
  characters on free text; `limit` in [1, 200]; rule fields checked against the per-log-type schema and the
  supported Sigma modifiers. Failures are raised as tool errors and audited as `rejected`.
- **Result-size limits:** at most 200 events per call and 60 KB per serialized result (events are dropped from the
  tail and `truncated: true` is set). The agent re-serialises structured results as compact JSON and caps what the model sees at 60 K chars.
- **Audit log:** one JSONL record per call with UTC time, tool, args, status (ok/rejected/error), result size,
  returned count, truncation flag and duration. Calls to unregistered tools are refused by the SDK before they
  reach the server's handlers, so they are recorded in the agent trace instead.
- **Sigma subset:** one `selection` map, AND across fields, OR across list values, modifiers
  `contains/startswith/endswith`, case-insensitive. Enough for M2 dry-runs; M4 will extend it into the validator.

## M3 — agent
- **Manual tool loop** (not the SDK tool runner) so budgets, the gate and grounding checks sit in one place and the
  mock and Anthropic providers share the exact same loop. Internal history uses the Anthropic Messages shape.
- **Provider selection:** `auto` uses Anthropic when `ANTHROPIC_API_KEY` is set, otherwise the mock; tests force the
  mock. Model `claude-opus-5-5`, effort `medium`, server-side refusal fallback enabled (`fallbacks: "default"`)
  because security-hunting prompts can trip cyber classifiers; a `refusal` stop ends the hunt cleanly.
- **Budgets:** steps (LLM calls), total tokens (reported usage; the mock estimates ~4 chars/token deterministically)
  and wall time (`anyio.fail_after` around every LLM and tool call).
- **Human-approval gate:** risky actions are containment recommendations via an agent-local
  `request_response_action` tool. It never executes anything — it records the decision. Policy `deny` (default,
  tests), `approve` (`--approve`) or `prompt` (`--interactive`). The MCP server itself stays read-only.
- **Evidence grounding:** a finding is `verified` only if every cited event id appeared in a tool result during the
  hunt; fabricated ids are kept but flagged.
- **Mock provider** implements one playbook (SSH brute force). It derives every pivot from tool results rather than
  from the labels, so the e2e test exercises the real server, safeguards and loop.

## M4 — eval
- **Validator is separate from the server's dry-run matcher** (`eval/sigma_validator.py` vs `service/sigma.py`): it
  parses the YAML the server emits, so the eval checks the artefact an analyst would deploy, not the agent's dict.
  A test asserts both agree on the same rule. PyYAML (`safe_load` only) was added for parsing.
- **Supported Sigma subset** is documented in the module docstring: `logsource.service` = our log types, named
  selections (map = AND, list of maps = OR), modifiers `contains/startswith/endswith/re` + `all`, wildcards in plain
  values, conditions with `and/or/not`, parentheses, `1 of`/`all of` pattern|them. Anything else (`base64`, `cidr`,
  keyword lists, `null`, `timeframe`, `| count()`, `near`, `logsource.category`) raises `SigmaUnsupported` naming the
  feature, so an unsupported rule is never silently scored as "zero hits".
- **Scoring:** ground truth per technique is the union of labelled event ids across chains (T1078 is in C1 and C4).
  Rule P/R: hits of all rules tagged `attack.<technique>` over the *full* logs vs ground truth. Evidence precision:
  cited ids in findings for that technique that are ground truth. "Detected" = at least one correct cited id.
  Precision with no hits/citations is reported as `n/a`, not 0 or 1.
- **Baseline strawman** (`eval/baseline.py`): one call, no tools. Prompt = hypothesis + seeded uniform sample of the
  hypothesis' log types, filled to the same 60 K-char budget the agent may see from one tool result. The mock
  baseline runs the *same* heuristic as the agent mock on that sample, with the brute-force threshold scaled by the
  sampling fraction (min 3) so sampling alone does not hide the attack, and emits the same rule shape. Its only
  handicap is the one under test: it cannot fetch events it was not shown, so it cannot pivot.
- **Mock eval runs only H1 (SSH brute force)** because the mock implements one playbook; the four-hypothesis set in
  `eval/hypotheses.json` runs with `--provider anthropic`. Three seeds (7, 21, 42) give sampling variance.
- **Cost = LLM calls, tool calls and tokens.** Mock tokens are ~4 chars/token estimates and are labelled as such; no
  dollar figure is quoted because it would be invented. Latency is measured wall time (`time.monotonic`); for the
  mock it is loop/tool overhead only.
- **Result (mock, 3 seeds, H1 only; superseded — see results/eval.md for all four hypotheses after ddc1acd):** agent detects 12/15 (seed, technique) cases with 1.0 evidence precision, rule
  P 0.80 / R 0.91 micro; baseline detects 1/15, rule R 0.30. The agent's rule loses precision because its "noisy
  sources" list also contains the C4 spray source (labelled T1110.003) — a real over-generalisation, kept visible.
  Neither system finds T1560.001 (archive), which needs a process-log pivot the mock playbook does not make.

## M5 — CI, reproducibility, threat model
- **CI** (`.github/workflows/ci.yml`): ruff check + format check, pytest, then `make data eval` as a smoke run;
  `ANTHROPIC_API_KEY` is forced empty so only the mock provider can run. Eval outputs are uploaded as an artifact.
- **`make reproduce`**: wipes `data/`, then lint, tests, regenerate data, eval and one demo hunt (mock). Numbers in
  `results/eval.md` are identical across runs except wall times.

### Threat model of the safeguards
Assets: the log store and anything the hunt could affect (hosts, accounts, firewall). Threat: the LLM acting
wrongly, whether by mistake or because attacker-controlled text in the logs (user agents, URIs, command lines)
injects instructions into tool results.

What the controls protect against:
- **Read-only tools:** a hijacked or confused model cannot modify, delete or exfiltrate-by-write; the worst a tool
  call can do is read synthetic logs. The audit log is the only write, and the model cannot address it.
- **Allow-list (server registration + agent-side check):** the model cannot reach a tool that was not deliberately
  exposed, even if it hallucinates or is told to call one; disallowed calls are refused and traced.
- **Input validation and result caps:** malformed or oversized arguments are rejected and audited; result size
  limits stop a single call from flooding the context or the budget.
- **Approval gate:** every containment recommendation needs a human decision (default deny) and is only recorded,
  never executed, so an injected "block this IP / disable this admin" cannot take effect on its own.
- **Budgets:** step, token and wall-time limits bound cost and stop runaway loops.
- **Grounding check + audit trail:** fabricated evidence ids are flagged, and every tool call is reconstructable.

What they do not protect against:
- **Wrong conclusions.** A prompt injection can still steer *what the model reports*: suppress a finding, blame an
  innocent host, or write a weak/over-broad rule. Grounding only proves a cited id was seen, not that it supports
  the claim. The eval and human review of findings are the mitigation, not the gate.
- **Approver error / fatigue.** The gate is only as good as the human; a persuasive justification written by an
  injected model can win approval. Approved actions are recorded, not executed, which limits but does not remove
  this risk once a person acts on them.
- **Read-path leakage.** With a real provider, the log contents a tool returns are sent to that API. Fine for
  synthetic data; real logs would need a data-handling review first.
- **Compromise below the agent:** a tampered server, dataset, dependency or host is out of scope; the audit log is
  append-only by convention, not tamper-evident (no hashing or signing).
- **Rule deployment risk.** Validated rules are scored on synthetic data only; their precision on real traffic is
  unknown.

## Review fixes: eval coverage, caveats, budget disclosure

- **Mock playbooks for H2-H4.** `MockProvider` now routes on the hypothesis wording (`agent.llm.route`) to one of
  four scripted playbooks: SSH brute force, web shell (shell command in a query string -> attacker IP -> requests in
  the prior 30 min -> processes spawned by the web server -> download and connection back), credential dumping
  (`/etc/shadow` read -> `crontab` on that host -> the scheduled binary parsed from the cron entry -> its runs ->
  the external IP of the first run -> all beacons), and spraying (failed logins paged forward by time -> source with
  >= 15 distinct accounts -> its successful login -> `useradd` on that host). Every pivot value comes from a tool
  result; the heuristics (web-server parents, shell verbs, cron syntax, thresholds) are generic and shared with the
  baseline mock, which applies them to its sample only.
- **Exploit window.** The attacker IP also makes benign-looking requests hours earlier; the web-shell playbook only
  attributes requests in the 30 minutes before the first shell hit to T1190 (precision over a wider net).
- **Budget-matched baseline.** Cheap with the mock, so added as a third system (`baseline_matched`): the baseline
  sample is sized to 4 x the agent's cumulative input tokens for the same hunt. The plain baseline stays as the
  one-tool-result-sized reference. Both caveats (mock results validate the pipeline, not LLM capability; unequal
  token budgets) are generated at the top of `results/eval.md`.
