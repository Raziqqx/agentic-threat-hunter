# Demo transcript

Captured on 2026-11-16 by running the README "See it working" steps from the repo root (mock provider,
seed 7). Timestamps, file names and wall times change per run; everything else is deterministic. Long audit
lines are cut at 300 characters and the `pip` output of `make venv` is cut to its last line.

## Step 1: run one hunt

````text
$ make venv && make hunt
Requirement already satisfied: uvicorn==0.54.0 in ./.venv/lib/python3.12/site-packages (from -r requirements.txt (line 39)) (0.54.0)
.venv/bin/python -m datagen.generate --seed 7 --out data
wrote 6 files to data (6.38 MB)
.venv/bin/python -m agent.cli --data data --hypothesis "SSH brute force against internet-facing servers"
completed: 4 findings, 1 rules, 8 steps, 139296 tokens -> results/runs/hunt-20261116T063606Z.json
  [T1110.001] SSH brute force from 203.0.113.66 (verified=True, evidence=10)
  [T1078] Login as bob on web-01 after brute force (verified=True, evidence=1)
  [T1021.004] Lateral SSH to db-01 (verified=True, evidence=1)
  [T1048] Large outbound transfer to the attacker (verified=True, evidence=2)
  action block_ip 203.0.113.66: denied
````

## Step 2: replay the trace and the Sigma rule

````text
$ .venv/bin/python -c "...replay the newest trace..."
1 ['search_logs'] Look for many failed SSH logins from one source.
2 ['lookup_ioc'] 203.0.113.66 has 80 failures; check intel.
3 ['search_logs'] Did any attempt succeed?
4 ['search_logs'] Where did bob log in next?
5 ['get_host_timeline'] Inspect db-01 after the lateral login.
6 ['propose_detection_rule'] Draft a detection rule.
7 ['request_response_action'] Recommend blocking the source (needs human approval).
8 [] Hypothesis confirmed by the logs.
```json
{"summary": "Hypot
title: 'SSH brute force from known noisy sources'
id: 3e3b145e-c3a6-5199-b2f4-d823d6e88101
status: experimental
description: 'Failed SSH logins from sources seen brute-forcing during the hunt.'
logsource:
  product: linux
  service: auth
detection:
  selection:
    outcome: 'failure'
    src_ip:
      - '203.0.113.140'
      - '203.0.113.66'
  condition: selection
tags:
  - attack.t1110.001
level: medium

````

## Step 3: the audit log

````text
$ tail -n 3 results/audit.jsonl
{"ts":"2026-11-16T06:36:05.997329+00:00","tool":"search_logs","args":{"log_type":"auth","host":null,"user":"bob","ip":null,"contains":"Accepted","start":"2026-03-03T03:11:16.928Z","end":null,"limit":20},"status":"ok","result_bytes":5164,"returned":20,"truncated":true,"duration_ms":3.72}
{"ts":"2026-11-16T06:36:06.020419+00:00","tool":"get_host_timeline","args":{"host":"db-01","start":"2026-03-03T03:15:17.928Z","end":null,"limit":60},"status":"ok","result_bytes":15899,"returned":60,"truncated":true,"duration_ms":5.02}
{"ts":"2026-11-16T06:36:06.044312+00:00","tool":"propose_detection_rule","args":{"title":"SSH brute force from known noisy sources","technique":"T1110.001","log_type":"auth","selection":{"outcome":"failure","src_ip":["203.0.113.140","203.0.113.66"]},"description":"Failed SSH logins from sources seen
````

## Step 4: approve through the human gate

````text
$ echo y | .venv/bin/python -m agent.cli --data data --provider mock --interactive --hypothesis "SSH brute force against internet-facing servers"
Approve request_response_action {"action": "block_ip", "target": "203.0.113.66", "justification": "Confirmed brute force source"}? [y/N] completed: 4 findings, 1 rules, 8 steps, 139306 tokens -> results/runs/hunt-20261116T063617Z.json
  [T1110.001] SSH brute force from 203.0.113.66 (verified=True, evidence=10)
  [T1078] Login as bob on web-01 after brute force (verified=True, evidence=1)
  [T1021.004] Lateral SSH to db-01 (verified=True, evidence=1)
  [T1048] Large outbound transfer to the attacker (verified=True, evidence=2)
  action block_ip 203.0.113.66: approved
````

## Step 5: the evaluation (summary table only)

````text
$ make eval
## Summary per system

| System | Techniques detected | Evidence P (micro) | Rule P (micro) | Rule R (micro) | LLM calls | Tool calls | Tokens in (estimated, ~4 chars/token) | Tokens out (estimated, ~4 chars/token) | Wall s (mean) | Wall s (max) | Grounded findings |
|---|---|---|---|---|---|---|---|---|---|---|---|
| baseline | 1/45 | 1.000 | 1.000 | 0.115 | 1.000 | 0.000 | 17575.167 | 63.667 | 0.010 | 0.012 | 1/1 |
| baseline_matched | 5/45 | 0.492 | 0.488 | 0.432 | 1.000 | 0.000 | 84221.167 | 153.750 | 0.025 | 0.052 | 9/9 |
| agent | 42/45 | 1.000 | 0.841 | 0.458 | 7.250 | 6.250 | 71958.833 | 730.500 | 0.182 | 0.255 | 45/45 |

Micro averages pool every (seed, technique) row of a system. Wall time for the agent includes starting the in-process MCP session; the mock makes no network calls, so latency here is tool and loop overhead, not model latency.

````
