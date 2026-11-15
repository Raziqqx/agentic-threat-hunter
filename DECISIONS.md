# Decisions

## M1 — datagen
- **Synthetic only.** All logs come from `datagen/generate.py`; no third-party dataset, so no licence to track. External
  addresses use the RFC 5737 documentation ranges (192.0.2/24, 198.51.100/24, 203.0.113/24): never routable.
- **One seeded `random.Random`** drives everything; events are sorted by timestamp (stable) and only then get
  `event_id`s (`<log_type>-NNNNNN`), so ids and bytes are identical for a seed. Tests compare SHA-256 hashes.
- **Labels live outside the logs** (`labels.json`, per chain → technique → event ids). Generator tags events with a
  private `_label` that is stripped before writing; a test asserts it never leaks.
- **Four chains, 14 technique steps:** C1 SSH brute force → valid account → lateral SSH → archive → exfil
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
