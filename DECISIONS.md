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
