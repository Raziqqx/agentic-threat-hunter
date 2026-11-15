"""In-memory, read-only view over the generated JSONL logs."""

from __future__ import annotations

import json
from pathlib import Path

from datagen.generate import LOG_TYPES

# Fields each log type exposes; used to validate rule selections.
FIELDS = {
    "auth": {"event_id", "ts", "host", "service", "user", "src_ip", "outcome", "message"},
    "process": {"event_id", "ts", "host", "user", "pid", "parent_image", "image", "cmdline"},
    "conn": {
        "event_id",
        "ts",
        "host",
        "uid",
        "src_ip",
        "dst_ip",
        "dst_port",
        "proto",
        "service",
        "duration",
        "orig_bytes",
        "resp_bytes",
        "conn_state",
    },
    "web": {"event_id", "ts", "host", "src_ip", "method", "uri", "status", "user_agent", "bytes"},
}


class LogStore:
    def __init__(self, data_dir: Path):
        self.events: list[dict] = []
        for t in LOG_TYPES:
            with open(data_dir / f"{t}.jsonl", encoding="utf-8") as f:
                self.events.extend(json.loads(line) for line in f)
        self.events.sort(key=lambda e: (e["ts"], e["event_id"]))
        # Lower-cased concatenation of all values, for substring search.
        self._blob = [" ".join(str(v) for v in e.values()).lower() for e in self.events]
        self.iocs: list[dict] = json.loads((data_dir / "iocs.json").read_text(encoding="utf-8"))

    def query(self, *, log_type=None, host=None, user=None, ip=None, contains=None, start=None, end=None):
        """Yield events matching every given filter, in time order."""
        needle = contains.lower() if contains else None
        for e, blob in zip(self.events, self._blob, strict=True):
            if log_type and e["log_type"] != log_type:
                continue
            if host and e["host"] != host:
                continue
            if user and e.get("user") != user:
                continue
            if ip and ip not in (e.get("src_ip"), e.get("dst_ip")):
                continue
            if start and e["ts"] < start:
                continue
            if end and e["ts"] > end:
                continue
            if needle and needle not in blob:
                continue
            yield e

    def references(self, indicator: str):
        """Events whose IP, user or any text field references the indicator."""
        low = indicator.lower()
        for e, blob in zip(self.events, self._blob, strict=True):
            if indicator in (e.get("src_ip"), e.get("dst_ip"), e.get("user")) or low in blob:
                yield e
