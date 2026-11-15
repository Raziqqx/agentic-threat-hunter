"""Async MCP server exposing read-only threat-hunting tools over the synthetic logs.

Run over stdio:  python -m service.server --data data --audit results/audit.jsonl
"""

from __future__ import annotations

import argparse
import json
import os
import uuid
from collections import Counter, defaultdict
from pathlib import Path

import anyio
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from datagen.generate import LOG_TYPES

from . import sigma
from .safeguards import (
    ALL_TOOLS,
    AuditLog,
    ValidationError,
    audited,
    cap_events,
    check_host,
    check_ip,
    check_limit,
    check_str,
    check_technique,
    check_time,
    check_user,
)
from .store import FIELDS, LogStore


def _check_log_type(log_type: str | None) -> str | None:
    if log_type is not None and log_type not in LOG_TYPES:
        raise ValidationError(f"log_type: expected one of {list(LOG_TYPES)}")
    return log_type


READ_ONLY = ToolAnnotations(readOnlyHint=True, destructiveHint=False, openWorldHint=False)


def build_server(data_dir: Path, audit_path: Path, allowed_tools: tuple[str, ...] = ALL_TOOLS) -> MCPServer:
    """Create the server. Only tools in `allowed_tools` (an allow-list) are registered."""
    unknown = set(allowed_tools) - set(ALL_TOOLS)
    if unknown:
        raise ValueError(f"unknown tools in allow-list: {sorted(unknown)}")
    store = LogStore(data_dir)
    audit = AuditLog(audit_path)
    mcp = MCPServer("agentic-threat-hunter")

    def register(fn):
        if fn.__name__ in allowed_tools:
            mcp.tool(name=fn.__name__, description=fn.__doc__, annotations=READ_ONLY)(audited(audit, fn.__name__)(fn))
        return fn

    async def run(fn):
        return await anyio.to_thread.run_sync(fn)

    @register
    async def search_logs(
        log_type: str | None = None,
        host: str | None = None,
        user: str | None = None,
        ip: str | None = None,
        contains: str | None = None,
        start: str | None = None,
        end: str | None = None,
        limit: int = 100,
    ) -> dict:
        """Search the logs. Filters are ANDed: log_type (auth|process|conn|web), host, user, ip (matches src_ip
        or dst_ip), contains (case-insensitive substring over all fields), start/end (ISO-8601). Returns at
        most `limit` (<=200) events in time order plus the total match count."""
        kw = dict(
            log_type=_check_log_type(log_type),
            host=check_host(host),
            user=check_user(user),
            ip=check_ip(ip),
            contains=check_str("contains", contains),
            start=check_time("start", start),
            end=check_time("end", end),
        )
        limit = check_limit(limit)

        def go():
            hits = list(store.query(**kw))
            return cap_events(hits[:limit], len(hits))

        return await run(go)

    @register
    async def get_host_timeline(host: str, start: str | None = None, end: str | None = None, limit: int = 100) -> dict:
        """All events on one host across every log type, in time order, optionally within start/end."""
        kw = dict(host=check_host(host), start=check_time("start", start), end=check_time("end", end))
        if not kw["host"]:
            raise ValidationError("host is required")
        limit = check_limit(limit)

        def go():
            hits = list(store.query(**kw))
            counts = Counter(e["log_type"] for e in hits)
            return cap_events(hits[:limit], len(hits), {"host": host, "counts_by_log_type": dict(counts)})

        return await run(go)

    @register
    async def lookup_ioc(indicator: str) -> dict:
        """Look up an IP, URI path or file path in the local threat-intel IOC feed (no network access)."""
        indicator = check_str("indicator", indicator)
        matches = [
            i
            for i in store.iocs
            if i["indicator"] == indicator or (i["type"] in ("uri", "file") and i["indicator"] in indicator)
        ]
        return {"indicator": indicator, "match": bool(matches), "matches": matches}

    @register
    async def correlate_events(indicator: str, start: str | None = None, end: str | None = None) -> dict:
        """Correlate one indicator (IP, user or string) across all log types: per host and log type, the
        event count, first/last seen and up to 10 sample event ids, plus related users/hosts/IPs."""
        indicator = check_str("indicator", indicator, max_len=100)
        start, end = check_time("start", start), check_time("end", end)

        def go():
            groups: dict[tuple[str, str], list[dict]] = defaultdict(list)
            users, ips = Counter(), Counter()
            for e in store.references(indicator):
                if (start and e["ts"] < start) or (end and e["ts"] > end):
                    continue
                groups[(e["host"], e["log_type"])].append(e)
                if e.get("user"):
                    users[e["user"]] += 1
                for f in ("src_ip", "dst_ip"):
                    if e.get(f) and e[f] != indicator:
                        ips[e[f]] += 1
            out = [
                {
                    "host": h,
                    "log_type": t,
                    "count": len(evs),
                    "first_seen": evs[0]["ts"],
                    "last_seen": evs[-1]["ts"],
                    "sample_event_ids": [e["event_id"] for e in evs[:10]],
                    "outcomes": dict(Counter(e["outcome"] for e in evs if "outcome" in e)),
                }
                for (h, t), evs in sorted(groups.items(), key=lambda kv: kv[1][0]["ts"])
            ]
            return {
                "indicator": indicator,
                "returned": len(out),
                "groups": out[:50],
                "truncated": len(out) > 50,
                "related_users": dict(users.most_common(10)),
                "related_ips": dict(ips.most_common(10)),
            }

        return await run(go)

    @register
    async def propose_detection_rule(
        title: str, technique: str, log_type: str, selection: dict, description: str = ""
    ) -> dict:
        """Draft a Sigma rule (subset: one selection map; AND across fields, OR across list values; modifiers
        |contains |startswith |endswith). The rule is dry-run over the logs and returned with its hit count and
        sample hits. Nothing is deployed or written."""
        title = check_str("title", title, max_len=120)
        technique = check_technique(technique)
        if _check_log_type(log_type) is None:
            raise ValidationError("log_type is required")
        if description:
            check_str("description", description, max_len=500)
        if not isinstance(selection, dict) or not 1 <= len(selection) <= 8:
            raise ValidationError("selection: expected a map with 1-8 field conditions")
        for key, val in selection.items():
            field, mod = sigma.split_key(key)
            if field not in FIELDS[log_type] or mod not in sigma.MODIFIERS:
                raise ValidationError(f"selection: unsupported field/modifier {key!r} for {log_type}")
            vals = val if isinstance(val, list) else [val]
            if not 1 <= len(vals) <= 20 or not all(isinstance(v, (str, int)) and not isinstance(v, bool) for v in vals):
                raise ValidationError(f"selection[{key!r}]: expected a string/int or a list of 1-20 of them")
            for v in vals:
                check_str(f"selection[{key!r}]", str(v))
        rule = {
            "title": title,
            "technique": technique,
            "log_type": log_type,
            "selection": selection,
            "description": description or title,
            "id": str(uuid.uuid5(uuid.NAMESPACE_URL, json.dumps([title, log_type, selection], sort_keys=True))),
        }

        def go():
            hits = [e["event_id"] for e in store.query(log_type=log_type) if sigma.matches(e, selection)]
            return {
                "rule_id": rule["id"],
                "sigma_yaml": sigma.to_yaml(rule),
                "rule": rule,
                "dry_run_hits": len(hits),
                "sample_hits": hits[:10],
                "returned": min(len(hits), 10),
                "truncated": len(hits) > 10,
            }

        return await run(go)

    return mcp


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--audit", type=Path, default=Path("results/audit.jsonl"))
    ap.add_argument(
        "--allow",
        default=os.environ.get("ATH_ALLOWED_TOOLS", ",".join(ALL_TOOLS)),
        help="comma-separated tool allow-list",
    )
    args = ap.parse_args()
    allowed = tuple(t for t in args.allow.split(",") if t)
    build_server(args.data, args.audit, allowed).run("stdio")


if __name__ == "__main__":
    main()
