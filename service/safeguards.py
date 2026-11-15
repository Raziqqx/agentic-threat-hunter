"""Safeguards shared by every MCP tool: input validation, result-size caps, audit log."""

from __future__ import annotations

import functools
import ipaddress
import json
import re
import threading
import time
from datetime import UTC, datetime
from pathlib import Path

ALL_TOOLS = ("search_logs", "get_host_timeline", "lookup_ioc", "correlate_events", "propose_detection_rule")
MAX_EVENTS = 200  # hard cap on events returned by one call
MAX_RESULT_BYTES = 60_000  # hard cap on serialized result size
MAX_STR = 200  # max length of any free-text argument

_HOST_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_USER_RE = re.compile(r"^[A-Za-z0-9_.-]{1,32}$")
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


class ValidationError(ValueError):
    """Raised for any argument that fails validation; surfaced to the client as a tool error."""


def check_str(name: str, value: str | None, max_len: int = MAX_STR) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip() or len(value) > max_len:
        raise ValidationError(f"{name}: expected non-empty string of at most {max_len} chars")
    if any(ord(c) < 32 for c in value):
        raise ValidationError(f"{name}: control characters are not allowed")
    return value


def check_host(host: str | None) -> str | None:
    if host is not None and not _HOST_RE.match(host):
        raise ValidationError("host: expected a short lowercase hostname like 'web-01'")
    return host


def check_user(user: str | None) -> str | None:
    if user is not None and not _USER_RE.match(user):
        raise ValidationError("user: invalid user name")
    return user


def check_ip(ip: str | None) -> str | None:
    if ip is None:
        return None
    try:
        ipaddress.ip_address(ip)
    except ValueError as exc:
        raise ValidationError(f"ip: not an IP address: {ip!r}") from exc
    return ip


def check_technique(tech: str) -> str:
    if not _TECH_RE.match(tech or ""):
        raise ValidationError("technique: expected an ATT&CK id like T1110 or T1110.001")
    return tech


def check_time(name: str, value: str | None) -> str | None:
    """Accept ISO-8601 and normalise to the log format (UTC, millisecond 'Z')."""
    if value is None:
        return None
    try:
        dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError) as exc:
        raise ValidationError(f"{name}: expected ISO-8601 timestamp") from exc
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def check_limit(limit: int, cap: int = MAX_EVENTS) -> int:
    if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= cap:
        raise ValidationError(f"limit: expected an integer in [1, {cap}]")
    return limit


def cap_events(events: list[dict], total: int, extra: dict | None = None) -> dict:
    """Package events, dropping from the tail until the serialized result fits MAX_RESULT_BYTES."""
    result = {
        **(extra or {}),
        "total_matches": total,
        "returned": len(events),
        "truncated": total > len(events),
        "events": events,
    }
    while len(json.dumps(result)) > MAX_RESULT_BYTES and result["events"]:
        result["events"] = result["events"][: len(result["events"]) * 3 // 4]
        result["returned"] = len(result["events"])
        result["truncated"] = True
    return result


class AuditLog:
    """Append-only JSONL audit trail of every tool call (allowed, rejected or failed)."""

    def __init__(self, path: Path):
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def write(self, record: dict) -> None:
        line = json.dumps(record, separators=(",", ":"), default=str)
        with self._lock, open(self.path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


def audited(audit: AuditLog, tool_name: str):
    """Decorator: time the call, record args/outcome/result size, re-raise errors."""

    def deco(fn):
        @functools.wraps(fn)
        async def wrapper(*args, **kwargs):
            t0 = time.perf_counter()
            rec = {"ts": datetime.now(UTC).isoformat(), "tool": tool_name, "args": kwargs}
            try:
                result = await fn(*args, **kwargs)
            except ValidationError as exc:
                rec.update(status="rejected", error=str(exc))
                raise
            except Exception as exc:
                rec.update(status="error", error=f"{type(exc).__name__}: {exc}")
                raise
            else:
                rec.update(
                    status="ok",
                    result_bytes=len(json.dumps(result)),
                    returned=result.get("returned"),
                    truncated=result.get("truncated"),
                )
                return result
            finally:
                rec["duration_ms"] = round((time.perf_counter() - t0) * 1000, 2)
                audit.write(rec)

        return wrapper

    return deco
