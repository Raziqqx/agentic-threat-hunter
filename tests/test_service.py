import json
import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

from service.safeguards import ALL_TOOLS, MAX_RESULT_BYTES
from service.server import build_server

pytestmark = pytest.mark.anyio


def payload(result):
    assert not result.is_error, result.content
    return json.loads(result.content[0].text)


@pytest.fixture
def audit_path(tmp_path):
    return tmp_path / "audit.jsonl"


@pytest.fixture
async def client(dataset, audit_path):
    server = build_server(dataset, audit_path)
    async with Client(server) as session:
        yield session


async def test_lists_exactly_the_allowed_tools(client):
    tools = await client.list_tools()
    assert sorted(t.name for t in tools.tools) == sorted(ALL_TOOLS)


async def test_allow_list_restricts_registration(dataset, audit_path):
    server = build_server(dataset, audit_path, allowed_tools=("search_logs",))
    async with Client(server) as s:
        assert [t.name for t in (await s.list_tools()).tools] == ["search_logs"]
        res = await s.call_tool("lookup_ioc", {"indicator": "203.0.113.66"})
        assert res.is_error
    with pytest.raises(ValueError):
        build_server(dataset, audit_path, allowed_tools=("delete_logs",))


async def test_search_logs_filters_and_limit(client):
    out = payload(await client.call_tool("search_logs", {"log_type": "auth", "ip": "203.0.113.66", "limit": 5}))
    assert out["returned"] == 5 and out["total_matches"] >= 80 and out["truncated"]
    assert all(e["src_ip"] == "203.0.113.66" for e in out["events"])


async def test_result_size_cap(client):
    out = payload(await client.call_tool("search_logs", {"limit": 200}))
    assert len(json.dumps(out)) <= MAX_RESULT_BYTES
    assert out["truncated"]


@pytest.mark.parametrize(
    "args",
    [
        {"limit": 0},
        {"limit": 1000},
        {"ip": "not-an-ip"},
        {"host": "WEB 01; rm -rf /"},
        {"log_type": "kernel"},
        {"start": "yesterday"},
        {"contains": "x" * 500},
        {"contains": "a\x00b"},
    ],
)
async def test_invalid_inputs_rejected_and_audited(client, audit_path, args):
    res = await client.call_tool("search_logs", args)
    assert res.is_error
    last = json.loads(audit_path.read_text().splitlines()[-1])
    assert last["tool"] == "search_logs" and last["status"] == "rejected"


async def test_host_timeline_is_ordered(client):
    out = payload(await client.call_tool("get_host_timeline", {"host": "db-01", "limit": 50}))
    ts = [e["ts"] for e in out["events"]]
    assert ts == sorted(ts) and set(out["counts_by_log_type"]) <= {"auth", "process", "conn", "web"}


async def test_lookup_ioc(client):
    hit = payload(await client.call_tool("lookup_ioc", {"indicator": "/uploads/shell.php?c=id"}))
    assert hit["match"] and hit["matches"][0]["type"] == "uri"
    miss = payload(await client.call_tool("lookup_ioc", {"indicator": "10.0.1.10"}))
    assert not miss["match"]


async def test_correlate_events_pivots(client):
    out = payload(await client.call_tool("correlate_events", {"indicator": "203.0.113.66"}))
    hosts = {g["host"] for g in out["groups"]}
    assert {"web-01", "db-01"} <= hosts  # brute-forced host and exfil host
    assert "bob" in out["related_users"]


async def test_propose_detection_rule_dry_run(client):
    args = {
        "title": "Shadow file read",
        "technique": "T1003.008",
        "log_type": "process",
        "selection": {"cmdline|contains": "/etc/shadow"},
    }
    out = payload(await client.call_tool("propose_detection_rule", args))
    assert out["dry_run_hits"] >= 2 and "attack.t1003.008" in out["sigma_yaml"]
    bad = await client.call_tool("propose_detection_rule", {**args, "selection": {"secret_field": "x"}})
    assert bad.is_error


async def test_every_call_is_audited(client, audit_path):
    await client.call_tool("lookup_ioc", {"indicator": "192.0.2.77"})
    await client.call_tool("get_host_timeline", {"host": "ws-07", "limit": 3})
    recs = [json.loads(x) for x in audit_path.read_text().splitlines()]
    assert [r["tool"] for r in recs] == ["lookup_ioc", "get_host_timeline"]
    assert all(r["status"] == "ok" and "duration_ms" in r and "args" in r for r in recs)


async def test_stdio_transport(dataset, tmp_path):
    params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "service.server", "--data", str(dataset), "--audit", str(tmp_path / "a.jsonl")],
        cwd=str(Path(__file__).resolve().parents[1]),
    )
    async with Client(params) as s:
        out = payload(await s.call_tool("lookup_ioc", {"indicator": "203.0.113.66"}))
        assert out["match"]
