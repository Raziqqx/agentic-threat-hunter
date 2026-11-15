import json

from datagen.generate import CHAINS, LOG_TYPES, generate


def test_same_seed_same_hashes(tmp_path):
    a = generate(11, tmp_path / "a", scale=0.2)
    b = generate(11, tmp_path / "b", scale=0.2)
    assert a == b


def test_different_seed_differs(tmp_path):
    a = generate(11, tmp_path / "a", scale=0.2)
    b = generate(12, tmp_path / "b", scale=0.2)
    assert a["auth.jsonl"] != b["auth.jsonl"]


def test_every_labelled_event_exists_and_ids_unique(dataset):
    ids = {}
    for t in LOG_TYPES:
        for line in (dataset / f"{t}.jsonl").read_text().splitlines():
            ev = json.loads(line)
            assert ev["event_id"] not in ids
            assert "_label" not in ev  # labels never leak into the logs
            ids[ev["event_id"]] = ev
    labels = json.loads((dataset / "labels.json").read_text())
    assert {c["chain_id"] for c in labels["chains"]} == set(CHAINS)
    for chain in labels["chains"]:
        assert len(chain["steps"]) >= 3
        for step in chain["steps"]:
            assert step["technique"].startswith("T")
            assert step["event_ids"]
            for eid in step["event_ids"]:
                assert eid in ids


def test_events_sorted_and_internal_fields(dataset):
    for t in LOG_TYPES:
        evs = [json.loads(x) for x in (dataset / f"{t}.jsonl").read_text().splitlines()]
        assert [e["ts"] for e in evs] == sorted(e["ts"] for e in evs)
        assert all(e["log_type"] == t and e["host"] for e in evs)
