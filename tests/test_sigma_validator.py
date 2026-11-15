import pytest

from eval.sigma_validator import SigmaError, SigmaUnsupported, parse_condition, parse_rule, tokenize
from service import sigma

AUTH = {
    "event_id": "auth-000001",
    "log_type": "auth",
    "host": "bastion-01",
    "user": "bob",
    "src_ip": "203.0.113.66",
    "outcome": "failure",
    "message": "Failed password for bob from 203.0.113.66 port 4242 ssh2",
}


def rule(detection: str, service: str = "auth", extra: str = "") -> str:
    return (
        f"title: t\nlogsource:\n  product: linux\n  service: {service}\n{extra}"
        f"detection:\n{detection}\ntags:\n  - attack.t1110.001\n"
    )


def one(field_key: str, value: str) -> str:
    return f"  sel:\n    {field_key}: {value}\n  condition: sel"


@pytest.mark.parametrize(
    "key,good,bad",
    [
        ("message", "'failed password for bob from 203.0.113.66 port 4242 ssh2'", "'Failed password'"),
        ("message|contains", "'PASSWORD FOR'", "'Accepted'"),
        ("message|startswith", "'Failed'", "'password'"),
        ("message|endswith", "'ssh2'", "'Failed'"),
        ("src_ip|re", "'^203\\.0\\.113\\.\\d+$'", "'^10\\.'"),
        ("host", "'bastion-*'", "'web-*'"),
        ("host", "'bastion-0?'", "'bastion-?'"),
    ],
)
def test_modifiers_positive_and_negative(key, good, bad):
    assert parse_rule(rule(one(key, good))).matches(AUTH)
    assert not parse_rule(rule(one(key, bad))).matches(AUTH)


def test_re_is_case_sensitive_and_others_are_not():
    assert not parse_rule(rule(one("message|re", "'^failed'"))).matches(AUTH)
    assert parse_rule(rule(one("message|contains", "'FAILED'"))).matches(AUTH)


def test_list_values_or_and_all_modifier():
    assert parse_rule(rule(one("user", "\n      - alice\n      - bob"))).matches(AUTH)
    both = "\n      - Failed\n      - ssh2"
    assert parse_rule(rule(one("message|contains|all", both))).matches(AUTH)
    assert not parse_rule(rule(one("message|contains|all", "\n      - Failed\n      - Accepted"))).matches(AUTH)


def test_selection_fields_are_anded_and_list_of_maps_ored():
    anded = "  sel:\n    user: bob\n    outcome: success\n  condition: sel"
    assert not parse_rule(rule(anded)).matches(AUTH)
    ored = "  sel:\n    - user: alice\n    - outcome: failure\n  condition: sel"
    assert parse_rule(rule(ored)).matches(AUTH)


def test_logsource_filters_log_type():
    r = parse_rule(rule(one("user", "bob")))
    assert not r.matches({**AUTH, "log_type": "process"})
    assert r.techniques == ["T1110.001"]


SELS = {"a": lambda e: e["a"], "b": lambda e: e["b"], "c": lambda e: e["c"], "filter_x": lambda e: e["x"]}


@pytest.mark.parametrize(
    "cond,env,expected",
    [
        ("a and b", dict(a=1, b=0, c=0, x=0), False),
        ("a or b", dict(a=0, b=1, c=0, x=0), True),
        ("not a", dict(a=0, b=0, c=0, x=0), True),
        ("a or b and c", dict(a=1, b=0, c=0, x=0), True),  # and binds tighter than or
        ("(a or b) and c", dict(a=1, b=0, c=0, x=0), False),
        ("not a and b", dict(a=0, b=1, c=0, x=0), True),  # not binds tightest
        ("a and not filter_x", dict(a=1, b=0, c=0, x=1), False),
        ("1 of them", dict(a=0, b=0, c=1, x=0), True),
        ("all of them", dict(a=1, b=1, c=1, x=0), False),
        ("1 of filter_*", dict(a=0, b=0, c=0, x=1), True),
        ("all of filter_* and a", dict(a=1, b=0, c=0, x=1), True),
        ("A AND NOT B", dict(a=1, b=0, c=0, x=0), True),  # keywords are case-insensitive
    ],
)
def test_condition_parsing(cond, env, expected):
    sels = {k.lower(): v for k, v in SELS.items()} | {"A": SELS["a"], "B": SELS["b"]}
    assert parse_condition(cond, sels)(env) is expected


def test_tokenize():
    assert tokenize("1 of sel_* and not (f1 or f2)") == ["1", "of", "sel_*", "and", "not", "(", "f1", "or", "f2", ")"]


@pytest.mark.parametrize(
    "cond", ["a and", "a b", "(a or b", "unknown", "1 of nothing_*", "", "a or or b", "a & b", "not"]
)
def test_malformed_conditions(cond):
    with pytest.raises(SigmaError):
        parse_condition(cond, SELS)


@pytest.mark.parametrize(
    "text,feature",
    [
        (rule(one("message|base64", "x")), "base64"),
        (rule(one("src_ip|cidr", "'10.0.0.0/8'")), "cidr"),
        (rule(one("message|contains|startswith", "x")), "combining"),
        (rule(one("user", "null")), "null"),
        (rule("  keywords:\n    - Failed\n  condition: keywords"), "keyword"),
        (rule("  sel:\n    user: bob\n  condition: sel | count() > 5"), "aggregation"),
        (rule("  sel:\n    user: bob\n  timeframe: 5m\n  condition: sel"), "timeframe"),
        (rule("  sel:\n    user: bob\n  condition: sel near sel"), "near"),
        (rule(one("user", "bob"), service="windows"), "service"),
        (
            "title: t\nlogsource:\n  category: process_creation\ndetection:\n  sel:\n    a: b\n  condition: sel\n",
            "category",
        ),
    ],
)
def test_unsupported_features_give_clear_errors(text, feature):
    with pytest.raises(SigmaUnsupported, match=feature):
        parse_rule(text)


@pytest.mark.parametrize(
    "text",
    [
        "title: t\n",  # missing logsource/detection
        ": : :",  # invalid YAML
        rule(one("no_such_field", "x")),
        rule(one("message|re", "'('")),
        rule("  condition: sel"),
    ],
)
def test_malformed_rules(text):
    with pytest.raises(SigmaError):
        parse_rule(text)


def test_round_trips_rules_emitted_by_the_mcp_server(dataset):
    """The server's YAML for a proposed rule parses and hits the same events as its dry run."""
    from eval.baseline import load_events

    draft = {
        "title": "x",
        "id": "1",
        "technique": "T1110.001",
        "log_type": "auth",
        "selection": {"outcome": "failure", "src_ip": ["203.0.113.66"]},
        "description": "d",
    }
    events = load_events(dataset)
    expected = [e["event_id"] for e in events if e["log_type"] == "auth" and sigma.matches(e, draft["selection"])]
    assert parse_rule(sigma.to_yaml(draft)).hits(events) == expected and len(expected) >= 80
