"""A small Sigma subset: one `selection` map, AND across fields, OR across list values.

Supported field modifiers: none (equality), |contains, |startswith, |endswith.
"""

from __future__ import annotations

MODIFIERS = {"", "contains", "startswith", "endswith"}


def split_key(key: str) -> tuple[str, str]:
    field, _, mod = key.partition("|")
    return field, mod


def _match_value(actual, mod: str, expected) -> bool:
    if actual is None:
        return False
    if mod == "":
        return str(actual).lower() == str(expected).lower()
    a, x = str(actual).lower(), str(expected).lower()
    return {"contains": x in a, "startswith": a.startswith(x), "endswith": a.endswith(x)}[mod]


def matches(event: dict, selection: dict) -> bool:
    for key, expected in selection.items():
        field, mod = split_key(key)
        values = expected if isinstance(expected, list) else [expected]
        if not any(_match_value(event.get(field), mod, v) for v in values):
            return False
    return True


def _yaml_scalar(v) -> str:
    if isinstance(v, int):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def to_yaml(rule: dict) -> str:
    """Emit the rule as Sigma-style YAML (enough structure for our fixed schema)."""
    lines = [
        f"title: {_yaml_scalar(rule['title'])}",
        f"id: {rule['id']}",
        "status: experimental",
        f"description: {_yaml_scalar(rule['description'])}",
        "logsource:",
        "  product: linux",
        f"  service: {rule['log_type']}",
        "detection:",
        "  selection:",
    ]
    for key, val in rule["selection"].items():
        if isinstance(val, list):
            lines.append(f"    {key}:")
            lines.extend(f"      - {_yaml_scalar(v)}" for v in val)
        else:
            lines.append(f"    {key}: {_yaml_scalar(val)}")
    lines += ["  condition: selection", "tags:", f"  - attack.{rule['technique'].lower()}", "level: medium"]
    return "\n".join(lines) + "\n"
