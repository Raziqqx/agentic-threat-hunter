"""Sigma rule validator: parse a documented subset of the Sigma spec and run rules over the generated logs.

Supported subset (anything else raises `SigmaUnsupported` with the offending feature named):
- logsource: `service` is one of our log types (auth, process, conn, web); `product`, if given, must be `linux`.
  `category` is not supported (there is no category -> log type mapping here).
- detection: any number of named selections. A selection is a map (AND across fields) or a list of maps (OR).
  A field value is a scalar or a list (OR across values; AND with the `all` modifier). Keyword (bare string list)
  selections, `null` values and `timeframe` are not supported.
- field modifiers: `contains`, `startswith`, `endswith`, `re` (at most one) plus optional `all`. Other modifiers
  (`base64`, `cidr`, `windash`, `gt`, ...) are rejected.
- value matching: case-insensitive string comparison, except `re` which is case-sensitive (as in the spec). Plain
  values (no modifier) honour the Sigma wildcards `*` and `?` (escape with a backslash); modified values are literal.
- condition: selection names, `and`, `or`, `not`, parentheses, `1 of <pattern>`, `all of <pattern>` and
  `1 of them` / `all of them`, where a pattern may end in `*`. Precedence: not > and > or. Aggregations
  (`| count() ...`) and `near` are rejected.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable
from dataclasses import dataclass

import yaml

from service.store import FIELDS

MATCH_MODIFIERS = {"contains", "startswith", "endswith", "re"}
SUPPORTED_MODIFIERS = MATCH_MODIFIERS | {"all"}

Predicate = Callable[[dict], bool]


class SigmaError(ValueError):
    """The rule is malformed (bad YAML, missing keys, unknown selection or field)."""


class SigmaUnsupported(SigmaError):
    """The rule uses a Sigma feature outside the supported subset."""


@dataclass
class SigmaRule:
    title: str
    log_type: str
    techniques: list[str]
    predicate: Predicate

    def matches(self, event: dict) -> bool:
        return event.get("log_type") == self.log_type and self.predicate(event)

    def hits(self, events: Iterable[dict]) -> list[str]:
        return [e["event_id"] for e in events if self.matches(e)]


# ---------------------------------------------------------------- field conditions


def _wildcard_regex(value: str) -> re.Pattern:
    out, i = [], 0
    while i < len(value):
        c = value[i]
        if c == "\\" and i + 1 < len(value) and value[i + 1] in "*?\\":
            out.append(re.escape(value[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return re.compile("".join(out), re.I | re.S)


def _value_test(mod: str | None, value) -> Callable[[str], bool]:
    if isinstance(value, bool) or not isinstance(value, (str, int, float)):
        raise SigmaUnsupported(f"value {value!r}: only string and number values are supported")
    s = str(value)
    if mod == "re":
        try:
            rx = re.compile(s)
        except re.error as exc:
            raise SigmaError(f"bad regular expression {s!r}: {exc}") from None
        return lambda a: rx.search(a) is not None
    x = s.lower()
    if mod == "contains":
        return lambda a: x in a.lower()
    if mod == "startswith":
        return lambda a: a.lower().startswith(x)
    if mod == "endswith":
        return lambda a: a.lower().endswith(x)
    if "*" in s or "?" in s:
        rx = _wildcard_regex(s)
        return lambda a: rx.fullmatch(a) is not None
    return lambda a: a.lower() == x


def _field_condition(log_type: str, key: str, value) -> Predicate:
    field, *mods = key.split("|")
    if field not in FIELDS[log_type]:
        raise SigmaError(f"field {field!r} does not exist in {log_type} logs")
    for m in mods:
        if m not in SUPPORTED_MODIFIERS:
            raise SigmaUnsupported(f"modifier {m!r} is not supported (supported: {sorted(SUPPORTED_MODIFIERS)})")
    match_mods = [m for m in mods if m in MATCH_MODIFIERS]
    if len(match_mods) > 1:
        raise SigmaUnsupported(f"{key!r}: combining {match_mods} is not supported")
    values = value if isinstance(value, list) else [value]
    if not values:
        raise SigmaError(f"{key!r}: empty value list")
    if any(v is None for v in values):
        raise SigmaUnsupported(f"{key!r}: null values are not supported")
    tests = [_value_test(match_mods[0] if match_mods else None, v) for v in values]
    combine = all if "all" in mods else any

    def pred(event: dict) -> bool:
        actual = event.get(field)
        if actual is None:
            return False
        a = str(actual)
        return combine(t(a) for t in tests)

    return pred


def _selection(log_type: str, name: str, body) -> Predicate:
    if isinstance(body, dict):
        if not body:
            raise SigmaError(f"selection {name!r} is empty")
        conds = [_field_condition(log_type, k, v) for k, v in body.items()]
        return lambda e: all(c(e) for c in conds)
    if isinstance(body, list) and body and all(isinstance(b, dict) for b in body):
        alts = [_selection(log_type, name, b) for b in body]
        return lambda e: any(a(e) for a in alts)
    if isinstance(body, list):
        raise SigmaUnsupported(f"selection {name!r}: keyword (bare value list) selections are not supported")
    raise SigmaError(f"selection {name!r}: expected a map or a list of maps")


# ---------------------------------------------------------------- condition parser

_TOKEN = re.compile(r"\s*(?:(\()|(\))|(\|)|([A-Za-z0-9_*]+))")


def tokenize(condition: str) -> list[str]:
    tokens, pos = [], 0
    condition = condition.strip()
    while pos < len(condition):
        m = _TOKEN.match(condition, pos)
        if not m or m.end() == pos:
            raise SigmaError(f"condition: unexpected character at {pos}: {condition[pos:]!r}")
        if m.group(3):
            raise SigmaUnsupported("condition: aggregations ('| count() ...') are not supported")
        tokens.append(m.group(m.lastindex))
        if tokens[-1].lower() == "near":
            raise SigmaUnsupported("condition: 'near' is not supported")
        pos = m.end()
    return tokens


class _ConditionParser:
    """Recursive descent: or_expr := and_expr ('or' and_expr)*; and_expr := not_expr ('and' not_expr)*;
    not_expr := 'not' not_expr | atom; atom := '(' or_expr ')' | ('1'|'all') 'of' (pattern|'them') | name."""

    KEYWORDS = {"and", "or", "not", "of", "them", "near"}

    def __init__(self, tokens: list[str], selections: dict[str, Predicate]):
        self.toks, self.i, self.sel = tokens, 0, selections

    def peek(self) -> str | None:
        return self.toks[self.i].lower() if self.i < len(self.toks) else None

    def take(self, expected: str | None = None) -> str:
        tok = self.toks[self.i] if self.i < len(self.toks) else None
        if tok is None or (expected and tok.lower() != expected):
            raise SigmaError(f"condition: expected {expected or 'a term'}, got {tok!r}")
        self.i += 1
        return tok

    def parse(self) -> Predicate:
        if not self.toks:
            raise SigmaError("condition is empty")
        pred = self.or_expr()
        if self.i != len(self.toks):
            raise SigmaError(f"condition: unexpected {self.toks[self.i]!r}")
        return pred

    def or_expr(self) -> Predicate:
        parts = [self.and_expr()]
        while self.peek() == "or":
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else (lambda e: any(p(e) for p in parts))

    def and_expr(self) -> Predicate:
        parts = [self.not_expr()]
        while self.peek() == "and":
            self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else (lambda e: all(p(e) for p in parts))

    def not_expr(self) -> Predicate:
        if self.peek() == "not":
            self.take()
            inner = self.not_expr()
            return lambda e: not inner(e)
        return self.atom()

    def atom(self) -> Predicate:
        tok = self.peek()
        if tok == "(":
            self.take()
            inner = self.or_expr()
            self.take(")")
            return inner
        if tok in ("1", "all") and self.i + 1 < len(self.toks) and self.toks[self.i + 1].lower() == "of":
            quant = self.take().lower()
            self.take("of")
            target = self.take()
            names = list(self.sel) if target.lower() == "them" else fnmatch.filter(self.sel, target)
            if not names:
                raise SigmaError(f"condition: {target!r} matches no selection")
            preds = [self.sel[n] for n in names]
            combine = any if quant == "1" else all
            return lambda e: combine(p(e) for p in preds)
        if tok is None or tok in self.KEYWORDS or tok == ")":
            raise SigmaError(f"condition: expected a selection name, got {tok!r}")
        name = self.take()
        if name not in self.sel:
            raise SigmaError(f"condition: unknown selection {name!r}")
        return self.sel[name]


def parse_condition(condition: str, selections: dict[str, Predicate]) -> Predicate:
    return _ConditionParser(tokenize(condition), selections).parse()


# ---------------------------------------------------------------- rule


def _techniques(tags) -> list[str]:
    out = []
    for t in tags or []:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(t).lower())
        if m:
            out.append(m.group(1).upper())
    return out


def parse_rule(source: str | dict) -> SigmaRule:
    """Parse Sigma YAML (or an already-loaded dict) into a rule that can be run over events."""
    if isinstance(source, str):
        try:
            doc = yaml.safe_load(source)
        except yaml.YAMLError as exc:
            raise SigmaError(f"invalid YAML: {exc}") from None
    else:
        doc = source
    if not isinstance(doc, dict):
        raise SigmaError("rule must be a YAML mapping")
    for key in ("title", "logsource", "detection"):
        if key not in doc:
            raise SigmaError(f"missing required key {key!r}")

    ls = doc["logsource"]
    if not isinstance(ls, dict):
        raise SigmaError("logsource must be a mapping")
    if "category" in ls:
        raise SigmaUnsupported("logsource.category is not supported; use service: auth|process|conn|web")
    if ls.get("product", "linux") != "linux":
        raise SigmaUnsupported(f"logsource.product {ls['product']!r} is not supported (only linux)")
    log_type = ls.get("service")
    if log_type not in FIELDS:
        raise SigmaUnsupported(f"logsource.service {log_type!r} is not one of {sorted(FIELDS)}")

    det = doc["detection"]
    if not isinstance(det, dict) or "condition" not in det:
        raise SigmaError("detection must be a mapping with a condition")
    if "timeframe" in det:
        raise SigmaUnsupported("detection.timeframe is not supported")
    condition = det["condition"]
    if isinstance(condition, list):
        raise SigmaUnsupported("a list of conditions is not supported; use one condition with 'or'")
    if not isinstance(condition, str):
        raise SigmaError("condition must be a string")
    selections = {name: _selection(log_type, name, body) for name, body in det.items() if name != "condition"}
    if not selections:
        raise SigmaError("detection has no selections")
    return SigmaRule(str(doc["title"]), log_type, _techniques(doc.get("tags")), parse_condition(condition, selections))
