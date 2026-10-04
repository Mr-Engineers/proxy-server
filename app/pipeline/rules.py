"""Reguły agenta z UI (Agents → Rules): drzewo warunków, pierwsza pasująca włączona reguła wygrywa.

Wartość pola szukana kolejno w: `Action.args`, request (query + body), faktach pipeline'u.
Brak pola → liść fałszywy (poza `is_empty`).
"""

from collections.abc import Iterable
from fnmatch import fnmatchcase
from typing import Any

from pydantic import BaseModel

from app.config.models import RuleConfig

OPS = {"eq", "neq", "gt", "gte", "lt", "lte", "in", "not_in", "is_empty", "not_empty"}
OUTCOMES = {"allow", "deny", "needs_ai"}
MISSING = object()


class RuleError(ValueError):
    pass


class RuleMatch(BaseModel):
    rule_id: str | None = None
    rule_name: str | None = None
    outcome: str | None = None
    detail: str = "No rule matched"


def validate_condition(node: Any, depth: int = 0) -> None:
    if depth > 8:
        raise RuleError("condition tree is too deep")
    if not isinstance(node, dict):
        raise RuleError("condition must be an object")
    if "combinator" in node:
        if node["combinator"] not in ("and", "or"):
            raise RuleError("combinator must be and | or")
        children = node.get("children", [])
        if not isinstance(children, list):
            raise RuleError("children must be a list")
        for child in children:
            validate_condition(child, depth + 1)
        return
    if not isinstance(node.get("field"), str) or not node["field"]:
        raise RuleError("leaf requires field")
    if node.get("op") not in OPS:
        raise RuleError(f"op must be one of {sorted(OPS)}")
    if node["op"] in ("in", "not_in") and not isinstance(node.get("value"), list):
        raise RuleError(f"{node['op']} requires a list value")


def _lookup(field: str, sources: Iterable[dict[str, Any]]) -> Any:
    for source in sources:
        node: Any = source
        for part in field.split("."):
            if isinstance(node, dict) and part in node:
                node = node[part]
            else:
                node = MISSING
                break
        if node is not MISSING:
            return node
    return MISSING


def _number(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value)
        except ValueError:
            return None
    if isinstance(value, dict) and "amount" in value:
        return _number(value["amount"])
    return None


def _as_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        folded = value.strip().casefold()
        if folded in {"true", "1", "yes"}:
            return True
        if folded in {"false", "0", "no"}:
            return False
    return None


def _equal(left: Any, right: Any) -> bool:
    left_number, right_number = _number(left), _number(right)
    if left_number is not None and right_number is not None:
        return left_number == right_number
    left_bool, right_bool = _as_bool(left), _as_bool(right)
    if left_bool is not None and right_bool is not None:
        return left_bool is right_bool
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    return left == right


def _leaf(node: dict[str, Any], sources: list[dict[str, Any]]) -> bool:
    value = _lookup(node["field"], sources)
    op = node["op"]
    empty = value is MISSING or value is None or value == "" or value == [] or value == {}
    if op == "is_empty":
        return empty
    if op == "not_empty":
        return not empty
    if value is MISSING:
        return False
    expected = node.get("value")
    match op:
        case "eq":
            return _equal(value, expected)
        case "neq":
            return not _equal(value, expected)
        case "in":
            return any(_equal(value, item) for item in expected or [])
        case "not_in":
            return not any(_equal(value, item) for item in expected or [])
    left, right = _number(value), _number(expected)
    if left is None or right is None:
        return False
    return {"gt": left > right, "gte": left >= right, "lt": left < right, "lte": left <= right}[op]


def matches(node: dict[str, Any], sources: list[dict[str, Any]]) -> bool:
    if "combinator" in node:
        results = (matches(child, sources) for child in node.get("children", []))
        return all(results) if node["combinator"] == "and" else any(results)
    return _leaf(node, sources)


def tool_matches(pattern: str, tool: str) -> bool:
    return pattern == tool or pattern == "*" or fnmatchcase(tool, pattern)


def evaluate_rules(
    rules: Iterable[RuleConfig],
    tool: str,
    args: dict[str, Any],
    request: dict[str, Any],
    facts: dict[str, Any] | None = None,
) -> RuleMatch:
    sources = [args, request, facts or {}]
    for rule in rules:
        if not rule.enabled or not tool_matches(rule.tool, tool):
            continue
        if matches(rule.condition or {"combinator": "and", "children": []}, sources):
            return RuleMatch(rule_id=rule.id, rule_name=rule.name, outcome=rule.outcome, detail=f"{rule.name} → {rule.outcome}")
    return RuleMatch()
