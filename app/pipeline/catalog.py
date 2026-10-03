"""Katalog akcji: trasa REST → tool → `Action`; capture odpowiedzi do stanu sesji."""

import json
from typing import Any
from urllib.parse import parse_qsl

from app.config.models import CaptureRule, ConfigSnapshot, ToolConfig
from app.core.jsonpath import find, first, has_wildcard

UNMATCHED = "<unmatched>"
MAX_STATE_ITEMS = 200


def match_route(snapshot: ConfigSnapshot, app_id: str, method: str, path: str) -> tuple[ToolConfig, dict[str, str]] | None:
    for tool in snapshot.tools.get(app_id, ()):
        if tool.http_method != method or tool.path_pattern is None:
            continue
        match = tool.path_pattern.match(path)
        if match is not None:
            return tool, match.groupdict()
    return None


def parse_json(raw: bytes) -> Any:
    if not raw:
        return None
    try:
        return json.loads(raw)
    except ValueError:
        return None


def request_document(query: str, path_params: dict[str, str], body: bytes) -> dict[str, Any]:
    document: dict[str, Any] = dict(parse_qsl(query, keep_blank_values=True))
    document.update(path_params)
    parsed = parse_json(body)
    if isinstance(parsed, dict):
        document.update(parsed)
    elif parsed is not None:
        document["body"] = parsed
    elif body:
        document["body"] = body.decode("utf-8", errors="replace")[:2000]
    return document


def extract_args(tool: ToolConfig, document: dict[str, Any]) -> dict[str, Any]:
    if not tool.args:
        return dict(document)
    args = {}
    for name, path in tool.args.items():
        values = find(document, path)
        if values:
            args[name] = values if has_wildcard(path) else values[0]
    return args


def _project(item: Any, fields: dict[str, str]) -> Any:
    if not fields:
        return item
    return {name: first(item, path if path.startswith("$") else f"$.{path}") for name, path in fields.items()}


def apply_capture(
    state: dict[str, Any],
    tool: ToolConfig,
    request_doc: dict[str, Any],
    response_doc: Any,
) -> dict[str, Any]:
    """Zwraca nowy stan sesji; listy deduplikowane po `key` (nowszy wpis wygrywa)."""
    updated = dict(state)
    for rule in tool.capture:
        source = request_doc if rule.origin == "request" else response_doc
        if source is None:
            continue
        items = [_project(item, rule.fields) for item in find(source, rule.source)]
        if not items:
            continue
        current = list(updated.get(rule.into) or [])
        updated[rule.into] = _merge(current, items, rule)
    return updated


def _merge(current: list, items: list, rule: CaptureRule) -> list:
    if rule.key is None:
        return (current + items)[-MAX_STATE_ITEMS:]
    merged = {str(item.get(rule.key)): item for item in current if isinstance(item, dict)}
    for item in items:
        if isinstance(item, dict) and item.get(rule.key) is not None:
            merged.pop(str(item[rule.key]), None)
            merged[str(item[rule.key])] = item
    return list(merged.values())[-MAX_STATE_ITEMS:]


def scan_texts(tool: ToolConfig, document: Any, limit: int = 64) -> list[str]:
    """Teksty dla klasyfikatorów (tor M): `scan_mode` all_strings / selected / none."""
    if document is None or tool.scan_mode == "none":
        return []
    if tool.scan_mode == "selected":
        values = [value for path in tool.scan for value in find(document, path)]
    else:
        values = []
        stack = [document]
        while stack and len(values) < limit:
            node = stack.pop()
            if isinstance(node, dict):
                stack.extend(node.values())
            elif isinstance(node, list):
                stack.extend(node)
            else:
                values.append(node)
    return [value for value in values if isinstance(value, str) and len(value) >= 16][:limit]
