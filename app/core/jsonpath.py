"""Podzbiór JSONPath używany w konfiguracji tooli: `$`, `.key`, `[n]`, `[*]`, `['key']`."""

import re
from functools import lru_cache
from typing import Any

TOKEN = re.compile(r"\.([A-Za-z_][A-Za-z0-9_-]*)|\[(\*|-?\d+)\]|\['([^']*)'\]")
WILDCARD = object()


class JsonPathError(ValueError):
    pass


@lru_cache(maxsize=1024)
def compile_path(path: str) -> tuple[Any, ...]:
    if not path.startswith("$"):
        raise JsonPathError(f"path must start with $: {path!r}")
    steps: list[Any] = []
    position = 1
    while position < len(path):
        match = TOKEN.match(path, position)
        if match is None:
            raise JsonPathError(f"invalid path {path!r} at {position}")
        name, index, quoted = match.groups()
        if name is not None:
            steps.append(name)
        elif quoted is not None:
            steps.append(quoted)
        elif index == "*":
            steps.append(WILDCARD)
        else:
            steps.append(int(index))
        position = match.end()
    return tuple(steps)


def find(document: Any, path: str) -> list[Any]:
    nodes = [document]
    for step in compile_path(path):
        next_nodes = []
        for node in nodes:
            if step is WILDCARD:
                if isinstance(node, list):
                    next_nodes.extend(node)
                elif isinstance(node, dict):
                    next_nodes.extend(node.values())
            elif isinstance(step, int):
                if isinstance(node, list) and -len(node) <= step < len(node):
                    next_nodes.append(node[step])
            elif isinstance(node, dict) and step in node:
                next_nodes.append(node[step])
        nodes = next_nodes
    return nodes


def first(document: Any, path: str, default: Any = None) -> Any:
    values = find(document, path)
    return values[0] if values else default


def has_wildcard(path: str) -> bool:
    return WILDCARD in compile_path(path)


def set_all(document: Any, path: str, value: Any) -> None:
    """Podmienia w miejscu wszystkie wartości pod ścieżką (redakcja)."""
    steps = compile_path(path)
    if not steps:
        return
    parents = [document]
    for step in steps[:-1]:
        next_parents = []
        for node in parents:
            if step is WILDCARD:
                next_parents.extend(node if isinstance(node, list) else node.values() if isinstance(node, dict) else [])
            elif isinstance(step, int):
                if isinstance(node, list) and -len(node) <= step < len(node):
                    next_parents.append(node[step])
            elif isinstance(node, dict) and step in node:
                next_parents.append(node[step])
        parents = next_parents
    last = steps[-1]
    for node in parents:
        if last is WILDCARD:
            if isinstance(node, list):
                node[:] = [value] * len(node)
            elif isinstance(node, dict):
                for key in node:
                    node[key] = value
        elif isinstance(last, int):
            if isinstance(node, list) and -len(node) <= last < len(node):
                node[last] = value
        elif isinstance(node, dict) and last in node:
            node[last] = value
