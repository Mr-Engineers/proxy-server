import base64
import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import asyncpg
from fastapi import HTTPException, Request


def iso(value: datetime | None) -> str | None:
    return value.isoformat().replace("+00:00", "Z") if value is not None else None


def encode_cursor(values: list[Any]) -> str:
    raw = json.dumps([iso(value) if isinstance(value, datetime) else value for value in values], default=str)
    return base64.urlsafe_b64encode(raw.encode()).decode().rstrip("=")


def decode_cursor(cursor: str | None) -> list[Any] | None:
    if not cursor:
        return None
    try:
        padded = cursor + "=" * (-len(cursor) % 4)
        values = json.loads(base64.urlsafe_b64decode(padded))
    except ValueError as exc:
        raise HTTPException(400, "Invalid cursor") from exc
    if not isinstance(values, list) or len(values) != 2:
        raise HTTPException(400, "Invalid cursor")
    return values


def parse_time(value: str | None, name: str) -> datetime | None:
    if value is None:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise HTTPException(400, f"Invalid {name}") from exc
    if parsed.tzinfo is None:
        raise HTTPException(400, f"{name} must include a timezone offset")
    return parsed


def multi(values: list[str] | None) -> list[str]:
    return [item.strip() for value in values or [] for item in value.split(",") if item.strip()]


class KeysetPage:
    """Paginacja kursorem po (kolumna sortowania, id)."""

    def __init__(self, column_sql: str, direction: str, cursor: str | None, cast: str = "") -> None:
        if direction not in ("asc", "desc"):
            raise HTTPException(400, "sort_dir must be asc or desc")
        self.column_sql = f'{column_sql} collate "C"' if cast == "text" else column_sql
        self.direction = direction
        self.cursor = decode_cursor(cursor)
        self.cast = cast

    def where(self, params: list[Any], id_sql: str) -> str:
        if self.cursor is None:
            return "true"
        value, last_id = self.cursor
        if self.cast == "timestamptz" and isinstance(value, str):
            value = parse_time(value, "cursor")
        params.extend([value, last_id])
        op = "<" if self.direction == "desc" else ">"
        cast = f"::{self.cast}" if self.cast and self.cast != "timestamptz" else ""
        return f"({self.column_sql}, {id_sql}) {op} (${len(params) - 1}{cast}, ${len(params)})"

    def order(self, id_sql: str) -> str:
        return f"{self.column_sql} {self.direction}, {id_sql} {self.direction}"

    @staticmethod
    def next_cursor(rows: list, limit: int, value_key: str, id_key: str = "id") -> str | None:
        if len(rows) <= limit:
            return None
        last = rows[limit - 1]
        return encode_cursor([last[value_key], last[id_key]])


@asynccontextmanager
async def mutation(request: Request) -> AsyncIterator[asyncpg.Connection]:
    """Transakcja z `proxy.actor` — trafia do `config_changes.changed_by`."""
    async with request.app.state.db.acquire() as conn, conn.transaction():
        await conn.execute("select set_config('proxy.actor', $1, true)", request.state.operator.actor)
        yield conn


def agent_names(request: Request) -> dict[str, str]:
    return {agent.id: agent.name for agent in request.app.state.snapshot.agents.values()}
