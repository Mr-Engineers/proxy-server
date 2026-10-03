"""Overview API — docs/api/overview.md (+ ta sama logika dla /agents/{id}/overview)."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

import asyncpg
from fastapi import APIRouter, HTTPException, Query, Request

from app.admin.common import parse_time
from app.config.models import ConfigSnapshot

router = APIRouter(tags=["Overview"])

BUCKETS = {"5m": 300, "15m": 900, "1h": 3600, "1d": 86400}
PRESETS = {"today", "24h", "7d", "30d"}
COMPARE = {"today": "vs yesterday", "24h": "vs prior 24 hours", "7d": "vs prior 7 days", "30d": "vs prior 30 days", "custom": "vs previous period"}
DECISION_ORDER = [("allow", "allow"), ("caution", "escalate"), ("deny", "deny"), ("rate_limited", "rate_limited")]


@dataclass
class Window:
    preset: str
    start: datetime
    end: datetime
    previous_start: datetime
    previous_end: datetime
    tz: ZoneInfo
    bucket: str

    def as_json(self) -> dict[str, Any]:
        def local(moment: datetime) -> str:
            return moment.astimezone(self.tz).isoformat()

        return {
            "preset": self.preset,
            "start": local(self.start),
            "end": local(self.end),
            "previousStart": local(self.previous_start),
            "previousEnd": local(self.previous_end),
            "timezone": self.tz.key,
            "bucket": self.bucket,
            "compareLabel": COMPARE[self.preset],
        }


def resolve_window(
    range_: str | None, from_: str | None, to: str | None, tz_name: str, bucket: str | None, now: datetime | None = None
) -> Window:
    try:
        tz = ZoneInfo(tz_name)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise HTTPException(400, f"Invalid tz: {tz_name}") from exc
    if bucket is not None and bucket not in BUCKETS:
        raise HTTPException(400, f"bucket must be one of {sorted(BUCKETS)}")
    now = now or datetime.now(timezone.utc)

    if range_ is None and (from_ or to):
        start, end = parse_time(from_, "from"), parse_time(to, "to")
        if start is None or end is None:
            raise HTTPException(400, "Custom range requires both from and to")
        if end <= start:
            raise HTTPException(400, "to must be after from")
        if end - start > timedelta(days=90):
            raise HTTPException(400, "Custom range may span at most 90 days")
        preset = "custom"
        previous_start, previous_end = start - (end - start), start
    else:
        preset = range_ or "today"
        if preset not in PRESETS:
            raise HTTPException(400, f"range must be one of {sorted(PRESETS)}")
        end = now
        if preset == "today":
            local_midnight = now.astimezone(tz).replace(hour=0, minute=0, second=0, microsecond=0)
            start = local_midnight.astimezone(timezone.utc)
            previous_start = (local_midnight - timedelta(days=1)).astimezone(timezone.utc)
            previous_end = start
        else:
            span = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "30d": timedelta(days=30)}[preset]
            start = now - span
            previous_start, previous_end = start - span, start

    if bucket is None:
        if preset in ("today", "24h"):
            bucket = "5m"
        elif preset == "7d":
            bucket = "1h"
        elif preset == "30d":
            bucket = "1d"
        else:
            seconds = (end - start).total_seconds()
            bucket = next((name for name, size in BUCKETS.items() if seconds / size <= 300), "1d")
    return Window(preset, start, end, previous_start, previous_end, tz, bucket)


def _agent_filter(agent_id: str | None, params: list[Any]) -> str:
    if agent_id is None:
        return "true"
    params.append(agent_id)
    return f"agent_id = ${len(params)}"


async def window_metrics(db: asyncpg.Pool, window: Window, agent_id: str | None, top_limit: int) -> dict[str, Any]:
    params: list[Any] = [window.start, window.end]
    agent_sql = _agent_filter(agent_id, params)
    base = f"from proxy.decisions where created_at >= $1 and created_at < $2 and {agent_sql}"

    split_rows = await db.fetch(f"select verdict, count(*) as n {base} group by verdict", *params)
    split = {row["verdict"]: row["n"] for row in split_rows}
    calls = sum(split.values())

    previous = await db.fetchval(
        f"select count(*) from proxy.decisions where created_at >= $1 and created_at < $2 and {agent_sql}",
        window.previous_start, window.previous_end, *params[2:],
    )
    delta = round((calls - previous) * 100 / previous) if previous else None

    size = BUCKETS[window.bucket]
    bucket_rows = await db.fetch(
        f"select floor(extract(epoch from created_at - $1) / {size})::int as idx, count(*) as n {base} group by idx",
        *params,
    )
    counts = {row["idx"]: row["n"] for row in bucket_rows}
    buckets = []
    cursor, index = window.start, 0
    while cursor < window.end:
        bucket_end = min(cursor + timedelta(seconds=size), window.end)
        buckets.append({
            "start": cursor.astimezone(window.tz).isoformat(),
            "end": bucket_end.astimezone(window.tz).isoformat(),
            "count": counts.get(index, 0),
        })
        cursor, index = cursor + timedelta(seconds=size), index + 1

    tools = await db.fetch(
        f"select tool, count(*) as n {base} group by tool order by n desc, tool limit {int(top_limit)}", *params
    )

    def pct(verdict: str) -> int:
        return round(split.get(verdict, 0) * 100 / calls) if calls else 0

    return {
        "calls": calls,
        "callsDeltaPct": delta,
        "denyRatePct": pct("deny"),
        "cautionRatePct": pct("escalate"),
        "rateLimited": split.get("rate_limited", 0),
        "decisionSplit": [{"decision": ui, "count": split.get(verdict, 0)} for ui, verdict in DECISION_ORDER],
        "callsOverTime": buckets,
        "topTools": [{"tool": row["tool"], "count": row["n"]} for row in tools],
        "_split": split,
    }


async def quota_usage(db: asyncpg.Pool, snapshot: ConfigSnapshot, agent_id: str | None = None) -> list[dict[str, Any]]:
    result = []
    for owner, quotas in snapshot.quotas.items():
        if agent_id is not None and owner != agent_id:
            continue
        agent = snapshot.agents.get(owner)
        for quota in quotas:
            if not quota.enabled:
                continue
            used = await db.fetchval(
                """
                select count(*) from proxy.decisions
                 where agent_id = $1 and verdict <> 'rate_limited' and created_at > now() - make_interval(secs => $2)
                """,
                owner, quota.window_seconds,
            )
            result.append({
                "id": quota.id,
                "agentId": owner,
                "label": f"{agent.name if agent else owner} · {quota.name}",
                "used": used,
                "cap": quota.cap,
                "unit": "calls",
            })
    return result


@router.get("/overview")
async def overview(
    request: Request,
    range_: str | None = Query(default=None, alias="range"),
    from_: str | None = Query(default=None, alias="from"),
    to: str | None = None,
    tz: str | None = None,
    bucket: str | None = None,
    top_limit: int = Query(default=5, ge=1, le=50),
) -> dict:
    snapshot = request.app.state.snapshot
    db = request.app.state.db
    window = resolve_window(range_, from_, to, tz or snapshot.settings.timezone, bucket)
    metrics = await window_metrics(db, window, None, top_limit)
    metrics.pop("_split")

    agent_rows = await db.fetch(
        """
        select d.agent_id, coalesce(a.name, d.agent_id) as agent_name,
               count(*) as n,
               count(*) filter (where d.verdict = 'allow') as clear,
               count(*) filter (where d.verdict in ('escalate', 'deny')) as flagged
          from proxy.decisions d left join proxy.agents a on a.id = d.agent_id
         where d.created_at >= $1 and d.created_at < $2
         group by d.agent_id, a.name
         order by n desc, d.agent_id
        """,
        window.start, window.end,
    )
    budgets = sorted(await quota_usage(db, snapshot), key=lambda item: item["used"] / item["cap"], reverse=True)
    return {
        "window": window.as_json(),
        **metrics,
        "pendingApprovals": await db.fetchval(
            "select count(*) from proxy.approvals where status = 'pending' and expires_at > now()"
        ),
        "activeAgents": sum(1 for agent in snapshot.agents.values() if agent.status == "active"),
        "agentSplit": [
            {"agentId": row["agent_id"], "agentName": row["agent_name"], "clear": row["clear"], "flagged": row["flagged"]}
            for row in agent_rows
        ],
        "topAgents": [
            {"agentId": row["agent_id"], "agentName": row["agent_name"], "count": row["n"]} for row in agent_rows[:top_limit]
        ],
        "budgets": budgets[:top_limit],
    }
