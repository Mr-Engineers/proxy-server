"""Audit API — docs/api/audit.md. Źródło: `proxy.decisions` (A1: jedno źródło prawdy w schemacie proxy)."""

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app.admin.common import KeysetPage, iso, multi, parse_time
from app.pipeline.models import UI_TO_VERDICT, Verdict

router = APIRouter(prefix="/audit", tags=["Audit"])

SORTS = {
    "time": ("d.created_at", "timestamptz", "created_at"),
    "tool": ("d.tool", "text", "tool"),
    "agent": ("d.agent_id", "text", "agent_id"),
    "decision": ("d.verdict", "text", "verdict"),
}

SELECT = """
select d.id, d.created_at, d.tool, d.agent_id, coalesce(a.name, d.agent_id) as agent_name, d.verdict, d.chain,
       d.args_redacted, d.session_id, d.action_status, d.http_status, d.upstream_status, d.reasons, d.signals,
       d.degraded, d.confidence, d.config_revision, d.latency_ms, d.kind, d.app_id, d.request_id, d.quota_id,
       d.retry_after_seconds, ap.id as approval_id, ap.status as approval_status
  from proxy.decisions d
  left join proxy.agents a on a.id = d.agent_id
  left join proxy.approvals ap on ap.decision_id = d.id
"""


def audit_event(row: Any, detail: bool = False) -> dict[str, Any]:
    item = {
        "id": row["id"],
        "timestamp": iso(row["created_at"]),
        "tool": row["tool"],
        "agentId": row["agent_id"],
        "agentName": row["agent_name"],
        "decision": Verdict(row["verdict"]).ui,
        "decisionChain": row["chain"] or [],
        "argsRedacted": row["args_redacted"] or {},
        "sessionId": row["session_id"],
        "approvalId": row["approval_id"],
        "actionStatus": row["action_status"],
        "httpStatus": row["http_status"] or None,
        "degraded": row["degraded"],
    }
    if row["quota_id"]:
        item["quotaId"] = row["quota_id"]
        item["retryAfterSeconds"] = row["retry_after_seconds"]
    if detail:
        signals = dict(row["signals"] or {})
        item |= {
            "reasons": row["reasons"] or [],
            "signals": {key: value for key, value in signals.items() if key not in ("facts", "enrichment")},
            "facts": signals.get("facts", {}),
            "enrichment": signals.get("enrichment", {}),
            "confidence": float(row["confidence"]),
            "configRevision": row["config_revision"],
            "latencyMs": float(row["latency_ms"]),
            "kind": row["kind"],
            "app": row["app_id"],
            "requestId": row["request_id"],
            "upstreamStatus": row["upstream_status"],
            "approvalStatus": row["approval_status"],
        }
    return item


def decision_filter(values: list[str]) -> list[str]:
    result = []
    for value in values:
        if value not in UI_TO_VERDICT:
            raise HTTPException(400, f"Invalid decision filter: {value}")
        result.append(UI_TO_VERDICT[value])
    return result


@router.get("")
async def list_audit(
    request: Request,
    search: str | None = None,
    agent_id: str | None = None,
    agent_name: str | None = None,
    decision: list[str] | None = Query(default=None),
    from_: str | None = Query(default=None, alias="from"),
    to: str | None = None,
    tool: str | None = None,
    session_id: str | None = None,
    sort: str = "time",
    sort_dir: str = "desc",
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = None,
) -> dict:
    if sort not in SORTS:
        raise HTTPException(400, f"sort must be one of {sorted(SORTS)}")
    column, cast, key = SORTS[sort]
    start, end = parse_time(from_, "from"), parse_time(to, "to")
    if start and end and end <= start:
        raise HTTPException(400, "to must be after from")

    params: list[Any] = []
    where = ["true"]

    def add(sql: str, value: Any) -> None:
        params.append(value)
        where.append(sql.replace("?", f"${len(params)}"))

    if search:
        add("(d.tool ilike '%' || ? || '%' or d.args_redacted::text ilike '%' || ? || '%')", search)
    if agent_id:
        add("d.agent_id = ?", agent_id)
    if agent_name:
        add("a.name ilike ?", agent_name)
    verdicts = decision_filter(multi(decision))
    if verdicts:
        add("d.verdict = any(?::text[])", verdicts)
    if start:
        add("d.created_at >= ?", start)
    if end:
        add("d.created_at < ?", end)
    if tool:
        add("d.tool like ? || '%'", tool)
    if session_id:
        add("d.session_id = ?", session_id)

    page = KeysetPage(column, sort_dir, cursor, cast)
    where.append(page.where(params, "d.id"))
    params.append(limit + 1)
    rows = await request.app.state.db.fetch(
        f"{SELECT} where {' and '.join(where)} order by {page.order('d.id')} limit ${len(params)}", *params
    )
    items = [audit_event(row) for row in rows[:limit]]
    return {"items": items, "nextCursor": page.next_cursor(rows, limit, key)}


@router.get("/{event_id}")
async def get_audit(event_id: str, request: Request) -> dict:
    row = await request.app.state.db.fetchrow(f"{SELECT} where d.id = $1", event_id)
    if row is None:
        raise HTTPException(404, "Unknown event")
    return audit_event(row, detail=True)
