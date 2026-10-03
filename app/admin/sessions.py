"""Sessions API (A4 / S12): lista sesji i timeline — hopy + decyzje + approvale.

Kontrakt: docs/api/sessions.md.
"""

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request

from app.admin.common import KeysetPage, iso
from app.pipeline.models import Verdict

router = APIRouter(prefix="/sessions", tags=["Sessions"])


def session_item(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "agentId": row["agent_id"],
        "agentName": row["agent_name"],
        "task": row["task"],
        "status": row["status"],
        "denyCount": row["deny_count"],
        "terminationReason": row["termination_reason"],
        "createdAt": iso(row["created_at"]),
        "lastActivityAt": iso(row["last_activity_at"]),
        "closedAt": iso(row["closed_at"]),
        "decisions": row["decisions"],
        "pendingApprovals": row["pending"],
    }


SELECT = """
select s.*, coalesce(a.name, s.agent_id) as agent_name,
       (select count(*) from proxy.decisions d where d.session_id = s.id) as decisions,
       (select count(*) from proxy.approvals ap where ap.session_id = s.id and ap.status = 'pending') as pending
  from proxy.sessions s left join proxy.agents a on a.id = s.agent_id
"""


@router.get("")
async def list_sessions(
    request: Request,
    agent_id: str | None = None,
    status: str | None = None,
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = None,
) -> dict:
    params: list[Any] = []
    where = ["true"]
    if agent_id:
        params.append(agent_id)
        where.append(f"s.agent_id = ${len(params)}")
    if status:
        params.append(status)
        where.append(f"s.status = ${len(params)}")
    page = KeysetPage("s.last_activity_at", "desc", cursor, "timestamptz")
    where.append(page.where(params, "s.id"))
    params.append(limit + 1)
    rows = await request.app.state.db.fetch(
        f"{SELECT} where {' and '.join(where)} order by {page.order('s.id')} limit ${len(params)}", *params
    )
    return {"items": [session_item(row) for row in rows[:limit]], "nextCursor": page.next_cursor(rows, limit, "last_activity_at")}


@router.get("/{session_id}")
async def get_session(session_id: str, request: Request) -> dict:
    db = request.app.state.db
    row = await db.fetchrow(f"{SELECT} where s.id = $1", session_id)
    if row is None:
        raise HTTPException(404, "Unknown session")
    hops = await db.fetch("select * from proxy.hops where session_id = $1 order by seq", session_id)
    decisions = {
        item["hop_id"]: item
        for item in await db.fetch(
            """
            select d.*, ap.id as approval_id, ap.status as approval_status, ap.feedback, ap.resolved_by
              from proxy.decisions d left join proxy.approvals ap on ap.decision_id = d.id
             where d.session_id = $1
            """,
            session_id,
        )
    }
    timeline = []
    for hop in hops:
        entry = {
            "hopId": hop["id"],
            "seq": hop["seq"],
            "timestamp": iso(hop["created_at"]),
            "direction": hop["direction"],
            "protocol": hop["protocol"],
            "app": hop["app_id"],
            "tool": hop["action"],
            "method": hop["http_method"],
            "path": hop["http_path"],
            "upstreamStatus": hop["upstream_status"],
            "upstreamLatencyMs": float(hop["upstream_latency_ms"]) if hop["upstream_latency_ms"] is not None else None,
            "payload": hop["payload"],
        }
        decision = decisions.get(hop["id"])
        if decision is not None:
            entry["decision"] = {
                "id": decision["id"],
                "decision": Verdict(decision["verdict"]).ui,
                "confidence": float(decision["confidence"]),
                "reasons": decision["reasons"],
                "decisionChain": decision["chain"],
                "actionStatus": decision["action_status"],
                "degraded": decision["degraded"],
                "approvalId": decision["approval_id"],
                "approvalStatus": decision["approval_status"],
                "feedback": decision["feedback"],
                "resolvedBy": decision["resolved_by"],
            }
        timeline.append(entry)
    return {**session_item(row), "state": row["state"], "timeline": timeline}
