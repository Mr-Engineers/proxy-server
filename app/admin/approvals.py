"""Approvals API — docs/api/approvals.md."""

from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.admin.common import KeysetPage, iso
from app.hitl.approvals import ApprovalError
from app.store.runtime import seconds_until, utcnow

router = APIRouter(prefix="/approvals", tags=["Approvals"])

SORTS = {
    "age": ("ap.created_at", "timestamptz", "created_at", True),
    "created_at": ("ap.created_at", "timestamptz", "created_at", False),
    "ttl": ("ap.expires_at", "timestamptz", "expires_at", False),
    "tool": ("ap.tool", "text", "tool", False),
    "agent": ("ap.agent_id", "text", "agent_id", False),
}

SELECT = """
select ap.id, ap.tool, ap.agent_id, coalesce(a.name, ap.agent_id) as agent_name, ap.created_at, ap.expires_at,
       ap.status, ap.session_id, ap.decision_id, d.signals, d.reasons, d.args_redacted, d.chain
  from proxy.approvals ap
  join proxy.decisions d on d.id = ap.decision_id
  left join proxy.agents a on a.id = ap.agent_id
"""


def matched_rules(reasons: list[dict]) -> list[str]:
    return [reason.get("message") or reason.get("code") for reason in reasons or []]


def _optional_prob(value: Any) -> float | None:
    """Model probs only when specialist scored; omit invented 50/50 placeholders."""
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def model_choice_label(signals: dict[str, Any], chain: list[dict] | None) -> str:
    choice = signals.get("choice")
    if choice == "clear":
        return "clear → allow"
    if choice == "deny":
        return "deny → block"
    if choice == "caution":
        return "caution → human"
    if signals.get("failed"):
        detail = signals.get("error_detail") or signals.get("error")
        if detail:
            return f"specialist failed: {str(detail)[:160]}"
    for step in chain or []:
        if step.get("stage") == "specialist" and step.get("detail"):
            return str(step["detail"])
    return "caution → human"


def approval_item(row: Any) -> dict[str, Any]:
    signals = row["signals"] or {}
    chain = row["chain"] or []
    now = utcnow()
    return {
        "id": row["id"],
        "tool": row["tool"],
        "agentId": row["agent_id"],
        "agentName": row["agent_name"],
        "specialist": signals.get("specialist", "rules/v0"),
        "allowProb": _optional_prob(signals.get("allow_prob")),
        "denyProb": _optional_prob(signals.get("deny_prob")),
        "ageSeconds": max(int((now - row["created_at"]).total_seconds()), 0),
        "ttlSeconds": seconds_until(row["expires_at"]),
        "matchedRules": matched_rules(row["reasons"]),
        "modelChoice": model_choice_label(signals, chain),
        "argsRedacted": row["args_redacted"] or {},
        "createdAt": iso(row["created_at"]),
        "expiresAt": iso(row["expires_at"]),
        "status": row["status"],
        "decisionId": row["decision_id"],
        "sessionId": row["session_id"],
        "decisionChain": chain,
    }


@router.get("")
async def list_approvals(
    request: Request,
    search: str | None = None,
    agent_id: str | None = None,
    sort: str = "age",
    sort_dir: str = "desc",
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = None,
) -> dict:
    if sort not in SORTS:
        raise HTTPException(400, f"sort must be one of {sorted(SORTS)}")
    column, cast, key, inverted = SORTS[sort]
    if sort_dir not in ("asc", "desc"):
        raise HTTPException(400, "sort_dir must be asc or desc")
    direction = {"asc": "desc", "desc": "asc"}[sort_dir] if inverted else sort_dir

    params: list[Any] = []
    where = ["ap.status = 'pending'", "ap.expires_at > now()"]
    if search:
        params.append(search)
        where.append(f"(ap.tool ilike '%' || ${len(params)} || '%' or a.name ilike '%' || ${len(params)} || '%')")
    if agent_id:
        params.append(agent_id)
        where.append(f"ap.agent_id = ${len(params)}")
    page = KeysetPage(column, direction, cursor, cast)
    where.append(page.where(params, "ap.id"))
    params.append(limit + 1)
    rows = await request.app.state.db.fetch(
        f"{SELECT} where {' and '.join(where)} order by {page.order('ap.id')} limit ${len(params)}", *params
    )
    return {"items": [approval_item(row) for row in rows[:limit]], "nextCursor": page.next_cursor(rows, limit, key)}


@router.get("/{approval_id}")
async def get_approval(approval_id: str, request: Request) -> dict:
    row = await request.app.state.db.fetchrow(f"{SELECT} where ap.id = $1", approval_id)
    if row is None:
        raise HTTPException(404, "Unknown approval")
    return approval_item(row)


class DenyBody(BaseModel):
    reason: str | None = Field(default=None, max_length=2000)


class TemporaryBody(BaseModel):
    ttlSeconds: int | None = None


async def _resolve(request: Request, approval_id: str, mode: str, feedback: str | None = None, ttl: int | None = None) -> dict:
    try:
        await request.app.state.approvals.resolve(approval_id, request.state.operator.actor, mode, feedback, ttl)
    except ApprovalError as exc:
        raise HTTPException(exc.status_code, exc.message) from exc
    return {"id": approval_id, "decision": "deny" if mode == "deny" else "allow", "mode": mode}


@router.post("/{approval_id}/allow")
async def allow(approval_id: str, request: Request) -> dict:
    return await _resolve(request, approval_id, "once")


@router.post("/{approval_id}/deny")
async def deny(approval_id: str, request: Request, body: DenyBody | None = None) -> dict:
    return await _resolve(request, approval_id, "deny", feedback=body.reason if body else None)


@router.post("/{approval_id}/allow-temporary")
async def allow_temporary(approval_id: str, request: Request, body: TemporaryBody | None = None) -> dict:
    ttl = (body.ttlSeconds if body else None) or request.app.state.snapshot.settings.default_approval_ttl_seconds
    if not 60 <= ttl <= 86400:
        raise HTTPException(400, "ttlSeconds must be between 60 and 86400")
    return await _resolve(request, approval_id, "temporary", ttl=ttl)
