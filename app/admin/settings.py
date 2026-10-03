"""Settings + Profile API — docs/api/settings.md, docs/api/profile.md."""

from datetime import datetime, timezone
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.admin.common import iso, mutation
from app.core.ids import new_id

router = APIRouter(tags=["Settings"])

WORKSPACE_KEYS = {
    "orgName": "workspace.org_name",
    "defaultApprovalTtlSeconds": "approvals.default_ttl_seconds",
    "specialistFailClosed": "specialist.fail_closed",
    "auditRetentionDays": "audit.retention_days",
}
TTL_OPTIONS = {300, 900, 1800, 3600}
RETENTION_OPTIONS = {30, 90, 180, 365}


async def workspace(request: Request) -> dict[str, Any]:
    rows = await request.app.state.db.fetch("select key, value from proxy.settings")
    values = {row["key"]: row["value"] for row in rows}
    return {
        "orgName": values.get("workspace.org_name", "Modus Demo"),
        "defaultApprovalTtlSeconds": values.get("approvals.default_ttl_seconds", 900),
        "specialistFailClosed": values.get("specialist.fail_closed", True),
        "auditRetentionDays": values.get("audit.retention_days", 90),
        "authMode": "invite_only",
    }


@router.get("/settings/workspace")
async def get_workspace(request: Request) -> dict:
    return await workspace(request)


class WorkspacePatch(BaseModel):
    model_config = {"extra": "forbid"}

    orgName: str | None = Field(default=None, min_length=1, max_length=120)
    defaultApprovalTtlSeconds: int | None = None
    specialistFailClosed: bool | None = None
    auditRetentionDays: int | None = None
    authMode: Literal["invite_only"] | None = None


@router.patch("/settings/workspace")
async def patch_workspace(body: WorkspacePatch, request: Request) -> dict:
    if body.defaultApprovalTtlSeconds is not None and body.defaultApprovalTtlSeconds not in TTL_OPTIONS:
        raise HTTPException(400, f"defaultApprovalTtlSeconds must be one of {sorted(TTL_OPTIONS)}")
    if body.auditRetentionDays is not None and body.auditRetentionDays not in RETENTION_OPTIONS:
        raise HTTPException(400, f"auditRetentionDays must be one of {sorted(RETENTION_OPTIONS)}")
    async with mutation(request) as conn:
        for field, key in WORKSPACE_KEYS.items():
            value = getattr(body, field)
            if value is not None:
                await conn.execute(
                    """
                    insert into proxy.settings (key, value) values ($1, $2)
                    on conflict (key) do update set value = excluded.value
                    """,
                    key, value,
                )
    return await workspace(request)


# --- operatorzy -------------------------------------------------------------


def operator_item(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "email": row["email"],
        "name": row["name"],
        "role": row["role"],
        "status": row["status"],
        "invitedAt": iso(row["invited_at"]),
        "lastActiveAt": iso(row["last_active_at"]),
    }


OPERATOR_SORTS = {"name": "name", "email": "email", "role": "role", "status": "status", "invited": "invited_at", "last_active": "last_active_at"}


def _require_admin(request: Request) -> None:
    roster = request.state.operator.roster
    if roster is not None and roster["role"] not in ("owner", "admin"):
        raise HTTPException(403, "Only owners and admins can manage operators")


@router.get("/settings/operators")
async def list_operators(
    request: Request,
    sort: str = "invited",
    sort_dir: str = "desc",
    limit: int = Query(default=100, ge=1, le=200),
    cursor: str | None = None,
) -> dict:
    if sort not in OPERATOR_SORTS or sort_dir not in ("asc", "desc"):
        raise HTTPException(400, "Invalid sort")
    offset = int(cursor) if cursor and cursor.isdigit() else 0
    rows = await request.app.state.db.fetch(
        f"select * from proxy.operators order by {OPERATOR_SORTS[sort]} {sort_dir} nulls last, id limit $1 offset $2",
        limit + 1, offset,
    )
    return {
        "items": [operator_item(row) for row in rows[:limit]],
        "nextCursor": str(offset + limit) if len(rows) > limit else None,
    }


class InviteBody(BaseModel):
    email: str = Field(pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$", max_length=320)
    role: Literal["admin", "operator", "viewer"]
    name: str = ""


@router.post("/settings/operators/invite", status_code=201)
async def invite_operator(body: InviteBody, request: Request) -> dict:
    _require_admin(request)
    db = request.app.state.db
    if await db.fetchval("select exists (select 1 from proxy.operators where lower(email) = lower($1))", body.email):
        raise HTTPException(409, "Email already on roster")
    row = await db.fetchrow(
        "insert into proxy.operators (id, email, name, role) values ($1, $2, $3, $4) returning *",
        new_id("op"), body.email, body.name or body.email.split("@")[0], body.role,
    )
    return operator_item(row)


async def _operator_action(request: Request, operator_id: str, allowed_from: tuple[str, ...], target: str) -> dict:
    _require_admin(request)
    db = request.app.state.db
    row = await db.fetchrow("select * from proxy.operators where id = $1", operator_id)
    if row is None:
        raise HTTPException(404, "Unknown operator")
    if row["role"] == "owner" or row["status"] not in allowed_from:
        raise HTTPException(409, f"Cannot change operator from {row['status']}")
    row = await db.fetchrow(
        """
        update proxy.operators set status = $2, invited_at = case when $2 = 'invited' then now() else invited_at end
         where id = $1 returning *
        """,
        operator_id, target,
    )
    return operator_item(row)


@router.post("/settings/operators/{operator_id}/resend")
async def resend_invite(operator_id: str, request: Request) -> dict:
    return await _operator_action(request, operator_id, ("invited",), "invited")


@router.post("/settings/operators/{operator_id}/disable")
async def disable_operator(operator_id: str, request: Request) -> dict:
    return await _operator_action(request, operator_id, ("active", "invited"), "disabled")


@router.post("/settings/operators/{operator_id}/enable")
async def enable_operator(operator_id: str, request: Request) -> dict:
    return await _operator_action(request, operator_id, ("disabled",), "active")


@router.get("/me")
async def me(request: Request) -> dict:
    operator = request.state.operator
    claims = operator.claims
    metadata = claims.get("user_metadata") or {}
    roster = None
    if operator.roster is not None:
        row = await request.app.state.db.fetchrow("select * from proxy.operators where id = $1", operator.roster["id"])
        roster = operator_item(row)
    ws = await workspace(request)
    return {
        "userId": operator.user_id,
        "email": operator.email,
        "name": (roster or {}).get("name") or metadata.get("full_name") or metadata.get("name") or operator.email,
        "avatarUrl": metadata.get("avatar_url"),
        "authProvider": (claims.get("app_metadata") or {}).get("provider", "email"),
        "lastSignInAt": None,
        "sessionExpiresAt": _exp(claims),
        "operator": roster,
        "workspace": {"orgName": ws["orgName"], "authMode": ws["authMode"]},
    }


def _exp(claims: dict) -> str | None:
    exp = claims.get("exp")
    return iso(datetime.fromtimestamp(exp, timezone.utc)) if isinstance(exp, (int, float)) else None
