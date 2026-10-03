"""Roles API — docs/api/roles.md. Rola = szablon uprawnień (apps × tools), deny-by-default.

Uprawnienia agenta w snapshocie = granty aktywnej roli ∪ `agent_permissions` (bezpośrednie).
"""

import re
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.admin.common import iso, mutation

router = APIRouter(prefix="/roles", tags=["Roles"])

ROLE_ID = re.compile(r"^[a-z0-9][a-z0-9_-]{1,62}$")
SORTS = {"name", "status", "agents", "grants", "updated"}


async def _matrix(conn, role_id: str) -> list[dict[str, Any]]:
    apps = await conn.fetch("select id, name from proxy.apps where protocol in ('rest', 'mcp') order by id")
    tools = await conn.fetch(
        """
        select t.id, t.app_id, t.name, exists (select 1 from proxy.role_grants g where g.role_id = $1 and g.tool_id = t.id) as granted
          from proxy.tools t where t.enabled order by t.app_id, t.name
        """,
        role_id,
    )
    wide = {row["app_id"] for row in await conn.fetch("select app_id from proxy.role_app_grants where role_id = $1", role_id)}
    grants = []
    for app in apps:
        app_tools = {f"{row['app_id']}.{row['name']}": row["granted"] or app["id"] in wide for row in tools if row["app_id"] == app["id"]}
        grants.append({"serverId": app["id"], "serverName": app["name"], "serverWide": app["id"] in wide, "tools": app_tools})
    return grants


async def load_role(request: Request, role_id: str) -> dict[str, Any]:
    db = request.app.state.db
    row = await db.fetchrow("select * from proxy.roles where id = $1", role_id)
    if row is None:
        raise HTTPException(404, "Unknown role")
    async with db.acquire() as conn:
        grants = await _matrix(conn, role_id)
    agents = await db.fetch("select id, name, status from proxy.agents where role_id = $1 order by name", role_id)
    effective = [
        {"serverId": grant["serverId"], "serverName": grant["serverName"], "tool": tool,
         "via": "server" if grant["serverWide"] else "tool"}
        for grant in grants for tool, granted in grant["tools"].items() if granted
    ]
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "status": row["status"],
        "grants": grants,
        "createdAt": iso(row["created_at"]),
        "updatedAt": iso(row["updated_at"]),
        "assignedAgents": [dict(agent) for agent in agents],
        "effectiveTools": effective,
    }


@router.get("")
async def list_roles(
    request: Request,
    search: str | None = None,
    status: str | None = None,
    sort: str = "updated",
    sort_dir: str = "desc",
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = None,
) -> dict:
    if sort not in SORTS:
        raise HTTPException(400, f"sort must be one of {sorted(SORTS)}")
    rows = await request.app.state.db.fetch(
        """
        select r.*,
               coalesce((select array_agg(a.id order by a.id) from proxy.agents a where a.role_id = r.id), '{}') as agent_ids,
               (select count(*) from proxy.tools t
                 where t.enabled and (exists (select 1 from proxy.role_grants g where g.role_id = r.id and g.tool_id = t.id)
                                   or exists (select 1 from proxy.role_app_grants g where g.role_id = r.id and g.app_id = t.app_id))
               ) as granted
          from proxy.roles r
         where ($1::text is null or r.name ilike '%' || $1 || '%' or r.description ilike '%' || $1 || '%')
           and ($2::text is null or r.status = $2)
        """,
        search, status,
    )
    keys = {
        "name": lambda row: row["name"],
        "status": lambda row: row["status"],
        "agents": lambda row: len(row["agent_ids"]),
        "grants": lambda row: row["granted"],
        "updated": lambda row: row["updated_at"],
    }
    rows = sorted(rows, key=keys[sort], reverse=sort_dir == "desc")
    offset = int(cursor) if cursor and cursor.isdigit() else 0
    page = rows[offset : offset + limit]
    names = {row["id"]: row["name"] for row in await request.app.state.db.fetch("select id, name from proxy.agents")}
    return {
        "items": [
            {
                "id": row["id"],
                "name": row["name"],
                "description": row["description"],
                "status": row["status"],
                "grantedToolCount": row["granted"],
                "assignedAgentIds": list(row["agent_ids"]),
                "assignedAgents": [{"id": agent_id, "name": names.get(agent_id, agent_id)} for agent_id in row["agent_ids"]],
                "createdAt": iso(row["created_at"]),
                "updatedAt": iso(row["updated_at"]),
            }
            for row in page
        ],
        "nextCursor": str(offset + limit) if offset + limit < len(rows) else None,
    }


class Grant(BaseModel):
    serverId: str
    serverWide: bool = False
    tools: dict[str, bool] = {}


class RoleCreate(BaseModel):
    id: str | None = None
    name: str = Field(min_length=1, max_length=120)
    description: str = ""
    grants: list[Grant] = []


class RolePatch(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=120)
    description: str | None = None
    grants: list[Grant] | None = None


async def _apply_grants(conn, role_id: str, grants: list[Grant]) -> None:
    for grant in grants:
        app = await conn.fetchval("select id from proxy.apps where id = $1", grant.serverId)
        if app is None:
            raise HTTPException(400, f"Unknown server {grant.serverId}")
        tools = {row["name"]: row["id"] for row in await conn.fetch("select id, name from proxy.tools where app_id = $1", app)}
        await conn.execute("delete from proxy.role_app_grants where role_id = $1 and app_id = $2", role_id, app)
        await conn.execute(
            "delete from proxy.role_grants g using proxy.tools t where g.tool_id = t.id and g.role_id = $1 and t.app_id = $2",
            role_id, app,
        )
        selected = []
        for name, granted in grant.tools.items():
            bare = name.removeprefix(f"{app}.")
            if bare not in tools:
                raise HTTPException(400, f"Unknown tool {name} on {app}")
            if granted:
                selected.append(tools[bare])
        if grant.serverWide or (tools and len(selected) == len(tools) and len(grant.tools) == len(tools)):
            await conn.execute("insert into proxy.role_app_grants (role_id, app_id) values ($1, $2)", role_id, app)
        else:
            for tool_id in selected:
                await conn.execute("insert into proxy.role_grants (role_id, tool_id) values ($1, $2)", role_id, tool_id)


@router.post("", status_code=201)
async def create_role(body: RoleCreate, request: Request) -> dict:
    role_id = body.id or "role_" + re.sub(r"[^a-z0-9]+", "_", body.name.lower()).strip("_")
    if not ROLE_ID.match(role_id):
        raise HTTPException(400, "Invalid role id")
    async with mutation(request) as conn:
        if await conn.fetchval("select exists (select 1 from proxy.roles where id = $1)", role_id):
            raise HTTPException(409, "Role already exists")
        await conn.execute(
            "insert into proxy.roles (id, name, description) values ($1, $2, $3)", role_id, body.name, body.description
        )
        await _apply_grants(conn, role_id, body.grants)
    return await load_role(request, role_id)


@router.get("/{role_id}")
async def get_role(role_id: str, request: Request) -> dict:
    return await load_role(request, role_id)


@router.patch("/{role_id}")
async def patch_role(role_id: str, body: RolePatch, request: Request) -> dict:
    async with mutation(request) as conn:
        status = await conn.fetchval("select status from proxy.roles where id = $1 for update", role_id)
        if status is None:
            raise HTTPException(404, "Unknown role")
        if status == "archived" and body.grants is not None:
            raise HTTPException(409, "Archived role grants cannot be edited")
        await conn.execute(
            "update proxy.roles set name = coalesce($2, name), description = coalesce($3, description), updated_at = now() where id = $1",
            role_id, body.name, body.description,
        )
        if body.grants is not None:
            await _apply_grants(conn, role_id, body.grants)
    return await load_role(request, role_id)


async def _transition(request: Request, role_id: str, allowed: tuple[str, ...], target: str) -> dict:
    async with mutation(request) as conn:
        status = await conn.fetchval("select status from proxy.roles where id = $1 for update", role_id)
        if status is None:
            raise HTTPException(404, "Unknown role")
        if status not in allowed:
            raise HTTPException(409, f"Cannot move role from {status} to {target}")
        await conn.execute("update proxy.roles set status = $2 where id = $1", role_id, target)
    return await load_role(request, role_id)


@router.post("/{role_id}/publish")
async def publish_role(role_id: str, request: Request) -> dict:
    return await _transition(request, role_id, ("draft",), "active")


@router.post("/{role_id}/archive")
async def archive_role(role_id: str, request: Request) -> dict:
    return await _transition(request, role_id, ("active", "draft"), "archived")
