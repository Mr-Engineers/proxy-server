"""MCP registry API — docs/api/mcp.md (read-only) + włączanie/wyłączanie aplikacji i tooli.

„Serwer” w UI = aplikacja z `proxy.apps` (REST lub MCP); toole = `proxy.tools`.
Discover / hosted / OAuth → 501 (poza MVP).
"""

from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel

from app.admin.common import iso, mutation

router = APIRouter(prefix="/mcp", tags=["MCP"])

HEALTH_SQL = """
select action_status from proxy.decisions
 where app_id = $1 and action_status in ('executed', 'upstream_error') and created_at > now() - interval '1 hour'
 order by created_at desc limit 20
"""


async def _health(db, app_id: str, enabled: bool) -> str:
    if not enabled:
        return "down"
    statuses = [row["action_status"] for row in await db.fetch(HEALTH_SQL, app_id)]
    if not statuses:
        return "pending"
    errors = statuses.count("upstream_error") / len(statuses)
    if errors >= 0.5:
        return "down"
    return "degraded" if errors > 0 else "healthy"


async def server_item(request: Request, app: Any) -> dict[str, Any]:
    db = request.app.state.db
    tools = await db.fetch(
        "select name, kind, http_method, http_path, mcp_tool, description, enabled from proxy.tools where app_id = $1 order by name",
        app["id"],
    )
    enabled_tools = [f"{app['id']}.{tool['name']}" for tool in tools if tool["enabled"]]
    return {
        "id": app["id"],
        "name": app["name"],
        "kind": "remote",
        "protocol": app["protocol"],
        "url": app["upstream_url"],
        "health": await _health(db, app["id"], app["enabled"]),
        "toolCount": len(enabled_tools),
        "tools": enabled_tools,
        "toolDetails": [
            {
                "name": f"{app['id']}.{tool['name']}",
                "kind": tool["kind"],
                "method": tool["http_method"],
                "path": tool["http_path"] or tool["mcp_tool"],
                "description": tool["description"],
                "enabled": tool["enabled"],
            }
            for tool in tools
        ],
        "lastSyncAt": iso(app["updated_at"]),
        "requiresAuth": False,
        "description": f"{app['protocol'].upper()} upstream {app['upstream_url']}",
        "enabled": app["enabled"],
        "hasPolicyPack": app["has_pack"],
    }


SELECT = """
select a.*, exists (select 1 from proxy.policy_packs p where p.app_id = a.id) as has_pack
  from proxy.apps a where a.protocol in ('rest', 'mcp')
"""


@router.get("")
async def list_servers(
    request: Request,
    kind: str = "all",
    health: str | None = None,
    search: str | None = None,
    limit: int = Query(default=100, ge=1, le=200),
    cursor: str | None = None,
) -> dict:
    if kind == "hosted":
        return {"items": [], "nextCursor": None}
    rows = await request.app.state.db.fetch(
        f"{SELECT} and ($1::text is null or a.name ilike '%' || $1 || '%' or a.upstream_url ilike '%' || $1 || '%') order by a.id",
        search,
    )
    items = [await server_item(request, row) for row in rows]
    if health:
        items = [item for item in items if item["health"] == health]
    offset = int(cursor) if cursor and cursor.isdigit() else 0
    return {"items": items[offset : offset + limit], "nextCursor": str(offset + limit) if offset + limit < len(items) else None}


@router.get("/hosted/source-options")
async def source_options() -> list[dict[str, str]]:
    return [
        {"id": "rest", "label": "HTTP / REST API", "blurb": "Map REST routes to tools", "urlPlaceholder": "https://api.example.com"},
        {"id": "openapi", "label": "OpenAPI / Swagger", "blurb": "Import routes from a spec", "urlPlaceholder": "https://api.example.com/openapi.json"},
        {"id": "database", "label": "Database", "blurb": "Not available yet", "urlPlaceholder": "postgresql://..."},
        {"id": "package", "label": "MCP package", "blurb": "Not available yet", "urlPlaceholder": "@scope/mcp-server"},
        {"id": "template", "label": "Template", "blurb": "Not available yet", "urlPlaceholder": ""},
    ]


@router.post("/remote/discover")
@router.post("/remote")
@router.post("/hosted/discover")
@router.post("/hosted")
async def not_implemented() -> None:
    raise HTTPException(501, "MCP discovery and hosted adapters are not implemented yet")


@router.get("/{server_id}")
async def get_server(server_id: str, request: Request) -> dict:
    row = await request.app.state.db.fetchrow(f"{SELECT} and a.id = $1", server_id)
    if row is None:
        raise HTTPException(404, "Unknown server")
    return await server_item(request, row)


class ServerPatch(BaseModel):
    enabled: bool | None = None
    name: str | None = None


@router.patch("/{server_id}")
async def patch_server(server_id: str, body: ServerPatch, request: Request) -> dict:
    async with mutation(request) as conn:
        updated = await conn.fetchval(
            "update proxy.apps set enabled = coalesce($2, enabled), name = coalesce($3, name) where id = $1 returning id",
            server_id, body.enabled, body.name,
        )
    if updated is None:
        raise HTTPException(404, "Unknown server")
    return await get_server(server_id, request)


class ToolPatch(BaseModel):
    enabled: bool | None = None
    kind: Literal["read", "write"] | None = None
    scanMode: Literal["all_strings", "selected", "none"] | None = None


@router.patch("/{server_id}/tools/{tool}")
async def patch_tool(server_id: str, tool: str, body: ToolPatch, request: Request) -> dict:
    async with mutation(request) as conn:
        updated = await conn.fetchval(
            """
            update proxy.tools set enabled = coalesce($3, enabled), kind = coalesce($4, kind),
                                   scan_mode = coalesce($5, scan_mode)
             where app_id = $1 and name = $2 returning id
            """,
            server_id, tool.removeprefix(f"{server_id}."), body.enabled, body.kind, body.scanMode,
        )
    if updated is None:
        raise HTTPException(404, "Unknown tool")
    return await get_server(server_id, request)


@router.delete("/{server_id}")
async def delete_server(server_id: str) -> None:
    raise HTTPException(501, "Removing servers from the catalog is not implemented yet; disable it instead")
