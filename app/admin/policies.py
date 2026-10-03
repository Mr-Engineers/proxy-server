"""Pakiety polityk (D15/D17): podgląd i edycja z walidacją przed zapisem.

Zapis przechodzi przez tę samą kompilację co snapshot — błędny pakiet lub override, który luzuje
parametry, kończy się 400 i nie trafia do bazy.
"""

from typing import Any

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel

from app.admin.common import iso, mutation
from app.policy.cedar import PolicyCompileError, compile_pack

router = APIRouter(prefix="/policies", tags=["Policies"])


async def _load(conn, app_id: str) -> tuple[Any, dict[str, dict]]:
    pack = await conn.fetchrow("select * from proxy.policy_packs where app_id = $1", app_id)
    if pack is None:
        raise HTTPException(404, "Unknown policy pack")
    overrides = {
        row["agent_id"]: row["params"]
        for row in await conn.fetch("select agent_id, params from proxy.policy_overrides where app_id = $1", app_id)
    }
    return pack, overrides


def _compile(app_id: str, policies: str, schema: str, params: dict, params_schema: dict, overrides: dict) -> Any:
    try:
        return compile_pack(app_id, policies, schema, params, params_schema, overrides)
    except PolicyCompileError as exc:
        raise HTTPException(400, f"Invalid policy pack: {exc}") from exc


def pack_item(pack: Any, overrides: dict[str, dict]) -> dict[str, Any]:
    compiled = _compile(pack["app_id"], pack["cedar_policies"], pack["cedar_schema"], pack["params"], pack["params_schema"], overrides)
    return {
        "appId": pack["app_id"],
        "cedarPolicies": pack["cedar_policies"],
        "cedarSchema": pack["cedar_schema"],
        "params": pack["params"],
        "paramsSchema": pack["params_schema"],
        "overrides": overrides,
        "rules": [note.model_dump() for note in compiled.annotations.values()],
        "effectiveParams": compiled.agent_params,
        "updatedAt": iso(pack["updated_at"]),
    }


@router.get("")
async def list_packs(request: Request) -> dict:
    async with request.app.state.db.acquire() as conn:
        ids = [row["app_id"] for row in await conn.fetch("select app_id from proxy.policy_packs order by app_id")]
        items = []
        for app_id in ids:
            pack, overrides = await _load(conn, app_id)
            items.append(pack_item(pack, overrides))
    return {"items": items}


@router.get("/{app_id}")
async def get_pack(app_id: str, request: Request) -> dict:
    async with request.app.state.db.acquire() as conn:
        pack, overrides = await _load(conn, app_id)
    return pack_item(pack, overrides)


class PackBody(BaseModel):
    cedarPolicies: str | None = None
    cedarSchema: str | None = None
    params: dict[str, Any] | None = None
    paramsSchema: dict[str, Any] | None = None


@router.put("/{app_id}")
async def put_pack(app_id: str, body: PackBody, request: Request) -> dict:
    async with mutation(request) as conn:
        if not await conn.fetchval("select exists (select 1 from proxy.apps where id = $1)", app_id):
            raise HTTPException(404, "Unknown app")
        existing = await conn.fetchrow("select * from proxy.policy_packs where app_id = $1", app_id)
        overrides = {
            row["agent_id"]: row["params"]
            for row in await conn.fetch("select agent_id, params from proxy.policy_overrides where app_id = $1", app_id)
        }
        policies = body.cedarPolicies if body.cedarPolicies is not None else (existing["cedar_policies"] if existing else "")
        schema = body.cedarSchema if body.cedarSchema is not None else (existing["cedar_schema"] if existing else "")
        params = body.params if body.params is not None else (existing["params"] if existing else {})
        params_schema = body.paramsSchema if body.paramsSchema is not None else (existing["params_schema"] if existing else {})
        _compile(app_id, policies, schema, params, params_schema, overrides)
        await conn.execute(
            """
            insert into proxy.policy_packs (app_id, cedar_policies, cedar_schema, params, params_schema)
            values ($1, $2, $3, $4, $5)
            on conflict (app_id) do update set cedar_policies = excluded.cedar_policies, cedar_schema = excluded.cedar_schema,
                                               params = excluded.params, params_schema = excluded.params_schema
            """,
            app_id, policies, schema, params, params_schema,
        )
    return await get_pack(app_id, request)


class OverrideBody(BaseModel):
    params: dict[str, Any]


@router.put("/{app_id}/overrides/{agent_id}")
async def put_override(app_id: str, agent_id: str, body: OverrideBody, request: Request) -> dict:
    async with mutation(request) as conn:
        pack, overrides = await _load(conn, app_id)
        if not await conn.fetchval("select exists (select 1 from proxy.agents where id = $1)", agent_id):
            raise HTTPException(404, "Unknown agent")
        overrides[agent_id] = body.params
        _compile(app_id, pack["cedar_policies"], pack["cedar_schema"], pack["params"], pack["params_schema"], overrides)
        await conn.execute(
            """
            insert into proxy.policy_overrides (app_id, agent_id, params) values ($1, $2, $3)
            on conflict (app_id, agent_id) do update set params = excluded.params
            """,
            app_id, agent_id, body.params,
        )
    return await get_pack(app_id, request)


@router.delete("/{app_id}/overrides/{agent_id}")
async def delete_override(app_id: str, agent_id: str, request: Request) -> dict:
    async with mutation(request) as conn:
        await conn.execute("delete from proxy.policy_overrides where app_id = $1 and agent_id = $2", app_id, agent_id)
    return await get_pack(app_id, request)
