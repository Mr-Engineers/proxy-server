"""Agents API — docs/api/agents.md: agenci, klucze, reguły (P5), kwoty (P6), posture, overview."""

import re
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, Field

from app.admin.common import KeysetPage, iso, multi, mutation
from app.admin.overview import quota_usage, resolve_window, window_metrics
from app.admin.roles import load_role
from app.auth.agent import generate_key
from app.config.models import RuleConfig
from app.core.ids import new_id
from app.pipeline.models import Action
from app.pipeline.rules import OUTCOMES, RuleError, evaluate_rules, validate_condition
from app.policy.cedar import CedarPolicyEngine
from app.policy.facts import compute_facts

router = APIRouter(tags=["Agents"])

AGENT_ID = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}$")

SELECT = """
select a.id, a.name, a.status, a.mandate, a.llm_models, a.limits, a.role_id, r.name as role_name,
       a.created_at, act.last_seen_at, coalesce(act.last_seen_at, 'epoch'::timestamptz) as last_seen_sort,
       (select k.hint from proxy.agent_keys k where k.agent_id = a.id
         order by (k.revoked_at is null) desc, k.created_at desc limit 1) as key_hint,
       coalesce((select array_agg(distinct t.app_id order by t.app_id)
                   from proxy.agent_permissions p join proxy.tools t on t.id = p.tool_id where p.agent_id = a.id), '{}')
       || coalesce((select array_agg(distinct t.app_id order by t.app_id)
                   from proxy.role_grants g join proxy.tools t on t.id = g.tool_id where g.role_id = a.role_id), '{}')
       || coalesce((select array_agg(distinct g.app_id order by g.app_id)
                   from proxy.role_app_grants g where g.role_id = a.role_id), '{}') as app_ids
  from proxy.agents a
  left join proxy.roles r on r.id = a.role_id
  left join proxy.agent_activity act on act.agent_id = a.id
"""

SORTS = {
    "name": ("a.name", "text", "name"),
    "role": ("coalesce(r.name, '')", "text", "role_name"),
    "status": ("a.status", "text", "status"),
    "api_key": ("coalesce((select k.hint from proxy.agent_keys k where k.agent_id = a.id order by k.created_at desc limit 1), '')", "text", "key_hint"),
    "last_seen": ("coalesce(act.last_seen_at, 'epoch'::timestamptz)", "timestamptz", "last_seen_sort"),
}


def agent_item(row: Any) -> dict[str, Any]:
    limits = row["limits"] or {}
    return {
        "id": row["id"],
        "name": row["name"],
        "roleId": row["role_id"],
        "roleName": row["role_name"],
        "status": row["status"],
        "apiKeyHint": row["key_hint"] or "",
        "mcpServerIds": sorted(set(row["app_ids"] or [])),
        "createdAt": iso(row["created_at"]),
        "lastSeenAt": iso(row["last_seen_at"]),
        "mandate": row["mandate"],
        "llmModels": list(row["llm_models"] or []),
        "rateLimitOverride": limits.get("requests_per_minute"),
        "limits": limits,
    }


async def load_agent(request: Request, agent_id: str) -> dict[str, Any]:
    row = await request.app.state.db.fetchrow(f"{SELECT} where a.id = $1", agent_id)
    if row is None:
        raise HTTPException(404, "Unknown agent")
    return agent_item(row)


async def _ensure_agent(conn, agent_id: str) -> None:
    if not await conn.fetchval("select exists (select 1 from proxy.agents where id = $1)", agent_id):
        raise HTTPException(404, "Unknown agent")


async def _check_role(conn, role_id: str | None) -> None:
    if role_id is None:
        return
    status = await conn.fetchval("select status from proxy.roles where id = $1", role_id)
    if status is None:
        raise HTTPException(400, "Unknown role")
    if status == "archived":
        raise HTTPException(409, "Role is archived")


# --- agenci -----------------------------------------------------------------


@router.get("/agents")
async def list_agents(
    request: Request,
    search: str | None = None,
    status: list[str] | None = Query(default=None),
    role_id: str | None = None,
    sort: str = "last_seen",
    sort_dir: str = "desc",
    limit: int = Query(default=50, ge=1, le=200),
    cursor: str | None = None,
) -> dict:
    if sort not in SORTS:
        raise HTTPException(400, f"sort must be one of {sorted(SORTS)}")
    column, cast, key = SORTS[sort]
    params: list[Any] = []
    where = ["true"]
    if search:
        params.append(search)
        n = len(params)
        where.append(f"(a.name ilike '%' || ${n} || '%' or a.id ilike '%' || ${n} || '%' or r.name ilike '%' || ${n} || '%')")
    statuses = multi(status)
    if statuses:
        params.append(statuses)
        where.append(f"a.status = any(${len(params)}::text[])")
    if role_id:
        params.append(role_id)
        where.append(f"a.role_id = ${len(params)}")
    page = KeysetPage(column, sort_dir, cursor, cast)
    where.append(page.where(params, "a.id"))
    params.append(limit + 1)
    rows = await request.app.state.db.fetch(
        f"{SELECT} where {' and '.join(where)} order by {page.order('a.id')} limit ${len(params)}", *params
    )
    return {"items": [agent_item(row) for row in rows[:limit]], "nextCursor": page.next_cursor(rows, limit, key)}


class AgentCreate(BaseModel):
    id: str
    name: str = Field(min_length=1, max_length=200)
    mandate: str = Field(min_length=1, max_length=4000)
    roleId: str | None = None
    llmModels: list[str] = []
    limits: dict[str, int] = {}


@router.post("/agents", status_code=201)
async def create_agent(body: AgentCreate, request: Request) -> dict:
    if not AGENT_ID.match(body.id):
        raise HTTPException(400, "id must match ^[a-z0-9][a-z0-9-]{1,62}$")
    key = generate_key()
    async with mutation(request) as conn:
        if await conn.fetchval("select exists (select 1 from proxy.agents where id = $1)", body.id):
            raise HTTPException(409, "Agent already exists")
        await _check_role(conn, body.roleId)
        await conn.execute(
            "insert into proxy.agents (id, name, mandate, llm_models, limits, role_id) values ($1, $2, $3, $4, $5, $6)",
            body.id, body.name, body.mandate, body.llmModels, body.limits, body.roleId,
        )
        await conn.execute(
            "insert into proxy.agent_keys (id, agent_id, sha256, hint) values ($1, $2, $3, $4)",
            key.key_id, body.id, key.sha256, key.hint,
        )
    return {**await load_agent(request, body.id), "apiKey": key.token}


@router.get("/agents/{agent_id}")
async def get_agent(agent_id: str, request: Request) -> dict:
    return await load_agent(request, agent_id)


class AgentPatch(BaseModel):
    model_config = {"extra": "forbid"}

    roleId: str | None = None
    name: str | None = Field(default=None, min_length=1, max_length=200)
    status: Literal["active", "disabled"] | None = None
    mandate: str | None = Field(default=None, min_length=1, max_length=4000)
    llmModels: list[str] | None = None
    rateLimitOverride: int | None = Field(default=None, ge=1)


@router.patch("/agents/{agent_id}")
async def patch_agent(agent_id: str, body: AgentPatch, request: Request) -> dict:
    fields = body.model_fields_set
    async with mutation(request) as conn:
        current = await conn.fetchrow("select status, limits from proxy.agents where id = $1 for update", agent_id)
        if current is None:
            raise HTTPException(404, "Unknown agent")
        if "status" in fields and current["status"] == "revoked":
            raise HTTPException(409, "Revoked agent needs a new key before it can be re-enabled")
        if "roleId" in fields:
            await _check_role(conn, body.roleId)
            await conn.execute("update proxy.agents set role_id = $2 where id = $1", agent_id, body.roleId)
        for field, column in (("name", "name"), ("status", "status"), ("mandate", "mandate"), ("llmModels", "llm_models")):
            if field in fields and getattr(body, field) is not None:
                await conn.execute(f"update proxy.agents set {column} = $2 where id = $1", agent_id, getattr(body, field))
        if "rateLimitOverride" in fields:
            limits = dict(current["limits"] or {})
            if body.rateLimitOverride is None:
                limits.pop("requests_per_minute", None)
            else:
                limits["requests_per_minute"] = body.rateLimitOverride
            await conn.execute("update proxy.agents set limits = $2 where id = $1", agent_id, limits)
    return await load_agent(request, agent_id)


@router.post("/agents/{agent_id}/revoke")
async def revoke_agent(agent_id: str, request: Request) -> dict:
    async with mutation(request) as conn:
        await _ensure_agent(conn, agent_id)
        await conn.execute("update proxy.agent_keys set revoked_at = now() where agent_id = $1 and revoked_at is null", agent_id)
        await conn.execute(
            "update proxy.agent_keys set hint = regexp_replace(hint, '^(ak_)', 'revoked_') where agent_id = $1 and hint like 'ak\\_%'",
            agent_id,
        )
        await conn.execute("update proxy.agents set status = 'revoked' where id = $1", agent_id)
    return await load_agent(request, agent_id)


@router.post("/agents/{agent_id}/keys", status_code=201)
async def create_key(agent_id: str, request: Request) -> dict:
    """Nowy klucz (pokazywany raz). Stare klucze zostają aktywne do revoke — rotacja bez przestoju."""
    key = generate_key()
    async with mutation(request) as conn:
        await _ensure_agent(conn, agent_id)
        await conn.execute(
            "insert into proxy.agent_keys (id, agent_id, sha256, hint) values ($1, $2, $3, $4)",
            key.key_id, agent_id, key.sha256, key.hint,
        )
        await conn.execute("update proxy.agents set status = 'active' where id = $1 and status = 'revoked'", agent_id)
    return {**await load_agent(request, agent_id), "apiKey": key.token}


@router.get("/agents/{agent_id}/overview")
async def agent_overview(
    agent_id: str,
    request: Request,
    range_: str | None = Query(default=None, alias="range"),
    from_: str | None = Query(default=None, alias="from"),
    to: str | None = None,
    tz: str | None = None,
    bucket: str | None = None,
    top_limit: int = Query(default=5, ge=1, le=50),
) -> dict:
    await load_agent(request, agent_id)
    snapshot = request.app.state.snapshot
    db = request.app.state.db
    window = resolve_window(range_, from_, to, tz or snapshot.settings.timezone, bucket)
    metrics = await window_metrics(db, window, agent_id, top_limit)
    split = metrics.pop("_split")
    clear, flagged = split.get("allow", 0), split.get("escalate", 0) + split.get("deny", 0)
    quotas = await quota_usage(db, snapshot, agent_id)
    daily = {quota.id for quota in snapshot.quotas.get(agent_id, ()) if quota.window == "1d"}
    budget = next((quota for quota in quotas if quota["id"] in daily), quotas[0] if quotas else None)
    return {
        "window": window.as_json(),
        **metrics,
        "pendingApprovals": await db.fetchval(
            "select count(*) from proxy.approvals where agent_id = $1 and status = 'pending' and expires_at > now()", agent_id
        ),
        "clear": clear,
        "flagged": flagged,
        "clearToday": clear,
        "cautionToday": flagged,
        "budget": budget,
    }


@router.get("/agents/{agent_id}/posture")
async def agent_posture(agent_id: str, request: Request) -> dict:
    agent_row = await load_agent(request, agent_id)
    db = request.app.state.db
    snapshot = request.app.state.snapshot
    role = None
    server_wide: set[str] = set()
    if agent_row["roleId"]:
        role = await load_role(request, agent_row["roleId"])
        server_wide = {grant["serverId"] for grant in role["grants"] if grant["serverWide"]}
    agent = snapshot.agents.get(agent_id)
    permissions = agent.permissions if agent else frozenset()
    apps = {row["id"]: row["name"] for row in await db.fetch("select id, name from proxy.apps where protocol in ('rest', 'mcp')")}
    callable_ = [
        {"serverId": tool.partition(".")[0], "serverName": apps.get(tool.partition(".")[0], tool.partition(".")[0]),
         "tool": tool, "via": "server" if tool.partition(".")[0] in server_wide else "tool"}
        for tool in sorted(permissions)
    ]
    granted_apps = {item["serverId"] for item in callable_}
    return {
        "role": role,
        "callable": callable_,
        "unreachable": [],
        "attachedWithoutGrants": sorted(set(apps) - granted_apps),
    }


@router.api_route("/agents/{agent_id}/mcp/{server_id}", methods=["POST", "DELETE"])
@router.post("/agents/{agent_id}/mcp/{server_id}/auth")
async def mcp_attach(agent_id: str, server_id: str) -> dict:
    raise HTTPException(501, "MCP attach is not implemented yet; access is granted through roles")


# --- reguły (P5) ------------------------------------------------------------


class RuleBody(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    tool: str = Field(min_length=1, max_length=200)
    when: dict[str, Any] = {"combinator": "and", "children": []}
    then: Literal["allow", "deny", "needs_ai"]
    enabled: bool = True
    position: int | None = None


def rule_item(row: Any) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "agentId": row["agent_id"],
        "tool": row["tool"],
        "when": row["condition"],
        "then": row["outcome"],
        "enabled": row["enabled"],
        "position": row["position"],
        "updatedAt": iso(row["updated_at"]),
    }


def _validate_rule(body: RuleBody) -> None:
    if body.then not in OUTCOMES:
        raise HTTPException(400, "then must be allow | deny | needs_ai")
    try:
        validate_condition(body.when)
    except RuleError as exc:
        raise HTTPException(400, f"Invalid condition tree: {exc}") from exc


@router.get("/agents/{agent_id}/rules")
async def list_rules(agent_id: str, request: Request) -> dict:
    await load_agent(request, agent_id)
    rows = await request.app.state.db.fetch(
        "select * from proxy.agent_rules where agent_id = $1 order by position, created_at", agent_id
    )
    return {"items": [rule_item(row) for row in rows]}


@router.post("/agents/{agent_id}/rules", status_code=201)
async def create_rule(agent_id: str, body: RuleBody, request: Request) -> dict:
    _validate_rule(body)
    async with mutation(request) as conn:
        await _ensure_agent(conn, agent_id)
        position = body.position
        if position is None:
            position = await conn.fetchval(
                "select coalesce(max(position), -1) + 1 from proxy.agent_rules where agent_id = $1", agent_id
            )
        row = await conn.fetchrow(
            """
            insert into proxy.agent_rules (id, agent_id, name, tool, condition, outcome, enabled, position)
            values ($1, $2, $3, $4, $5, $6, $7, $8) returning *
            """,
            new_id("rule"), agent_id, body.name, body.tool, body.when, body.then, body.enabled, position,
        )
    return rule_item(row)


@router.put("/agents/{agent_id}/rules/{rule_id}")
async def update_rule(agent_id: str, rule_id: str, body: RuleBody, request: Request) -> dict:
    _validate_rule(body)
    async with mutation(request) as conn:
        row = await conn.fetchrow(
            """
            update proxy.agent_rules
               set name = $3, tool = $4, condition = $5, outcome = $6, enabled = $7, position = coalesce($8, position)
             where id = $1 and agent_id = $2 returning *
            """,
            rule_id, agent_id, body.name, body.tool, body.when, body.then, body.enabled, body.position,
        )
    if row is None:
        raise HTTPException(404, "Unknown rule")
    return rule_item(row)


@router.delete("/agents/{agent_id}/rules/{rule_id}", status_code=204)
async def delete_rule(agent_id: str, rule_id: str, request: Request) -> None:
    async with mutation(request) as conn:
        deleted = await conn.fetchval(
            "delete from proxy.agent_rules where id = $1 and agent_id = $2 returning id", rule_id, agent_id
        )
    if deleted is None:
        raise HTTPException(404, "Unknown rule")


FACT_FIELDS = [
    ("order_value_minor", "number"), ("qty_ratio_pct", "number"), ("quantity", "number"), ("qty_needed", "number"),
    ("offer_seen_in_session", "enum"), ("sku_needed", "enum"), ("merchant_known", "enum"), ("currency", "text"),
]


def _field_type(spec: dict[str, Any]) -> tuple[str, list | None]:
    if "enum" in spec:
        return "enum", spec["enum"]
    if spec.get("type") in ("number", "integer"):
        return "number", None
    if spec.get("type") == "boolean":
        return "enum", [True, False]
    return "text", None


@router.get("/agents/{agent_id}/rules/meta")
async def rules_meta(agent_id: str, request: Request) -> dict:
    await load_agent(request, agent_id)
    snapshot = request.app.state.snapshot
    tools_by_app = []
    fields: dict[str, dict[str, Any]] = {}
    for app_id, tools in sorted(snapshot.tools.items()):
        app = snapshot.apps[app_id]
        tools_by_app.append({"serverId": app_id, "serverName": app.name, "tools": [tool.qualified for tool in tools]})
        for tool in tools:
            properties = (tool.input_schema or {}).get("properties", {})
            for name, spec in properties.items():
                kind, values = _field_type(spec if isinstance(spec, dict) else {})
                entry = fields.setdefault(name, {"id": name, "label": name, "type": kind, "tools": []})
                if values:
                    entry["values"] = values
                entry["tools"].append(tool.qualified)
            for name in tool.args:
                entry = fields.setdefault(name, {"id": name, "label": name, "type": "text", "tools": []})
                if tool.qualified not in entry["tools"]:
                    entry["tools"].append(tool.qualified)
    for name, kind in FACT_FIELDS:
        fields.setdefault(name, {"id": name, "label": name, "type": kind, "tools": ["*"], "computed": True})
        if kind == "enum":
            fields[name]["values"] = [True, False]
    samples = await request.app.state.db.fetch(
        """
        select id, tool, args_redacted, verdict from proxy.decisions
         where agent_id = $1 and tool not like '%<unmatched>' order by created_at desc limit 5
        """,
        agent_id,
    )
    return {
        "tools": tools_by_app,
        "fields": list(fields.values()),
        "dryRunSamples": [
            {"id": row["id"], "label": f"{row['tool']} ({row['verdict']})", "tool": row["tool"], "args": row["args_redacted"]}
            for row in samples
        ],
    }


class DryRunBody(BaseModel):
    tool: str
    args: dict[str, Any] = {}
    rules: list[dict[str, Any]] | None = None
    sessionState: dict[str, Any] = {}
    enrichment: dict[str, Any] = {}


@router.post("/agents/{agent_id}/rules/dry-run")
async def rules_dry_run(agent_id: str, body: DryRunBody, request: Request) -> dict:
    await load_agent(request, agent_id)
    snapshot = request.app.state.snapshot
    if body.rules is not None:
        rules = []
        for index, raw in enumerate(body.rules):
            try:
                parsed = RuleBody(**{key: raw[key] for key in raw if key in RuleBody.model_fields})
            except (TypeError, ValueError) as exc:
                raise HTTPException(400, f"Invalid rule at index {index}: {exc}") from exc
            _validate_rule(parsed)
            rules.append(RuleConfig(id=raw.get("id") or f"draft_{index}", agent_id=agent_id, name=parsed.name,
                                    tool=parsed.tool, condition=parsed.when, outcome=parsed.then, enabled=parsed.enabled))
    else:
        rows = await request.app.state.db.fetch(
            "select * from proxy.agent_rules where agent_id = $1 order by position, created_at", agent_id
        )
        rules = [RuleConfig(id=row["id"], agent_id=agent_id, name=row["name"], tool=row["tool"],
                            condition=row["condition"], outcome=row["outcome"], enabled=row["enabled"]) for row in rows]

    facts = compute_facts(body.args, body.sessionState, body.enrichment, {})
    match = evaluate_rules(rules, body.tool, body.args, body.args, facts)
    result: dict[str, Any] = {"matchedRuleId": match.rule_id, "outcome": match.outcome, "detail": match.detail}

    tool = snapshot.tool(body.tool)
    if tool is not None:
        app = snapshot.apps[tool.app_id]
        action = Action(app=app.id, tool=tool.qualified, kind=tool.kind, args=body.args, request=body.args,
                        session_id="dry-run", agent_id=agent_id)
        expects_merchant = any(source.name == "merchant" for source in app.enrichment)
        policy = CedarPolicyEngine().evaluate(snapshot, action, body.sessionState, body.enrichment, {}, expects_merchant)
        result["policy"] = {"verdict": policy.verdict, "reasons": [reason.model_dump() for reason in policy.reasons],
                            "facts": policy.facts}
    return result


# --- kwoty (P6) ---------------------------------------------------------------


class QuotaCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    window: Literal["1m", "1h", "1d"]
    cap: int = Field(ge=1)
    burst: int = Field(default=0, ge=0)


class QuotaPatch(BaseModel):
    enabled: bool | None = None
    name: str | None = Field(default=None, min_length=1, max_length=200)
    cap: int | None = Field(default=None, ge=1)
    burst: int | None = Field(default=None, ge=0)


async def quota_item(request: Request, row: Any) -> dict[str, Any]:
    used = await request.app.state.db.fetchval(
        """
        select count(*) from proxy.decisions
         where agent_id = $1 and verdict <> 'rate_limited' and created_at > now() - make_interval(secs => $2)
        """,
        row["agent_id"], WINDOW_SECONDS[row["window"]],
    )
    return {
        "id": row["id"],
        "name": row["name"],
        "agentId": row["agent_id"],
        "agentName": row["agent_name"],
        "window": row["window"],
        "cap": row["cap"],
        "used": used,
        "unit": "calls",
        "enabled": row["enabled"],
        "burst": row["burst"],
        "updatedAt": iso(row["updated_at"]),
    }


WINDOW_SECONDS = {"1m": 60, "1h": 3600, "1d": 86400}
QUOTA_SELECT = 'select q.*, a.name as agent_name from proxy.quotas q join proxy.agents a on a.id = q.agent_id'


@router.get("/agents/{agent_id}/quotas")
async def list_quotas(agent_id: str, request: Request) -> dict:
    await load_agent(request, agent_id)
    rows = await request.app.state.db.fetch(f"{QUOTA_SELECT} where q.agent_id = $1 order by q.created_at", agent_id)
    return {"items": [await quota_item(request, row) for row in rows]}


@router.post("/agents/{agent_id}/quotas", status_code=201)
async def create_quota(agent_id: str, body: QuotaCreate, request: Request) -> dict:
    quota_id = new_id("quota")
    async with mutation(request) as conn:
        await _ensure_agent(conn, agent_id)
        await conn.execute(
            'insert into proxy.quotas (id, agent_id, name, "window", cap, burst) values ($1, $2, $3, $4, $5, $6)',
            quota_id, agent_id, body.name, body.window, body.cap, body.burst,
        )
    row = await request.app.state.db.fetchrow(f"{QUOTA_SELECT} where q.id = $1", quota_id)
    return await quota_item(request, row)


@router.patch("/quotas/{quota_id}")
async def patch_quota(quota_id: str, body: QuotaPatch, request: Request) -> dict:
    async with mutation(request) as conn:
        row = await conn.fetchrow(
            """
            update proxy.quotas
               set enabled = coalesce($2, enabled), name = coalesce($3, name),
                   cap = coalesce($4, cap), burst = coalesce($5, burst)
             where id = $1 returning id
            """,
            quota_id, body.enabled, body.name, body.cap, body.burst,
        )
    if row is None:
        raise HTTPException(404, "Unknown quota")
    row = await request.app.state.db.fetchrow(f"{QUOTA_SELECT} where q.id = $1", quota_id)
    return await quota_item(request, row)
