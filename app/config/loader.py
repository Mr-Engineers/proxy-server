import json
import os
from collections import defaultdict
from collections.abc import Iterable, Mapping
from typing import Any

import asyncpg
from pydantic import SecretStr

from app.config.models import (
    AgentConfig,
    AgentKey,
    AppConfig,
    AuthType,
    CaptureRule,
    ConfigSnapshot,
    EnrichmentSource,
    Protocol,
    QuotaConfig,
    RuleConfig,
    ToolConfig,
    UpstreamAuth,
    WorkspaceSettings,
)

APPS_QUERY = """
select id, name, protocol, upstream_url, timeout_ms, auth_type, auth_header,
       auth_secret_env, auth_secret_ciphertext is not null as has_ciphertext,
       aws_region, aws_service, enrichment::text as enrichment
  from proxy.apps
 where enabled
 order by id
"""

TOOLS_QUERY = """
select t.id::text as id, t.app_id, t.name, t.kind, t.description, t.http_method, t.http_path, t.mcp_tool,
       t.input_schema::text as input_schema, t.args::text as args, t.capture::text as capture, t.scan_mode,
       t.scan::text as scan, t.redact::text as redact
  from proxy.tools t
  join proxy.apps a on a.id = t.app_id
 where t.enabled and a.enabled
 order by t.app_id, t.name
"""

AGENTS_QUERY = "select id, name, status, mandate, llm_models, limits::text as limits, role_id from proxy.agents order by id"
KEYS_QUERY = "select id, agent_id, sha256 from proxy.agent_keys where revoked_at is null"
PERMISSIONS_QUERY = "select agent_id, tool_id::text as tool_id from proxy.agent_permissions"
ROLES_QUERY = "select id, status from proxy.roles"
ROLE_GRANTS_QUERY = "select role_id, tool_id::text as tool_id from proxy.role_grants"
ROLE_APP_GRANTS_QUERY = "select role_id, app_id from proxy.role_app_grants"
RULES_QUERY = """
select id, agent_id, name, tool, condition::text as condition, outcome, enabled, position
  from proxy.agent_rules
 order by agent_id, position, created_at
"""
QUOTAS_QUERY = 'select id, agent_id, name, "window", cap, burst, enabled from proxy.quotas order by agent_id, id'
PACKS_QUERY = (
    "select app_id, cedar_policies, cedar_schema, params::text as params, params_schema::text as params_schema"
    " from proxy.policy_packs"
)
OVERRIDES_QUERY = "select app_id, agent_id, params::text as params from proxy.policy_overrides"
SETTINGS_QUERY = "select key, value::text as value from proxy.settings"

SETTINGS_KEYS = {
    "workspace.org_name": "org_name",
    "approvals.default_ttl_seconds": "default_approval_ttl_seconds",
    "specialist.fail_closed": "specialist_fail_closed",
    "audit.retention_days": "audit_retention_days",
    "sessions.max_denies": "max_denies_per_session",
    "workspace.timezone": "timezone",
}


class ConfigError(Exception):
    pass


def _json(value: Any) -> Any:
    """Kolumny JSONB są czytane jako `::text`, więc wynik nie zależy od kodeka połączenia."""
    return json.loads(value) if isinstance(value, str) else value


def _build_auth(row: Mapping, environ: Mapping[str, str]) -> UpstreamAuth:
    auth_type = AuthType(row["auth_type"])
    if row["has_ciphertext"]:
        raise ConfigError(f"app {row['id']}: encrypted secrets are not supported yet, use auth_secret_env")

    secret = None
    env_name = row["auth_secret_env"]
    if env_name is not None:
        value = environ.get(env_name)
        if not value:
            raise ConfigError(f"app {row['id']}: environment variable {env_name} is not set")
        secret = SecretStr(value)

    if auth_type == AuthType.BASIC and secret is not None and ":" not in secret.get_secret_value():
        raise ConfigError(f"app {row['id']}: basic auth secret must have the form user:password")

    return UpstreamAuth(
        type=auth_type,
        header=row["auth_header"],
        secret=secret,
        aws_region=row["aws_region"],
        aws_service=row["aws_service"],
    )


def _build_enrichment(row: Mapping) -> tuple[EnrichmentSource, ...]:
    raw = _json(row.get("enrichment")) or {}
    try:
        return tuple(EnrichmentSource(name=name, **spec) for name, spec in raw.items())
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"app {row['id']}: invalid enrichment config: {exc}") from exc


def _build_tool(row: Mapping) -> ToolConfig:
    try:
        capture = tuple(
            CaptureRule(
                into=item["into"],
                source=item.get("from", "$"),
                fields=item.get("fields", {}),
                key=item.get("key"),
                origin=item.get("origin", "response"),
            )
            for item in _json(row["capture"]) or []
        )
        return ToolConfig(
            id=row["id"],
            app_id=row["app_id"],
            name=row["name"],
            kind=row["kind"],
            description=row["description"],
            http_method=row["http_method"],
            http_path=row["http_path"],
            mcp_tool=row["mcp_tool"],
            input_schema=_json(row["input_schema"]),
            args=_json(row["args"]) or {},
            capture=capture,
            scan_mode=row["scan_mode"],
            scan=tuple(_json(row["scan"]) or []),
            redact=tuple(_json(row["redact"]) or []),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise ConfigError(f"tool {row['app_id']}.{row['name']}: invalid config: {exc}") from exc


def _settings(rows: Iterable[Mapping]) -> WorkspaceSettings:
    values = {}
    for row in rows:
        field = SETTINGS_KEYS.get(row["key"])
        if field is not None:
            values[field] = _json(row["value"])
    try:
        return WorkspaceSettings(**values)
    except ValueError as exc:
        raise ConfigError(f"invalid settings: {exc}") from exc


def build_snapshot(
    revision: int,
    rows: list[Mapping],
    environ: Mapping[str, str],
    *,
    tools: Iterable[Mapping] = (),
    agents: Iterable[Mapping] = (),
    keys: Iterable[Mapping] = (),
    permissions: Iterable[Mapping] = (),
    roles: Iterable[Mapping] = (),
    role_grants: Iterable[Mapping] = (),
    role_app_grants: Iterable[Mapping] = (),
    rules: Iterable[Mapping] = (),
    quotas: Iterable[Mapping] = (),
    packs: Iterable[Mapping] = (),
    overrides: Iterable[Mapping] = (),
    settings: Iterable[Mapping] = (),
) -> ConfigSnapshot:
    from app.policy.cedar import PolicyCompileError, compile_pack

    apps = {
        row["id"]: AppConfig(
            id=row["id"],
            name=row["name"],
            protocol=Protocol(row["protocol"]),
            upstream_url=row["upstream_url"].rstrip("/"),
            timeout_seconds=row["timeout_ms"] / 1000,
            auth=_build_auth(row, environ),
            enrichment=_build_enrichment(row),
        )
        for row in rows
    }
    llm_apps = [app.id for app in apps.values() if app.protocol == Protocol.LLM]
    if len(llm_apps) > 1:
        raise ConfigError(f"only one enabled llm app is supported, found: {llm_apps}")

    tools_by_app: dict[str, list[ToolConfig]] = defaultdict(list)
    tools_by_id: dict[str, ToolConfig] = {}
    for row in tools:
        if row["app_id"] not in apps:
            continue
        tool = _build_tool(row)
        tools_by_app[tool.app_id].append(tool)
        tools_by_id[tool.id] = tool

    active_roles = {row["id"] for row in roles if row["status"] == "active"}
    role_tools: dict[str, set[str]] = defaultdict(set)
    for row in role_grants:
        if row["role_id"] in active_roles and row["tool_id"] in tools_by_id:
            role_tools[row["role_id"]].add(tools_by_id[row["tool_id"]].qualified)
    for row in role_app_grants:
        if row["role_id"] in active_roles:
            role_tools[row["role_id"]].update(tool.qualified for tool in tools_by_app.get(row["app_id"], ()))

    direct: dict[str, set[str]] = defaultdict(set)
    for row in permissions:
        if row["tool_id"] in tools_by_id:
            direct[row["agent_id"]].add(tools_by_id[row["tool_id"]].qualified)

    agent_map = {
        row["id"]: AgentConfig(
            id=row["id"],
            name=row["name"],
            status=row["status"],
            mandate=row["mandate"],
            llm_models=tuple(row["llm_models"] or ()),
            limits=_json(row["limits"]) or {},
            role_id=row["role_id"],
            permissions=frozenset(direct[row["id"]] | role_tools.get(row["role_id"], set())),
        )
        for row in agents
    }

    key_map = {
        row["id"]: AgentKey(id=row["id"], agent_id=row["agent_id"], sha256=bytes(row["sha256"]))
        for row in keys
        if row["agent_id"] in agent_map
    }

    rules_by_agent: dict[str, list[RuleConfig]] = defaultdict(list)
    for row in rules:
        rules_by_agent[row["agent_id"]].append(
            RuleConfig(**{**dict(row), "condition": _json(row["condition"]) or {}})
        )

    quotas_by_agent: dict[str, list[QuotaConfig]] = defaultdict(list)
    for row in quotas:
        quotas_by_agent[row["agent_id"]].append(QuotaConfig(**dict(row)))

    overrides_by_app: dict[str, dict[str, dict]] = defaultdict(dict)
    for row in overrides:
        if row["agent_id"] not in agent_map:
            raise ConfigError(f"policy override for unknown agent {row['agent_id']}")
        overrides_by_app[row["app_id"]][row["agent_id"]] = _json(row["params"]) or {}

    policy_packs = {}
    for row in packs:
        if row["app_id"] not in apps:
            continue
        try:
            policy_packs[row["app_id"]] = compile_pack(
                app_id=row["app_id"],
                policies=row["cedar_policies"],
                schema_text=row["cedar_schema"],
                params=_json(row["params"]) or {},
                params_schema=_json(row["params_schema"]) or {},
                overrides=overrides_by_app.get(row["app_id"], {}),
            )
        except PolicyCompileError as exc:
            raise ConfigError(f"policy pack {row['app_id']}: {exc}") from exc

    return ConfigSnapshot(
        revision=revision,
        apps=apps,
        tools={app_id: tuple(items) for app_id, items in tools_by_app.items()},
        agents=agent_map,
        keys=key_map,
        rules={agent_id: tuple(items) for agent_id, items in rules_by_agent.items()},
        quotas={agent_id: tuple(items) for agent_id, items in quotas_by_agent.items()},
        policy_packs=policy_packs,
        settings=_settings(settings),
    )


async def load_snapshot(conn: asyncpg.Connection, environ: Mapping[str, str] = os.environ) -> ConfigSnapshot:
    async with conn.transaction(isolation="repeatable_read", readonly=True):
        revision = await conn.fetchval("select revision from proxy.config_revision")
        rows = await conn.fetch(APPS_QUERY)
        other = {
            "tools": await conn.fetch(TOOLS_QUERY),
            "agents": await conn.fetch(AGENTS_QUERY),
            "keys": await conn.fetch(KEYS_QUERY),
            "permissions": await conn.fetch(PERMISSIONS_QUERY),
            "roles": await conn.fetch(ROLES_QUERY),
            "role_grants": await conn.fetch(ROLE_GRANTS_QUERY),
            "role_app_grants": await conn.fetch(ROLE_APP_GRANTS_QUERY),
            "rules": await conn.fetch(RULES_QUERY),
            "quotas": await conn.fetch(QUOTAS_QUERY),
            "packs": await conn.fetch(PACKS_QUERY),
            "overrides": await conn.fetch(OVERRIDES_QUERY),
            "settings": await conn.fetch(SETTINGS_QUERY),
        }
    return build_snapshot(revision, rows, environ, **other)
