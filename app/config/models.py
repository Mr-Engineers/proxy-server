import re
from enum import StrEnum
from functools import cached_property
from typing import Any

from pydantic import BaseModel, ConfigDict, SecretStr


class Protocol(StrEnum):
    REST = "rest"
    MCP = "mcp"
    LLM = "llm"
    WEB = "web"


class AuthType(StrEnum):
    NONE = "none"
    BEARER = "bearer"
    API_KEY_HEADER = "api_key_header"
    BASIC = "basic"
    AWS_SIGV4 = "aws_sigv4"


class UpstreamAuth(BaseModel):
    model_config = ConfigDict(frozen=True)

    type: AuthType = AuthType.NONE
    header: str | None = None
    secret: SecretStr | None = None
    aws_region: str | None = None
    aws_service: str | None = None


class EnrichmentSource(BaseModel):
    """Endpoint tylko dla proxy, np. GET /merchants/{merchant_id}.

    `params` mapuje parametr ścieżki na JSONPath w kontekście {args, <wcześniejsze źródła>};
    brak wpisu = wartość z args o tej samej nazwie.
    """

    model_config = ConfigDict(frozen=True)

    name: str
    method: str = "GET"
    path: str
    params: dict[str, str] = {}
    tools: tuple[str, ...] = ()
    cache_ttl_seconds: int = 60


class AppConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    protocol: Protocol
    upstream_url: str
    timeout_seconds: float
    auth: UpstreamAuth = UpstreamAuth()
    enrichment: tuple[EnrichmentSource, ...] = ()


class CaptureRule(BaseModel):
    model_config = ConfigDict(frozen=True)

    into: str
    source: str = "$"
    fields: dict[str, str] = {}
    key: str | None = None
    origin: str = "response"


class ToolConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    app_id: str
    name: str
    kind: str
    description: str | None = None
    http_method: str | None = None
    http_path: str | None = None
    mcp_tool: str | None = None
    input_schema: dict[str, Any] | None = None
    args: dict[str, str] = {}
    capture: tuple[CaptureRule, ...] = ()
    scan_mode: str = "all_strings"
    scan: tuple[str, ...] = ()
    redact: tuple[str, ...] = ()

    @property
    def qualified(self) -> str:
        return f"{self.app_id}.{self.name}"

    @cached_property
    def path_pattern(self) -> re.Pattern[str] | None:
        if self.http_path is None:
            return None
        parts = re.split(r"(\{[a-zA-Z_][a-zA-Z0-9_]*\})", self.http_path)
        regex = "".join(
            f"(?P<{part[1:-1]}>[^/]+)" if part.startswith("{") else re.escape(part) for part in parts
        )
        return re.compile(f"^{regex}/?$")


class AgentKey(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    agent_id: str
    sha256: bytes


class AgentConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    status: str
    mandate: str
    llm_models: tuple[str, ...] = ()
    limits: dict[str, Any] = {}
    role_id: str | None = None
    permissions: frozenset[str] = frozenset()


class RuleConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    agent_id: str
    name: str
    tool: str
    condition: dict[str, Any]
    outcome: str
    enabled: bool = True
    position: int = 0


class QuotaConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    agent_id: str
    name: str
    window: str
    cap: int
    burst: int = 0
    enabled: bool = True

    @property
    def window_seconds(self) -> int:
        return {"1m": 60, "1h": 3600, "1d": 86400}[self.window]

    @property
    def limit(self) -> int:
        return self.cap + self.burst


class PolicyAnnotation(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    severity: str
    message: str = ""


class PolicyPack(BaseModel):
    model_config = ConfigDict(frozen=True)

    app_id: str
    policies: str
    schema_text: str = ""
    annotations: dict[str, PolicyAnnotation] = {}
    params_schema: dict[str, Any] = {}
    # action name → parametry w postaci gotowej dla Cedar (kwoty w groszach)
    params: dict[str, dict[str, Any]] = {}
    # agent_id → action name → parametry po zaostrzeniu przez overrides
    agent_params: dict[str, dict[str, dict[str, Any]]] = {}

    def params_for(self, agent_id: str, action: str) -> dict[str, Any]:
        return self.agent_params.get(agent_id, {}).get(action, self.params.get(action, {}))


class WorkspaceSettings(BaseModel):
    model_config = ConfigDict(frozen=True)

    org_name: str = "Modus Demo"
    default_approval_ttl_seconds: int = 900
    specialist_fail_closed: bool = True
    audit_retention_days: int = 90
    max_denies_per_session: int = 3
    timezone: str = "Europe/Warsaw"


class ConfigSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    revision: int
    apps: dict[str, AppConfig]
    tools: dict[str, tuple[ToolConfig, ...]] = {}
    agents: dict[str, AgentConfig] = {}
    keys: dict[str, AgentKey] = {}
    rules: dict[str, tuple[RuleConfig, ...]] = {}
    quotas: dict[str, tuple[QuotaConfig, ...]] = {}
    policy_packs: dict[str, PolicyPack] = {}
    settings: WorkspaceSettings = WorkspaceSettings()

    @property
    def llm(self) -> AppConfig | None:
        return next((app for app in self.apps.values() if app.protocol == Protocol.LLM), None)

    def tool(self, qualified: str) -> ToolConfig | None:
        app_id, _, name = qualified.partition(".")
        return next((tool for tool in self.tools.get(app_id, ()) if tool.name == name), None)
