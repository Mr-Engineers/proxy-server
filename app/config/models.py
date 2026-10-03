from enum import StrEnum

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


class AppConfig(BaseModel):
    model_config = ConfigDict(frozen=True)

    id: str
    name: str
    protocol: Protocol
    upstream_url: str
    timeout_seconds: float
    auth: UpstreamAuth = UpstreamAuth()


class ConfigSnapshot(BaseModel):
    model_config = ConfigDict(frozen=True)

    revision: int
    apps: dict[str, AppConfig]

    @property
    def llm(self) -> AppConfig | None:
        return next((app for app in self.apps.values() if app.protocol == Protocol.LLM), None)
