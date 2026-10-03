"""Tożsamość agenta (ADR 0002): `Authorization: Bearer ak_<key_id>_<secret>`.

Proxy trzyma tylko SHA-256 całego tokenu; po `key_id` znajduje wpis i porównuje hash w czasie stałym.
`AgentAuthenticator` to punkt podmiany na OIDC (S25).
"""

import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass

from fastapi import Request

from app.config.models import AgentConfig, ConfigSnapshot

KEY_PREFIX = "ak_"


class AgentAuthError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


@dataclass(frozen=True)
class AgentPrincipal:
    agent: AgentConfig
    key_id: str

    @property
    def agent_id(self) -> str:
        return self.agent.id


@dataclass(frozen=True)
class GeneratedKey:
    key_id: str
    token: str
    sha256: bytes
    hint: str


def hash_token(token: str) -> bytes:
    return hashlib.sha256(token.encode()).digest()


def generate_key() -> GeneratedKey:
    key_id = secrets.token_hex(4)
    secret = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip("=")
    token = f"{KEY_PREFIX}{key_id}_{secret}"
    return GeneratedKey(key_id=key_id, token=token, sha256=hash_token(token), hint=f"{KEY_PREFIX}{key_id}_••••{token[-4:]}")


class AgentAuthenticator:
    def authenticate(self, snapshot: ConfigSnapshot, authorization: str | None) -> AgentPrincipal:
        if not authorization or not authorization.lower().startswith("bearer "):
            raise AgentAuthError(401, "missing_agent_key", "Authorization: Bearer <agent_key> is required")
        token = authorization[7:].strip()
        if not token.startswith(KEY_PREFIX):
            raise AgentAuthError(401, "invalid_agent_key", "Invalid agent key")
        key_id = token[len(KEY_PREFIX) :].partition("_")[0]
        key = snapshot.keys.get(key_id)
        if key is None or not hmac.compare_digest(key.sha256, hash_token(token)):
            raise AgentAuthError(401, "invalid_agent_key", "Invalid agent key")
        agent = snapshot.agents.get(key.agent_id)
        if agent is None:
            raise AgentAuthError(401, "invalid_agent_key", "Invalid agent key")
        if agent.status != "active":
            raise AgentAuthError(403, "agent_disabled", "Agent is not active")
        return AgentPrincipal(agent=agent, key_id=key_id)


async def authenticate_request(request: Request) -> AgentPrincipal:
    principal = request.app.state.agent_auth.authenticate(
        request.app.state.snapshot, request.headers.get("authorization")
    )
    request.state.agent_id = principal.agent_id
    store = request.app.state.store
    if store is not None:
        await store.touch_agent(principal.agent_id)
    return principal
