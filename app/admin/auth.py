"""Uwierzytelnianie operatorów UI: JWT z Supabase Auth (HS256 z sekretem projektu lub JWKS)."""

from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any

import jwt
from fastapi import HTTPException, Request

ASYMMETRIC = ["RS256", "ES256", "EdDSA"]


@dataclass(frozen=True)
class Operator:
    user_id: str
    email: str
    claims: dict[str, Any] = field(default_factory=dict)
    roster: dict[str, Any] | None = None

    @property
    def actor(self) -> str:
        return self.email or self.user_id


@lru_cache(maxsize=4)
def _jwks_client(url: str) -> jwt.PyJWKClient:
    return jwt.PyJWKClient(url, cache_keys=True, lifespan=3600)


def decode_token(token: str, settings) -> dict[str, Any]:
    options = {"require": ["exp", "sub"]}
    header = jwt.get_unverified_header(token)
    algorithm = header.get("alg")
    if algorithm == "HS256":
        if settings.supabase_jwt_secret is None:
            raise HTTPException(401, "HS256 tokens are not accepted")
        return jwt.decode(
            token,
            settings.supabase_jwt_secret.get_secret_value(),
            algorithms=["HS256"],
            audience=settings.supabase_jwt_audience,
            options=options,
        )
    if algorithm in ASYMMETRIC and settings.supabase_url:
        url = settings.supabase_url.rstrip("/") + "/auth/v1/.well-known/jwks.json"
        key = _jwks_client(url).get_signing_key_from_jwt(token)
        return jwt.decode(token, key.key, algorithms=ASYMMETRIC, audience=settings.supabase_jwt_audience, options=options)
    raise HTTPException(401, "Unsupported token")


async def require_operator(request: Request) -> Operator:
    settings = request.app.state.settings
    if settings.admin_auth_disabled:
        operator = Operator(user_id="dev", email=request.headers.get("x-dev-operator", "dev@localhost"))
    else:
        header = request.headers.get("authorization", "")
        if not header.lower().startswith("bearer "):
            raise HTTPException(401, "Missing bearer token")
        try:
            claims = decode_token(header[7:].strip(), settings)
        except jwt.PyJWTError as exc:
            raise HTTPException(401, f"Invalid token: {exc}") from exc
        operator = Operator(user_id=claims["sub"], email=claims.get("email", ""), claims=claims)

    row = await request.app.state.db.fetchrow(
        "select * from proxy.operators where lower(email) = lower($1) or user_id = $2", operator.email, operator.user_id
    )
    if row is not None:
        if row["status"] == "disabled":
            raise HTTPException(403, "Operator is disabled")
        await request.app.state.db.execute(
            """
            update proxy.operators
               set last_active_at = now(), user_id = coalesce(user_id, $2),
                   status = case when status = 'invited' then 'active' else status end
             where id = $1
            """,
            row["id"], operator.user_id if operator.user_id != "dev" else None,
        )
        operator = Operator(operator.user_id, operator.email, operator.claims, dict(row))
    request.state.operator = operator
    return operator
