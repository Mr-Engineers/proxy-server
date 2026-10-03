import os
from collections.abc import Mapping

import asyncpg
from pydantic import SecretStr

from app.config.models import AppConfig, AuthType, ConfigSnapshot, Protocol, UpstreamAuth

APPS_QUERY = """
select id, name, protocol, upstream_url, timeout_ms, auth_type, auth_header,
       auth_secret_env, auth_secret_ciphertext is not null as has_ciphertext,
       aws_region, aws_service
  from proxy.apps
 where enabled
 order by id
"""


class ConfigError(Exception):
    pass


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


def build_snapshot(revision: int, rows: list[Mapping], environ: Mapping[str, str]) -> ConfigSnapshot:
    apps = {
        row["id"]: AppConfig(
            id=row["id"],
            name=row["name"],
            protocol=Protocol(row["protocol"]),
            upstream_url=row["upstream_url"].rstrip("/"),
            timeout_seconds=row["timeout_ms"] / 1000,
            auth=_build_auth(row, environ),
        )
        for row in rows
    }
    llm_apps = [app.id for app in apps.values() if app.protocol == Protocol.LLM]
    if len(llm_apps) > 1:
        raise ConfigError(f"only one enabled llm app is supported, found: {llm_apps}")
    return ConfigSnapshot(revision=revision, apps=apps)


async def load_snapshot(conn: asyncpg.Connection, environ: Mapping[str, str] = os.environ) -> ConfigSnapshot:
    async with conn.transaction(isolation="repeatable_read", readonly=True):
        revision = await conn.fetchval("select revision from proxy.config_revision")
        rows = await conn.fetch(APPS_QUERY)
    return build_snapshot(revision, rows, environ)
