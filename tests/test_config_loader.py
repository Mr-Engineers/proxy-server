import asyncio
import os
from pathlib import Path

import pytest

from app.config.loader import ConfigError, build_snapshot, load_snapshot
from app.config.models import AuthType, Protocol

MIGRATIONS = sorted((Path(__file__).parent.parent / "migrations").glob("*.sql"))


def _row(**overrides) -> dict:
    row = {
        "id": "warehouse",
        "name": "Magazyn",
        "protocol": "rest",
        "upstream_url": "http://warehouse:8000/",
        "timeout_ms": 2500,
        "auth_type": "api_key_header",
        "auth_header": "X-Api-Key",
        "auth_secret_env": "WAREHOUSE_API_KEY",
        "has_ciphertext": False,
        "aws_region": None,
        "aws_service": None,
    }
    return row | overrides


def test_builds_snapshot_from_rows() -> None:
    snapshot = build_snapshot(7, [_row()], {"WAREHOUSE_API_KEY": "secret"})

    app = snapshot.apps["warehouse"]
    assert snapshot.revision == 7
    assert app.upstream_url == "http://warehouse:8000"
    assert app.timeout_seconds == 2.5
    assert app.auth.type == AuthType.API_KEY_HEADER
    assert app.auth.secret.get_secret_value() == "secret"
    assert snapshot.llm is None


def test_missing_secret_env_fails() -> None:
    with pytest.raises(ConfigError, match="WAREHOUSE_API_KEY"):
        build_snapshot(1, [_row()], {})


def test_encrypted_secret_not_supported_yet() -> None:
    with pytest.raises(ConfigError, match="encrypted"):
        build_snapshot(1, [_row(auth_secret_env=None, has_ciphertext=True)], {})


def test_basic_auth_secret_format() -> None:
    with pytest.raises(ConfigError, match="user:password"):
        build_snapshot(1, [_row(auth_type="basic", auth_header=None)], {"WAREHOUSE_API_KEY": "nocolon"})


def test_single_llm_app() -> None:
    llm = _row(id="bedrock", protocol="llm", auth_type="aws_sigv4", auth_header=None, auth_secret_env=None,
               aws_region="eu-north-1", aws_service="bedrock")
    snapshot = build_snapshot(1, [llm], {})
    assert snapshot.llm.id == "bedrock"
    assert snapshot.llm.protocol == Protocol.LLM

    with pytest.raises(ConfigError, match="only one enabled llm app"):
        build_snapshot(1, [llm, llm | {"id": "other"}], {})


@pytest.mark.skipif(not os.environ.get("TEST_DATABASE_URL"), reason="TEST_DATABASE_URL not set")
def test_loads_snapshot_from_postgres() -> None:
    import asyncpg

    async def scenario() -> None:
        conn = await asyncpg.connect(os.environ["TEST_DATABASE_URL"])
        try:
            await conn.execute("drop schema if exists proxy cascade")
            for migration in MIGRATIONS:
                await conn.execute(migration.read_text())
            await conn.execute(
                """
                insert into proxy.apps (id, name, protocol, upstream_url, auth_type, aws_region, aws_service)
                values ('bedrock', 'Bedrock', 'llm', 'https://bedrock-runtime.eu-north-1.amazonaws.com/openai/v1',
                        'aws_sigv4', 'eu-north-1', 'bedrock');
                insert into proxy.apps (id, name, protocol, upstream_url, auth_type, auth_header, auth_secret_env)
                values ('warehouse', 'Magazyn', 'rest', 'http://warehouse:8000', 'api_key_header', 'X-Api-Key',
                        'WAREHOUSE_API_KEY');
                insert into proxy.apps (id, name, protocol, upstream_url, enabled)
                values ('disabled_app', 'Off', 'rest', 'http://off:8000', false);
                """
            )
            snapshot = await load_snapshot(conn, {"WAREHOUSE_API_KEY": "secret"})
        finally:
            await conn.execute("drop schema if exists proxy cascade")
            await conn.close()

        assert snapshot.revision == 3
        assert set(snapshot.apps) == {"bedrock", "warehouse"}
        assert snapshot.llm.auth.aws_region == "eu-north-1"

    asyncio.run(scenario())
