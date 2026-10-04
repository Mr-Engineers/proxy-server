import asyncio

import pytest

from app.config.loader import ConfigError, build_snapshot, load_snapshot
from app.config.models import AuthType, Protocol



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


def test_loads_full_snapshot_from_postgres(database) -> None:
    import asyncpg

    from app.store.runtime import init_connection

    async def scenario():
        conn = await asyncpg.connect(database)
        try:
            await init_connection(conn)
            return await load_snapshot(conn, {"WAREHOUSE_API_KEY": "secret", "BEDROCK_API_KEY": "k"})
        finally:
            await conn.close()

    snapshot = asyncio.run(scenario())
    assert set(snapshot.apps) == {"bedrock", "warehouse", "marketplace"}
    assert snapshot.apps["marketplace"].enrichment[1].params == {"merchant_id": "$.offer.merchant.id"}
    agent = snapshot.agents["purchasing-agent"]
    assert agent.permissions == {
        "warehouse.list_low_stock", "warehouse.register_po", "marketplace.search_products", "marketplace.place_order"
    }
    assert "dev0001" in snapshot.keys
    pack = snapshot.policy_packs["marketplace"]
    countries = pack.params_for("purchasing-agent", "place_order")["allowed_countries"]
    assert {"PL", "DE"} <= set(countries) and "IN" not in countries
    assert pack.params_for("other-agent", "place_order")["max_order_value_minor"] == 1_000_000
    assert snapshot.settings.org_name == "Modus Demo"
    assert snapshot.tool("marketplace.search_products").capture[0].key == "offer_id"


def test_role_must_be_active_to_grant(database) -> None:
    import asyncpg

    async def scenario():
        conn = await asyncpg.connect(database)
        try:
            await conn.execute("update proxy.roles set status = 'draft'")
            return await load_snapshot(conn, {"WAREHOUSE_API_KEY": "secret", "BEDROCK_API_KEY": "k"})
        finally:
            await conn.close()

    assert asyncio.run(scenario()).agents["purchasing-agent"].permissions == frozenset()


def test_override_for_unknown_agent_fails() -> None:
    with pytest.raises(ConfigError, match="unknown agent"):
        build_snapshot(1, [], {}, overrides=[{"app_id": "marketplace", "agent_id": "ghost", "params": "{}"}])
