"""CLI administracyjne.

    python -m app.cli create-key <agent_id>          # nowy klucz agenta (pokazywany raz)
    python -m app.cli load-policies [policies/...]   # pakiety polityk z plików → proxy.policy_packs / overrides
    python -m app.cli seed-demo [--sessions 12]      # przykładowe sesje i decyzje dla UI (A7)
    python -m app.cli retention                      # jednorazowe czyszczenie wg audit.retention_days
"""

import argparse
import asyncio
import json
import random
import sys
from datetime import timedelta
from pathlib import Path

import asyncpg

from app.auth.agent import generate_key
from app.core.ids import new_id
from app.core.settings import get_settings
from app.db.dsn import parse_database_url
from app.jobs import apply_retention
from app.policy.cedar import compile_pack
from app.store.runtime import init_connection, request_sha256, utcnow

POLICIES_DIR = Path(__file__).resolve().parent.parent / "policies"


async def _connect() -> asyncpg.Connection:
    settings = get_settings()
    password = settings.database_password.get_secret_value() if settings.database_password else None
    conn = await asyncpg.connect(**parse_database_url(settings.database_url, password).as_kwargs())
    await init_connection(conn)
    return conn


async def create_key(agent_id: str) -> None:
    conn = await _connect()
    try:
        if not await conn.fetchval("select exists (select 1 from proxy.agents where id = $1)", agent_id):
            sys.exit(f"unknown agent {agent_id}")
        key = generate_key()
        async with conn.transaction():
            await conn.execute("set local proxy.actor = 'cli'")
            await conn.execute(
                "insert into proxy.agent_keys (id, agent_id, sha256, hint) values ($1, $2, $3, $4)",
                key.key_id, agent_id, key.sha256, key.hint,
            )
        print(key.token)
    finally:
        await conn.close()


def read_pack(directory: Path) -> dict:
    def text(name: str) -> str:
        path = directory / name
        return path.read_text() if path.exists() else ""

    def data(name: str) -> dict:
        path = directory / name
        return json.loads(path.read_text()) if path.exists() else {}

    pack = {
        "app_id": directory.name,
        "policies": text("policy.cedar"),
        "schema": text("schema.cedarschema"),
        "params": data("params.json"),
        "params_schema": data("params_schema.json"),
        "overrides": data("overrides.json"),
    }
    compile_pack(pack["app_id"], pack["policies"], pack["schema"], pack["params"], pack["params_schema"], pack["overrides"])
    return pack


async def store_packs(conn: asyncpg.Connection, packs: list[dict]) -> list[str]:
    loaded = []
    async with conn.transaction():
        await conn.execute("set local proxy.actor = 'cli'")
        for pack in packs:
            if not await conn.fetchval("select exists (select 1 from proxy.apps where id = $1)", pack["app_id"]):
                print(f"skip {pack['app_id']}: app not configured")
                continue
            await conn.execute(
                """
                insert into proxy.policy_packs (app_id, cedar_policies, cedar_schema, params, params_schema)
                values ($1, $2, $3, $4, $5)
                on conflict (app_id) do update set cedar_policies = excluded.cedar_policies,
                  cedar_schema = excluded.cedar_schema, params = excluded.params, params_schema = excluded.params_schema
                """,
                pack["app_id"], pack["policies"], pack["schema"], pack["params"], pack["params_schema"],
            )
            await conn.execute("delete from proxy.policy_overrides where app_id = $1", pack["app_id"])
            for agent_id, params in pack["overrides"].items():
                if await conn.fetchval("select exists (select 1 from proxy.agents where id = $1)", agent_id):
                    await conn.execute(
                        "insert into proxy.policy_overrides (app_id, agent_id, params) values ($1, $2, $3)",
                        pack["app_id"], agent_id, params,
                    )
                else:
                    print(f"skip override {pack['app_id']}/{agent_id}: unknown agent")
            loaded.append(pack["app_id"])
    return loaded


async def load_policies(paths: list[str]) -> None:
    directories = [Path(path) for path in paths] or sorted(p for p in POLICIES_DIR.iterdir() if p.is_dir())
    packs = [read_pack(directory) for directory in directories]
    conn = await _connect()
    try:
        for app_id in await store_packs(conn, packs):
            print(f"loaded {app_id}")
    finally:
        await conn.close()


SCENARIOS = [
    ("warehouse.list_low_stock", "read", "allow", [], {}),
    ("marketplace.search_products", "read", "allow", [], {"sku": "PAP-A4-80"}),
    ("marketplace.place_order", "write", "allow", [], {"offer_id": "off_bm_pap", "quantity": 38, "unit_price": {"amount": "118.00", "currency": "PLN"}}),
    ("warehouse.register_po", "write", "allow", [], {"sku": "PAP-A4-80", "quantity": 38, "marketplace_order_id": "ord_8f2c"}),
    ("marketplace.place_order", "write", "deny", ["marketplace.country_not_allowed"], {"offer_id": "off_cd_pap", "quantity": 38, "unit_price": {"amount": "61.00", "currency": "PLN"}}),
    ("marketplace.place_order", "write", "escalate", ["marketplace.merchant_too_young"], {"offer_id": "off_pr_pap", "quantity": 38, "unit_price": {"amount": "36.00", "currency": "PLN"}}),
    ("marketplace.place_order", "write", "escalate", ["marketplace.qty_ratio_exceeded"], {"offer_id": "off_bm_pap", "quantity": 400, "unit_price": {"amount": "118.00", "currency": "PLN"}}),
    ("marketplace.place_order", "write", "deny", ["marketplace.offer_not_grounded"], {"offer_id": "off_unknown", "quantity": 38, "unit_price": {"amount": "99.00", "currency": "PLN"}}),
    ("marketplace.<unmatched>", "write", "deny", ["unknown_route"], {"body": "..."}),
    ("marketplace.search_products", "read", "rate_limited", ["rate_limited"], {"q": "toner"}),
]


def _chain(verdict: str, reasons: list[str]) -> list[dict]:
    rules = {"deny": "deny", "escalate": "caution", "rate_limited": "rate_limited"}.get(verdict, "pass")
    specialist = (
        {"stage": "specialist", "outcome": "caution", "detail": "caution → human (young merchant / over-qty)"}
        if verdict == "escalate"
        else {"stage": "specialist", "outcome": "skipped", "detail": "Not required"}
    )
    return [
        {"stage": "rbac", "outcome": "deny" if "unknown_route" in reasons else "pass", "detail": "Role role_purchasing_operator"},
        {"stage": "rules", "outcome": rules, "detail": "; ".join(reasons) or "No rule matched"},
        specialist,
        {"stage": "human", "outcome": "pending" if verdict == "escalate" else "skipped", "detail": "Waiting for operator" if verdict == "escalate" else "Not required"},
    ]


def _signals(verdict: str, reasons: list[str]) -> dict:
    if verdict != "escalate":
        return {
            "available": False,
            "choice": None,
            "confidence": None,
            "allow_prob": 1.0 if verdict == "allow" else 0.0,
            "deny_prob": 1.0 if verdict == "deny" else 0.0,
            "specialist": "rules/v0",
            "version": "v0",
            "demo": True,
        }
    # Demo HITL path: specialist cautioned (same shape as live Jev signals).
    return {
        "available": True,
        "choice": "caution",
        "confidence": 0.78,
        "alignment": 0.22,
        "p_malicious": 0.18,
        "allow_prob": 0.22,
        "deny_prob": 0.18,
        "specialist": "local/purchasing",
        "version": "jev-latest",
        "latency_ms": 186.0,
        "failed": False,
        "demo": True,
        "notes": reasons,
    }


async def seed_demo(sessions: int) -> None:
    conn = await _connect()
    rng = random.Random(42)
    status_for = {"allow": "executed", "deny": "blocked", "escalate": "pending_approval", "rate_limited": "rate_limited"}
    http_for = {"allow": 200, "deny": 403, "escalate": 202, "rate_limited": 429}
    try:
        agent_id = await conn.fetchval("select id from proxy.agents order by id limit 1")
        if agent_id is None:
            sys.exit("no agents — run seeds/seed.sql first")
        revision = await conn.fetchval("select revision from proxy.config_revision")
        async with conn.transaction():
            for index in range(sessions):
                started = utcnow() - timedelta(minutes=rng.randint(5, 60 * 30))
                session_id = new_id("ses")
                await conn.execute(
                    "insert into proxy.sessions (id, agent_id, task, created_at, last_activity_at) values ($1, $2, $3, $4, $4)",
                    session_id, agent_id, f"Restock PAP-A4-80 (demo {index + 1})", started,
                )
                for seq, scenario in enumerate(rng.sample(SCENARIOS, k=rng.randint(3, 6))):
                    tool, kind, verdict, reasons, args = scenario
                    moment = started + timedelta(seconds=seq * rng.randint(5, 40))
                    hop_id, decision_id = new_id("hop"), new_id("dec")
                    await conn.execute(
                        """
                        insert into proxy.hops (id, session_id, agent_id, seq, direction, protocol, app_id, action, payload, created_at)
                        values ($1, $2, $3, $4, 'request', 'rest', $5, $6, $7, $8)
                        """,
                        hop_id, session_id, agent_id, seq, tool.partition(".")[0], tool, {"demo": True, "args": args}, moment,
                    )
                    await conn.execute(
                        """
                        insert into proxy.decisions (id, hop_id, session_id, verdict, confidence, reasons, signals, latency_ms,
                                                     config_revision, agent_id, app_id, tool, kind, chain, args_redacted,
                                                     action_status, http_status, created_at, quota_id, retry_after_seconds)
                        values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
                        """,
                        decision_id, hop_id, session_id, verdict, 1.0 if verdict != "escalate" else 0.5,
                        [{"code": code, "severity": "deny" if verdict != "escalate" else "escalate", "message": code, "source": "policy"} for code in reasons],
                        _signals(verdict, reasons),
                        rng.uniform(2, 40), revision, agent_id, tool.partition(".")[0], tool, kind, _chain(verdict, reasons),
                        args, status_for[verdict], http_for[verdict], moment,
                        "quota_purchasing_hourly" if verdict == "rate_limited" else None, 60 if verdict == "rate_limited" else None,
                    )
                    if verdict == "escalate":
                        request = {"app_id": tool.partition(".")[0], "tool": tool, "method": "POST", "path": "/orders",
                                   "query": "", "headers": [["content-type", "application/json"]], "body": json.dumps(args)}
                        pending = rng.random() < 0.4
                        await conn.execute(
                            """
                            insert into proxy.approvals (id, decision_id, session_id, agent_id, tool, request, request_sha256,
                                                         expires_at, status, resolved_at, resolved_by, created_at)
                            values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
                            """,
                            new_id("apr"), decision_id, session_id, agent_id, tool, request, request_sha256(request),
                            utcnow() + timedelta(minutes=15) if pending else moment + timedelta(minutes=15),
                            "pending" if pending else "expired", None if pending else moment + timedelta(minutes=15),
                            None, moment if not pending else utcnow() - timedelta(seconds=rng.randint(5, 300)),
                        )
        print(f"seeded {sessions} demo sessions for {agent_id}")
    finally:
        await conn.close()


async def retention() -> None:
    conn = await _connect()
    try:
        days = await conn.fetchval("select (value #>> '{}')::int from proxy.settings where key = 'audit.retention_days'") or 90
    finally:
        await conn.close()
    settings = get_settings()
    password = settings.database_password.get_secret_value() if settings.database_password else None
    pool = await asyncpg.create_pool(min_size=1, max_size=1, **parse_database_url(settings.database_url, password).as_kwargs())
    try:
        await apply_retention(pool, days)
    finally:
        await pool.close()
    print(f"retention applied ({days} days)")


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m app.cli")
    commands = parser.add_subparsers(dest="command", required=True)
    key = commands.add_parser("create-key")
    key.add_argument("agent_id")
    policies = commands.add_parser("load-policies")
    policies.add_argument("paths", nargs="*")
    demo = commands.add_parser("seed-demo")
    demo.add_argument("--sessions", type=int, default=12)
    commands.add_parser("retention")
    args = parser.parse_args()

    match args.command:
        case "create-key":
            asyncio.run(create_key(args.agent_id))
        case "load-policies":
            asyncio.run(load_policies(args.paths))
        case "seed-demo":
            asyncio.run(seed_demo(args.sessions))
        case "retention":
            asyncio.run(retention())


if __name__ == "__main__":
    main()
