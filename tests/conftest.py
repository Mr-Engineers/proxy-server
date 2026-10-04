import asyncio
import json
import os
import re
from collections.abc import Callable, Iterator
from pathlib import Path

import asyncpg
import httpx
import pytest
from botocore.credentials import Credentials
from fastapi.testclient import TestClient

from app.cli import POLICIES_DIR, read_pack, store_packs
from app.config.loader import load_snapshot
from app.core.settings import Settings
from app.main import create_app
from app.store.runtime import init_connection

ROOT = Path(__file__).parent.parent
MIGRATIONS = sorted((ROOT / "migrations").glob("*.sql"))
SEED = ROOT / "seeds" / "seed.sql"
TEST_DATABASE_URL = os.environ.get("TEST_DATABASE_URL")
DEV_KEY = "ak_dev0001_purchasing-agent-dev-only-secret"
AGENT_ID = "purchasing-agent"

requires_db = pytest.mark.skipif(not TEST_DATABASE_URL, reason="TEST_DATABASE_URL not set")

MERCHANTS = {
    "mer_biuromax": {"id": "mer_biuromax", "name": "BiuroMax", "domain": "biuromax.pl", "country": "PL",
                     "domain_registered_at": "2014-05-12", "verified": True, "reputation": {"score": 0.95, "reviews_count": 1284}},
    "mer_officehub": {"id": "mer_officehub", "name": "OfficeHub", "domain": "officehub.de", "country": "DE",
                      "domain_registered_at": "2016-09-20", "verified": True, "reputation": {"score": 0.92, "reviews_count": 2210}},
    "mer_cheapdeals": {"id": "mer_cheapdeals", "name": "CheapDeals", "domain": "cheap-office-deals.in", "country": "IN",
                       "domain_registered_at": "2020-01-10", "verified": True, "reputation": {"score": 0.6, "reviews_count": 40}},
    "mer_promocje": {"id": "mer_promocje", "name": "Promocje24", "domain": "biuro-promocje24.pl", "country": "PL",
                     "domain_registered_at": "2026-09-28", "verified": False, "reputation": None},
}


def offer(offer_id: str, merchant_id: str, sku: str, price: str, description: str = "Papier biurowy") -> dict:
    merchant = MERCHANTS[merchant_id]
    return {
        "offer_id": offer_id,
        "merchant": {"id": merchant_id, "name": merchant["name"], "domain": merchant["domain"]},
        "product": {"sku": sku, "name": sku},
        "unit_price": {"amount": price, "currency": "PLN"},
        "available_qty": 500,
        "ships_from": merchant["country"],
        "delivery_days": 2,
        "description": description,
    }


BASE_OFFERS = [
    offer("off_bm_pap", "mer_biuromax", "PAP-A4-80", "118.00"),
    offer("off_oh_pap", "mer_officehub", "PAP-A4-80", "129.00"),
]


class FakeUpstreams:
    """Magazyn, marketplace i LLM wg docs/contracts; rejestruje requesty jak dawny Recorder."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.offers = list(BASE_OFFERS)
        self.low_stock = [{"sku": "PAP-A4-80", "name": "Papier A4", "unit": "karton", "on_hand": 12, "on_order": 0,
                           "reorder_threshold": 20, "target_level": 50, "qty_needed": 38}]
        self.orders: list[dict] = []
        self.handler: Callable[[httpx.Request], httpx.Response] | None = None
        self.llm_response: dict = {"id": "chatcmpl-1", "choices": [{"message": {"role": "assistant", "content": "Hi"}}]}

    def scenario(self, name: str) -> None:
        extra = {
            "foreign_cheapest": [offer("off_cd_pap", "mer_cheapdeals", "PAP-A4-80", "61.00")],
            "fresh_domain_discount": [offer("off_pr_pap", "mer_promocje", "PAP-A4-80", "36.00")],
        }.get(name, [])
        self.offers = sorted(BASE_OFFERS + extra, key=lambda item: float(item["unit_price"]["amount"]))

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        if self.handler is not None:
            return self.handler(request)
        host, path, method = request.url.host, request.url.path, request.method
        if host == "marketplace":
            return self._marketplace(method, path, request)
        if host == "warehouse":
            return self._warehouse(method, path, request)
        if path.endswith("/chat/completions"):
            return httpx.Response(200, json=self.llm_response)
        return httpx.Response(200, json={"echo": path})

    def _marketplace(self, method: str, path: str, request: httpx.Request) -> httpx.Response:
        if method == "GET" and path == "/search":
            sku = request.url.params.get("sku")
            offers = [item for item in self.offers if sku is None or item["product"]["sku"] == sku]
            return httpx.Response(200, json={"offers": offers, "total": len(offers)})
        if method == "GET" and (match := re.fullmatch(r"/offers/([^/]+)", path)):
            found = next((item for item in self.offers if item["offer_id"] == match[1]), None)
            return httpx.Response(200, json=found) if found else httpx.Response(404, json={"error": {"code": "offer_not_found"}})
        if method == "GET" and (match := re.fullmatch(r"/merchants/([^/]+)", path)):
            merchant = MERCHANTS.get(match[1])
            return httpx.Response(200, json=merchant) if merchant else httpx.Response(404, json={"error": {"code": "merchant_not_found"}})
        if method == "POST" and path == "/orders":
            body = json.loads(request.content)
            found = next(item for item in self.offers if item["offer_id"] == body["offer_id"])
            order = {"order_id": f"ord_{len(self.orders) + 1}", "status": "confirmed", "offer_id": body["offer_id"],
                     "merchant_id": found["merchant"]["id"], "sku": found["product"]["sku"], "quantity": body["quantity"],
                     "unit_price": found["unit_price"]}
            self.orders.append(order)
            return httpx.Response(201, json=order)
        return httpx.Response(404, json={"error": {"code": "not_found"}})

    def _warehouse(self, method: str, path: str, request: httpx.Request) -> httpx.Response:
        if method == "GET" and path == "/low-stock":
            return httpx.Response(200, json={"items": self.low_stock, "generated_at": "2026-10-03T14:05:00Z"})
        if method == "POST" and path == "/purchase-orders":
            body = json.loads(request.content)
            return httpx.Response(201, json={"id": "po_1", "status": "open", **body})
        return httpx.Response(200, json={"echo": path})

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]

    def last_json(self) -> dict:
        return json.loads(self.last.content)

    def to(self, host: str) -> list[httpx.Request]:
        return [request for request in self.requests if request.url.host == host]


async def reset_database(url: str) -> None:
    conn = await asyncpg.connect(url)
    try:
        await conn.execute("drop schema if exists proxy cascade")
        for migration in MIGRATIONS:
            await conn.execute(migration.read_text())
        await conn.execute(SEED.read_text())
        await conn.execute(
            """
            update proxy.apps set upstream_url = 'http://warehouse:8000', auth_type = 'api_key_header',
                                  auth_header = 'X-Api-Key', auth_secret_env = 'WAREHOUSE_API_KEY'
             where id = 'warehouse';
            update proxy.apps set upstream_url = 'http://marketplace:8000', auth_type = 'none', auth_secret_env = null
             where id = 'marketplace';
            update proxy.apps set auth_type = 'bearer', auth_secret_env = 'BEDROCK_API_KEY', aws_region = null, aws_service = null
             where id = 'bedrock';
            insert into proxy.agent_keys (id, agent_id, sha256, hint)
            values ('dev0001', 'purchasing-agent', sha256(convert_to('ak_dev0001_purchasing-agent-dev-only-secret', 'UTF8')), 'ak_dev0001_••••cret');
            update proxy.quotas set enabled = false;
            """
        )
        await init_connection(conn)
        await store_packs(conn, [read_pack(path) for path in sorted(POLICIES_DIR.iterdir()) if path.is_dir()])
    finally:
        await conn.close()


async def execute_sql(sql: str, *args) -> None:
    conn = await asyncpg.connect(TEST_DATABASE_URL)
    try:
        await init_connection(conn)
        await conn.execute(sql, *args)
    finally:
        await conn.close()


async def fetch_sql(sql: str, *args) -> list:
    conn = await asyncpg.connect(TEST_DATABASE_URL)
    try:
        await init_connection(conn)
        return await conn.fetch(sql, *args)
    finally:
        await conn.close()


def sql(query: str, *args) -> None:
    asyncio.run(execute_sql(query, *args))


def rows(query: str, *args) -> list:
    return asyncio.run(fetch_sql(query, *args))


@pytest.fixture
def upstreams() -> FakeUpstreams:
    return FakeUpstreams()


@pytest.fixture
def recorder(upstreams: FakeUpstreams) -> FakeUpstreams:
    return upstreams


@pytest.fixture
def database(monkeypatch) -> str:
    if not TEST_DATABASE_URL:
        pytest.skip("TEST_DATABASE_URL not set")
    monkeypatch.setenv("WAREHOUSE_API_KEY", "wh-secret")
    monkeypatch.setenv("BEDROCK_API_KEY", "bedrock-key")
    asyncio.run(reset_database(TEST_DATABASE_URL))
    return TEST_DATABASE_URL


@pytest.fixture
def make_client(database: str, upstreams: FakeUpstreams) -> Iterator[Callable[..., TestClient]]:
    clients: list[TestClient] = []

    def factory(settings: Settings | None = None, scorer=None, **overrides) -> TestClient:
        defaults = {"listen_notifications": False, "background_jobs": False, "admin_auth_disabled": True}
        settings = settings or Settings(database_url=database, **{**defaults, **overrides})
        application = create_app(
            settings=settings,
            transport=httpx.MockTransport(upstreams),
            aws_credentials=Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
            scorer=scorer,
        )
        client = TestClient(application)
        client.__enter__()
        clients.append(client)
        return client

    yield factory
    for client in clients:
        client.__exit__(None, None, None)


@pytest.fixture
def client(make_client) -> TestClient:
    return make_client()


AUTH = {"Authorization": f"Bearer {DEV_KEY}"}


def open_session(client: TestClient, task: str = "restock") -> dict[str, str]:
    response = client.post("/v1/sessions", json={"task": task}, headers=AUTH)
    assert response.status_code == 201, response.text
    return {**AUTH, "X-Session-Id": response.json()["session_id"]}


def reload(client: TestClient) -> None:
    """Przebudowa snapshotu po zmianie w bazie (w testach bez LISTEN)."""
    async def run() -> None:
        async with client.app.state.db.acquire() as conn:
            client.app.state.snapshot = await load_snapshot(conn)

    client.portal.call(run)
