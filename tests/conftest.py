import json
from collections.abc import Callable, Iterator

import httpx
import pytest
from botocore.credentials import Credentials
from fastapi.testclient import TestClient
from pydantic import SecretStr

from app.config.models import AppConfig, AuthType, ConfigSnapshot, Protocol, UpstreamAuth
from app.core.settings import Settings
from app.main import create_app

WAREHOUSE = AppConfig(
    id="warehouse",
    name="Magazyn",
    protocol=Protocol.REST,
    upstream_url="http://warehouse:8000",
    timeout_seconds=5,
    auth=UpstreamAuth(type=AuthType.API_KEY_HEADER, header="X-Api-Key", secret=SecretStr("wh-secret")),
)

BEDROCK = AppConfig(
    id="bedrock",
    name="Bedrock",
    protocol=Protocol.LLM,
    upstream_url="https://bedrock-runtime.eu-north-1.amazonaws.com/openai/v1",
    timeout_seconds=60,
    auth=UpstreamAuth(type=AuthType.BEARER, secret=SecretStr("bedrock-key")),
)


class Recorder:
    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.handler: Callable[[httpx.Request], httpx.Response] = lambda request: httpx.Response(
            200, json={"echo": request.url.path}
        )

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.handler(request)

    @property
    def last(self) -> httpx.Request:
        return self.requests[-1]

    def last_json(self) -> dict:
        return json.loads(self.last.content)


@pytest.fixture
def recorder() -> Recorder:
    return Recorder()


@pytest.fixture
def make_client(recorder: Recorder) -> Iterator[Callable[..., TestClient]]:
    clients: list[TestClient] = []

    def factory(*apps: AppConfig, settings: Settings | None = None) -> TestClient:
        snapshot = ConfigSnapshot(revision=1, apps={app.id: app for app in (apps or (WAREHOUSE, BEDROCK))})
        application = create_app(
            settings=settings or Settings(),
            snapshot=snapshot,
            transport=httpx.MockTransport(recorder),
            aws_credentials=Credentials("AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"),
        )
        client = TestClient(application)
        client.__enter__()
        clients.append(client)
        return client

    yield factory
    for client in clients:
        client.__exit__(None, None, None)
