from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from uuid import uuid4

import asyncpg
import httpx
from botocore.credentials import Credentials
from fastapi import FastAPI, Request
from fastapi.responses import Response

from app.adapters import llm, rest
from app.config.loader import load_snapshot
from app.config.models import ConfigSnapshot
from app.core.settings import Settings, get_settings
from app.upstream.auth import Authenticator
from app.upstream.client import UpstreamClient

REQUEST_ID_HEADER = "X-Request-Id"


def create_app(
    settings: Settings | None = None,
    snapshot: ConfigSnapshot | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    aws_credentials: Credentials | None = None,
) -> FastAPI:
    settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.settings = settings
        pool = None
        if snapshot is None:
            pool = await asyncpg.create_pool(settings.database_url, min_size=1, max_size=5)
            async with pool.acquire() as conn:
                application.state.snapshot = await load_snapshot(conn)
        else:
            application.state.snapshot = snapshot
        application.state.db = pool

        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as http:
            application.state.upstream = UpstreamClient(
                http,
                Authenticator(aws_credentials),
                settings.max_response_bytes,
            )
            try:
                yield
            finally:
                if pool is not None:
                    await pool.close()

    application = FastAPI(
        title="proxy-server",
        description="Security proxy for agent-to-LLM, agent-to-app, agent-to-MCP and agent-to-agent traffic.",
        version="0.1.0",
        lifespan=lifespan,
    )

    @application.middleware("http")
    async def request_id(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request.state.request_id = f"req_{uuid4().hex}"
        response = await call_next(request)
        response.headers[REQUEST_ID_HEADER] = request.state.request_id
        return response

    @application.get("/health", tags=["Health"])
    async def health(request: Request) -> dict:
        return {"status": "ok", "config_revision": request.app.state.snapshot.revision}

    application.include_router(llm.router)
    application.include_router(rest.router)
    return application


app = create_app()
