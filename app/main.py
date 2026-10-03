import logging
import time
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
from app.core.logging import configure_logging
from app.core.settings import Settings, get_settings
from app.db.dsn import parse_database_url
from app.upstream.auth import Authenticator
from app.upstream.client import UpstreamClient

REQUEST_ID_HEADER = "X-Request-Id"

logger = logging.getLogger("proxy.http")


def create_app(
    settings: Settings | None = None,
    snapshot: ConfigSnapshot | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    aws_credentials: Credentials | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.settings = settings
        pool = None
        if snapshot is None:
            password = settings.database_password.get_secret_value() if settings.database_password else None
            params = parse_database_url(settings.database_url, password)
            try:
                pool = await asyncpg.create_pool(min_size=1, max_size=5, **params.as_kwargs())
            except Exception as exc:
                logger.error(
                    "database_connect_failed",
                    extra={"fields": params.describe() | {"error": type(exc).__name__, "detail": str(exc)}},
                )
                raise
            async with pool.acquire() as conn:
                application.state.snapshot = await load_snapshot(conn)
        else:
            application.state.snapshot = snapshot
        application.state.db = pool
        logger.info(
            "startup",
            extra={
                "fields": {
                    "config_revision": application.state.snapshot.revision,
                    "apps": sorted(application.state.snapshot.apps),
                    "log_bodies": settings.log_bodies,
                }
            },
        )

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
        started = time.perf_counter()
        fields = {
            "request_id": request.state.request_id,
            "session_id": request.headers.get("x-session-id"),
            "method": request.method,
            "path": request.url.path,
            "client": request.client.host if request.client else None,
        }
        try:
            response = await call_next(request)
        except Exception:
            fields["latency_ms"] = round((time.perf_counter() - started) * 1000, 1)
            logger.exception("http_request_failed", extra={"fields": fields})
            raise
        fields |= {"status": response.status_code, "latency_ms": round((time.perf_counter() - started) * 1000, 1)}
        if request.url.path != "/health":
            logger.info("http_request", extra={"fields": fields})
        response.headers[REQUEST_ID_HEADER] = request.state.request_id
        return response

    @application.get("/health", tags=["Health"])
    async def health(request: Request) -> dict:
        return {"status": "ok", "config_revision": request.app.state.snapshot.revision}

    application.include_router(llm.router)
    application.include_router(rest.router)
    return application


app = create_app()
