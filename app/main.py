import asyncio
import logging
import time
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
from uuid import uuid4

import asyncpg
import httpx
from botocore.credentials import Credentials
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response

from app import jobs
from app.adapters import agent_api, llm, rest
from app.admin.router import install as install_admin
from app.auth.agent import AgentAuthenticator
from app.config.loader import load_snapshot
from app.config.models import ConfigSnapshot
from app.core.logging import configure_logging
from app.core.settings import Settings, get_settings
from app.db.dsn import parse_database_url
from app.hitl.approvals import ApprovalNotifier, ApprovalService, listen
from app.pipeline.engine import DecisionPipeline
from app.pipeline.enrichment import HttpEnricher
from app.pipeline.jev import JevScorer
from app.pipeline.ml import MlScorer, NullScorer
from app.store.runtime import RuntimeStore, init_connection
from app.upstream.auth import Authenticator
from app.upstream.client import UpstreamClient

REQUEST_ID_HEADER = "X-Request-Id"

logger = logging.getLogger("proxy.http")


def default_scorer(settings: Settings) -> MlScorer:
    key = settings.typesafe_api_key.get_secret_value() if settings.typesafe_api_key else ""
    if not key.strip():
        return NullScorer()
    return JevScorer(
        api_key=key.strip(),
        model=settings.typesafe_model,
        timeout_seconds=settings.jev_timeout_seconds,
    )


def create_app(
    settings: Settings | None = None,
    snapshot: ConfigSnapshot | None = None,
    transport: httpx.AsyncBaseTransport | None = None,
    aws_credentials: Credentials | None = None,
    scorer: MlScorer | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    scorer = scorer if scorer is not None else default_scorer(settings)

    @asynccontextmanager
    async def lifespan(application: FastAPI) -> AsyncIterator[None]:
        application.state.settings = settings
        password = settings.database_password.get_secret_value() if settings.database_password else None
        params = parse_database_url(settings.database_url, password)
        try:
            pool = await asyncpg.create_pool(
                min_size=1, max_size=settings.db_pool_max_size, init=init_connection, **params.as_kwargs()
            )
        except Exception as exc:
            logger.error(
                "database_connect_failed",
                extra={"fields": params.describe() | {"error": type(exc).__name__, "detail": str(exc)}},
            )
            raise
        if snapshot is None:
            async with pool.acquire() as conn:
                application.state.snapshot = await load_snapshot(conn)
        else:
            application.state.snapshot = snapshot

        logger.info(
            "startup",
            extra={
                "fields": {
                    "config_revision": application.state.snapshot.revision,
                    "apps": sorted(application.state.snapshot.apps),
                    "agents": sorted(application.state.snapshot.agents),
                    "policy_packs": sorted(application.state.snapshot.policy_packs),
                    "log_bodies": settings.log_bodies,
                }
            },
        )

        listener = None
        tasks: list[asyncio.Task] = []
        reload_task: asyncio.Task | None = None

        async def reload(revision: str) -> None:
            await asyncio.sleep(settings.config_reload_debounce_seconds)
            try:
                async with pool.acquire() as conn:
                    new_snapshot = await load_snapshot(conn)
            except Exception as exc:
                logger.error("config_reload_failed", extra={"fields": {"revision": revision, "error": str(exc)}})
                return
            if new_snapshot.revision >= application.state.snapshot.revision:
                application.state.snapshot = new_snapshot
                logger.info("config_reloaded", extra={"fields": {"config_revision": new_snapshot.revision}})

        def on_config(revision: str) -> None:
            nonlocal reload_task
            if snapshot is not None:
                return
            if reload_task is not None and not reload_task.done():
                reload_task.cancel()
            reload_task = asyncio.get_running_loop().create_task(reload(revision))

        application.state.reload_config = lambda: reload("manual")

        async with httpx.AsyncClient(transport=transport, follow_redirects=False) as http:
            upstream = UpstreamClient(http, Authenticator(aws_credentials), settings.max_response_bytes)
            store = RuntimeStore(pool)
            application.state.upstream = upstream
            application.state.store = store
            application.state.db = pool
            application.state.agent_auth = AgentAuthenticator()
            application.state.scorer = scorer
            application.state.enricher = HttpEnricher(upstream)
            application.state.pipeline = DecisionPipeline(store, application.state.enricher, application.state.scorer)
            application.state.notifier = ApprovalNotifier()
            application.state.approvals = ApprovalService(application)
            try:
                if settings.listen_notifications:
                    listener = await listen(application, params.as_kwargs(), on_config)
                if settings.background_jobs:
                    tasks = jobs.start(application)
                yield
            finally:
                for task in tasks:
                    task.cancel()
                if reload_task is not None:
                    reload_task.cancel()
                if listener is not None:
                    await listener.close()
                close = getattr(application.state.scorer, "aclose", None)
                if close is not None:
                    await close()
                await pool.close()

    application = FastAPI(
        title="proxy-server",
        description="Security proxy for agent-to-LLM, agent-to-app, agent-to-MCP and agent-to-agent traffic.",
        version="0.2.0",
        lifespan=lifespan,
    )
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_methods=["*"],
        allow_headers=["*"],
        allow_credentials=True,
    )

    @application.middleware("http")
    async def request_id(request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        request.state.request_id = f"req_{uuid4().hex}"
        started = time.perf_counter()
        fields = {
            "request_id": request.state.request_id,
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
        fields |= {
            "session_id": getattr(request.state, "session_id", None),
            "agent_id": getattr(request.state, "agent_id", None),
            "status": response.status_code,
            "latency_ms": round((time.perf_counter() - started) * 1000, 1),
        }
        if request.url.path != "/health":
            logger.info("http_request", extra={"fields": fields})
        response.headers[REQUEST_ID_HEADER] = request.state.request_id
        return response

    @application.get("/health", tags=["Health"])
    async def health(request: Request) -> dict:
        return {"status": "ok", "config_revision": request.app.state.snapshot.revision}

    application.include_router(agent_api.router)
    application.include_router(llm.router)
    application.include_router(rest.router)
    install_admin(application)
    return application


app = create_app()
