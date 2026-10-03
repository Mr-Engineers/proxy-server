import json
import logging

from fastapi import Request
from fastapi.responses import Response

from app.config.models import AppConfig, Protocol
from app.core.errors import error_response
from app.core.logging import render_body
from app.upstream.client import UpstreamError, UpstreamResponse

logger = logging.getLogger("proxy.upstream")


class RequestTooLarge(Exception):
    pass


async def read_body(request: Request, limit: int) -> bytes:
    declared = request.headers.get("content-length")
    if declared is not None and declared.isdigit() and int(declared) > limit:
        raise RequestTooLarge
    body = await request.body()
    if len(body) > limit:
        raise RequestTooLarge
    return body


def _json_field(raw: bytes, key: str) -> object:
    try:
        payload = json.loads(raw)
    except ValueError:
        return None
    return payload.get(key) if isinstance(payload, dict) else None


def _log_exchange(
    request: Request,
    app: AppConfig,
    method: str,
    path: str,
    query: str,
    body: bytes,
    upstream: UpstreamResponse | None,
    error: UpstreamError | None,
) -> None:
    settings = request.app.state.settings
    fields: dict[str, object] = {
        "request_id": request.state.request_id,
        "session_id": getattr(request.state, "session_id", None),
        "agent_id": getattr(request.state, "agent_id", None),
        "protocol": app.protocol.value,
        "app": app.id,
        "method": method,
        "path": path,
        "query": query or None,
        "request_bytes": len(body),
    }
    if upstream is not None:
        fields |= {
            "status": upstream.status_code,
            "upstream_latency_ms": round(upstream.latency_ms, 1),
            "response_bytes": len(upstream.content),
        }
    if error is not None:
        fields |= {"status": error.status_code, "error": error.code}
    if app.protocol == Protocol.LLM:
        fields["model"] = _json_field(body, "model")
        if upstream is not None:
            fields["usage"] = _json_field(upstream.content, "usage")
    if settings.log_bodies:
        fields["request_body"] = render_body(body, settings.log_body_max_chars)
        if upstream is not None:
            fields["response_body"] = render_body(upstream.content, settings.log_body_max_chars)

    level = logging.WARNING if error is not None else logging.INFO
    logger.log(level, "upstream_exchange", extra={"fields": fields})


async def forward(request: Request, app: AppConfig, method: str, path: str, query: str, body: bytes) -> Response:
    try:
        upstream = await request.app.state.upstream.send(
            app,
            method,
            path,
            query,
            request.headers.items(),
            body,
            request.state.request_id,
        )
    except UpstreamError as exc:
        _log_exchange(request, app, method, path, query, body, None, exc)
        return error_response(exc.status_code, "upstream_error", exc.code, exc.message)

    _log_exchange(request, app, method, path, query, body, upstream, None)
    response = Response(content=upstream.content, status_code=upstream.status_code)
    for name, value in upstream.headers:
        response.headers.append(name, value)
    return response


def too_large_response() -> Response:
    return error_response(413, "invalid_request_error", "request_too_large", "Request body exceeds limit")
