from fastapi import Request
from fastapi.responses import Response

from app.config.models import AppConfig
from app.core.errors import error_response
from app.upstream.client import UpstreamError


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
        return error_response(exc.status_code, "upstream_error", exc.code, exc.message)
    response = Response(content=upstream.content, status_code=upstream.status_code)
    for name, value in upstream.headers:
        response.headers.append(name, value)
    return response


def too_large_response() -> Response:
    return error_response(413, "invalid_request_error", "request_too_large", "Request body exceeds limit")
