import json

from fastapi import APIRouter, Request
from fastapi.responses import Response

from app.adapters.common import RequestTooLarge, forward, read_body, too_large_response
from app.core.errors import error_response

router = APIRouter()


@router.post("/v1/chat/completions", include_in_schema=False)
async def chat_completions(request: Request) -> Response:
    llm = request.app.state.snapshot.llm
    if llm is None:
        return error_response(503, "upstream_error", "llm_not_configured", "No LLM upstream is configured")

    try:
        body = await read_body(request, request.app.state.settings.max_request_bytes)
    except RequestTooLarge:
        return too_large_response()

    try:
        payload = json.loads(body)
    except ValueError:
        return error_response(400, "invalid_request_error", "invalid_json", "Request body must be valid JSON")
    if not isinstance(payload, dict):
        return error_response(400, "invalid_request_error", "invalid_json", "Request body must be a JSON object")
    if payload.get("stream") is True:
        return error_response(400, "invalid_request_error", "stream_not_supported", "Streaming is not supported, set stream to false")

    return await forward(request, llm, "POST", "/chat/completions", "", body)
