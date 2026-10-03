from fastapi import APIRouter, Request
from fastapi.responses import Response

from app.adapters.common import RequestTooLarge, forward, read_body, too_large_response
from app.config.models import Protocol
from app.core.errors import error_response

router = APIRouter()

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


@router.api_route("/apps/{app_id}/{path:path}", methods=METHODS, include_in_schema=False)
async def forward_to_app(app_id: str, path: str, request: Request) -> Response:
    app = request.app.state.snapshot.apps.get(app_id)
    if app is None or app.protocol != Protocol.REST:
        return error_response(404, "not_found", "unknown_app", f"App {app_id} is not configured")

    segments = path.split("/")
    if any(segment in {".", ".."} for segment in segments):
        return error_response(400, "invalid_request_error", "invalid_path", "Path must not contain . or .. segments")

    try:
        body = await read_body(request, request.app.state.settings.max_request_bytes)
    except RequestTooLarge:
        return too_large_response()

    return await forward(request, app, request.method, "/" + path, request.url.query, body)
