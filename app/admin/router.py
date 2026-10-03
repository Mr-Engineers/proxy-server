"""Control-plane API dla one-frontend: `/api/v1`, JWT Supabase, błędy `{detail}`."""

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

from app.admin import agents, approvals, audit, mcp, overview, policies, roles, sessions, settings
from app.admin.auth import require_operator

PREFIX = "/api/v1"


def _specialists() -> APIRouter:
    router = APIRouter(prefix="/specialists", tags=["Specialists"])

    @router.get("")
    async def list_specialists(request: Request) -> dict:
        return {"items": request.app.state.scorer.describe(), "nextCursor": None}

    @router.get("/{specialist_id}")
    async def get_specialist(specialist_id: str, request: Request) -> dict:
        item = next((item for item in request.app.state.scorer.describe() if item.get("id") == specialist_id), None)
        if item is None:
            raise HTTPException(404, "Unknown specialist")
        return item

    return router


def _simulator() -> APIRouter:
    router = APIRouter(prefix="/simulator", tags=["Simulator"])

    @router.api_route("/{path:path}", methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
    async def not_implemented(path: str) -> None:
        raise HTTPException(501, "Simulator is not implemented yet")

    return router


def install(application: FastAPI) -> None:
    api = APIRouter(prefix=PREFIX, dependencies=[Depends(require_operator)])
    for module in (overview, agents, approvals, audit, roles, mcp, policies, settings, sessions):
        api.include_router(module.router)
    api.include_router(_specialists())
    api.include_router(_simulator())
    application.include_router(api)

    @application.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        if request.url.path.startswith(PREFIX):
            first = exc.errors()[0] if exc.errors() else {}
            location = ".".join(str(part) for part in first.get("loc", ()) if part != "body")
            return JSONResponse(status_code=400, content={"detail": f"{location}: {first.get('msg', 'invalid request')}"})
        return JSONResponse(status_code=422, content={"detail": exc.errors()})
