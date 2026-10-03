"""API agenta: sesje (ADR 0002) i long-poll approvali (ADR 0004)."""

from fastapi import APIRouter, Query, Request
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel, Field

from app.auth.agent import AgentAuthError, authenticate_request
from app.core.errors import error_response
from app.hitl.approvals import agent_view
from app.store.runtime import utcnow

router = APIRouter(prefix="/v1", tags=["Agent"])


class SessionCreate(BaseModel):
    task: str | None = Field(default=None, max_length=4000)


@router.post("/sessions", status_code=201)
async def create_session(request: Request, body: SessionCreate | None = None) -> Response:
    try:
        principal = await authenticate_request(request)
    except AgentAuthError as exc:
        return error_response(exc.status_code, "authentication_error", exc.code, exc.message)
    session = await request.app.state.store.create_session(principal.agent_id, body.task if body else None)
    return JSONResponse(
        status_code=201,
        content={
            "session_id": session["id"],
            "agent_id": session["agent_id"],
            "status": session["status"],
            "created_at": session["created_at"].isoformat(),
        },
    )


@router.post("/sessions/{session_id}/close")
async def close_session(session_id: str, request: Request) -> Response:
    try:
        principal = await authenticate_request(request)
    except AgentAuthError as exc:
        return error_response(exc.status_code, "authentication_error", exc.code, exc.message)
    store = request.app.state.store
    session = await store.get_session(session_id)
    if session is None or session["agent_id"] != principal.agent_id:
        return error_response(404, "not_found", "unknown_session", "Session not found")
    closed = await store.close_session(session_id) or session
    return JSONResponse(content={"session_id": closed["id"], "status": closed["status"]})


@router.get("/approvals/{approval_id}")
async def poll_approval(approval_id: str, request: Request, wait: int = Query(default=0, ge=0, le=30)) -> Response:
    try:
        principal = await authenticate_request(request)
    except AgentAuthError as exc:
        return error_response(exc.status_code, "authentication_error", exc.code, exc.message)
    store = request.app.state.store
    approval = await store.get_approval(approval_id)
    if approval is None or approval["agent_id"] != principal.agent_id:
        return error_response(404, "not_found", "unknown_approval", "Approval not found")

    if wait and (approval["status"] == "pending" or approval["execution_result"] is None and approval["status"] == "approved"):
        await request.app.state.notifier.wait(approval_id, wait)
        approval = await store.get_approval(approval_id)

    if approval["status"] == "pending" and approval["expires_at"] <= utcnow():
        await store.expire_due()
        approval = await store.get_approval(approval_id)

    status_code, content = agent_view(approval)
    return JSONResponse(status_code=status_code, content=content, headers={"X-Decision-Id": approval["decision_id"]})

