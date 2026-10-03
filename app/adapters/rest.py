"""Adapter REST (hop B, egzekwowanie): `/apps/{app}/...` → katalog akcji → pipeline → upstream."""

import logging

from fastapi import APIRouter, Request
from fastapi.responses import Response

from app import gateway
from app.adapters.common import RequestTooLarge, read_body, too_large_response
from app.auth.agent import AgentAuthError, authenticate_request
from app.config.models import Protocol
from app.core.errors import decision_response, error_response
from app.core.redact import redact
from app.pipeline.catalog import UNMATCHED, extract_args, match_route, request_document
from app.pipeline.engine import DecisionContext
from app.pipeline.models import Action, Verdict
from app.policy.cedar import budget_windows
from app.store.runtime import SessionError
from app.upstream.client import UpstreamError

router = APIRouter()
logger = logging.getLogger("proxy.upstream")

METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE"]


@router.api_route("/apps/{app_id}/{path:path}", methods=METHODS, include_in_schema=False)
async def forward_to_app(app_id: str, path: str, request: Request) -> Response:
    state = request.app.state
    try:
        principal = await authenticate_request(request)
    except AgentAuthError as exc:
        return error_response(exc.status_code, "authentication_error", exc.code, exc.message)

    snapshot = state.snapshot
    app = snapshot.apps.get(app_id)
    if app is None or app.protocol != Protocol.REST:
        return error_response(404, "not_found", "unknown_app", f"App {app_id} is not configured")

    segments = path.split("/")
    if any(segment in {".", ".."} for segment in segments):
        return error_response(400, "invalid_request_error", "invalid_path", "Path must not contain . or .. segments")

    try:
        body = await read_body(request, state.settings.max_request_bytes)
    except RequestTooLarge:
        return too_large_response()

    try:
        session = await state.store.require_session(request.headers.get("x-session-id"), principal.agent_id)
    except SessionError as exc:
        return error_response(exc.status_code, "session_error", exc.code, exc.message)
    session_id = session["id"]
    request.state.session_id = session_id

    method, upstream_path, query = request.method, "/" + path, request.url.query
    matched = match_route(snapshot, app_id, method, upstream_path)
    tool, path_params = matched if matched else (None, {})
    request_doc = request_document(query, path_params, body)
    action = Action(
        app=app_id,
        tool=tool.qualified if tool else f"{app_id}.{UNMATCHED}",
        kind=tool.kind if tool else ("read" if method == "GET" else "write"),
        args=extract_args(tool, request_doc) if tool else {},
        request=request_doc,
        session_id=session_id,
        agent_id=principal.agent_id,
    )

    request_id = request.state.request_id
    hop_id = await state.store.insert_hop(
        session_id=session_id, agent_id=principal.agent_id, direction="request", protocol=app.protocol.value,
        app_id=app_id, tool_id=tool.id if tool else None, action=action.tool, http_method=method,
        http_path=upstream_path,
        payload={"method": method, "path": upstream_path, "query": query or None,
                 "body": gateway.body_payload(body, request.app), "request_id": request_id},
    )

    decision = await state.pipeline.decide(
        DecisionContext(
            snapshot=snapshot, agent=principal.agent, app=app, tool=tool, action=action,
            session_state=session["state"] or {}, request_id=request_id,
        )
    )
    args_redacted = redact(action.args if tool and tool.args else request_doc, tool.redact if tool else ())
    invalid = any(reason.code == "schema_violation" for reason in decision.reasons)

    status_map = {
        Verdict.ALLOW: ("forwarded", None),
        Verdict.DENY: ("invalid" if invalid else "blocked", 400 if invalid else 403),
        Verdict.ESCALATE: ("pending_approval", 202),
        Verdict.RATE_LIMITED: ("rate_limited", 429),
    }
    action_status, http_status = status_map[decision.verdict]
    await state.store.insert_decision(
        decision, hop_id=hop_id, session_id=session_id, agent_id=principal.agent_id, app_id=app_id,
        tool=action.tool, kind=action.kind, args_redacted=args_redacted, action_status=action_status,
        http_status=http_status or 0, request_id=request_id,
    )
    logger.info(
        "decision",
        extra={"fields": {
            "request_id": request_id, "session_id": session_id, "agent_id": principal.agent_id,
            "decision_id": decision.id, "tool": action.tool, "verdict": decision.verdict.value,
            "reasons": [reason.code for reason in decision.reasons], "degraded": decision.degraded,
            "latency_ms": round(decision.latency_ms, 1),
        }},
    )

    stored = gateway.StoredRequest(
        app_id=app_id, tool=action.tool, method=method, path=upstream_path, query=query,
        headers=gateway.keep_headers(list(request.headers.items())), body=body,
    )

    if decision.verdict is Verdict.DENY:
        limit = principal.agent.limits.get("max_denies_per_session") or snapshot.settings.max_denies_per_session
        if await state.store.register_deny(session_id, limit):
            await state.store.set_decision_status(decision.id, "session_terminated", 403)
            return decision_response(403, "session_terminated", decision.id)
        if invalid:
            return decision_response(400, "invalid_arguments", decision.id)
        return decision_response(403, "blocked", decision.id)

    if decision.verdict is Verdict.RATE_LIMITED:
        retry = decision.retry_after_seconds or 1
        return decision_response(
            429, "rate_limited", decision.id, {"retry_after_seconds": retry}, headers={"Retry-After": str(retry)}
        )

    if decision.verdict is Verdict.ESCALATE:
        approval = await state.store.create_approval(
            decision_id=decision.id, session_id=session_id, agent_id=principal.agent_id, tool=action.tool,
            request=stored.to_json(), ttl_seconds=snapshot.settings.default_approval_ttl_seconds,
        )
        return decision_response(
            202, "pending_approval", decision.id,
            {"approval_id": approval["id"], "poll_url": f"/v1/approvals/{approval['id']}?wait=30",
             "expires_at": approval["expires_at"].isoformat()},
        )

    pack = snapshot.policy_packs.get(app_id)
    outcome = await gateway.execute(
        request.app, app=app, tool=tool, stored=stored, decision_id=decision.id, session_id=session_id,
        agent_id=principal.agent_id, request_id=request_id, request_doc=request_doc, facts=decision.facts,
        record_spend=bool(budget_windows(pack, principal.agent_id, tool.name)),
    )
    if isinstance(outcome, UpstreamError):
        response = error_response(outcome.status_code, "upstream_error", outcome.code, outcome.message)
    else:
        response = Response(content=outcome.content, status_code=outcome.status_code)
        for name, value in outcome.headers:
            response.headers.append(name, value)
    response.headers["X-Decision-Id"] = decision.id
    return response
