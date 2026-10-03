"""Adapter LLM (hop A): tylko obserwacja (ADR 0005).

Agent musi się uwierzytelnić; model musi być na liście agenta (`llm_models`, pusta = dowolny).
Z `X-Session-Id`: zapis hopów, skan wejścia (indirect injection) i propozycji `tool_calls` do stanu sesji.
"""

import json
from typing import Any

from fastapi import APIRouter, Request
from fastapi.responses import Response

from app import gateway
from app.adapters.common import RequestTooLarge, forward, read_body, too_large_response
from app.auth.agent import AgentAuthError, authenticate_request
from app.core.errors import error_response
from app.store.runtime import SessionError

router = APIRouter()

MAX_TOOL_CALLS = 50


def _input_texts(payload: dict[str, Any]) -> list[str]:
    texts = []
    for message in payload.get("messages") or []:
        if not isinstance(message, dict) or message.get("role") in ("system", "assistant"):
            continue
        content = message.get("content")
        if isinstance(content, str):
            texts.append(content)
        elif isinstance(content, list):
            texts.extend(part.get("text", "") for part in content if isinstance(part, dict) and part.get("type") == "text")
    return [text for text in texts if text]


def _tool_calls(response: Any) -> list[dict[str, Any]]:
    calls = []
    if not isinstance(response, dict):
        return calls
    for choice in response.get("choices") or []:
        message = choice.get("message") if isinstance(choice, dict) else None
        for call in (message or {}).get("tool_calls") or []:
            function = call.get("function") or {}
            arguments = function.get("arguments")
            try:
                arguments = json.loads(arguments) if isinstance(arguments, str) else arguments
            except ValueError:
                pass
            calls.append({"id": call.get("id"), "name": function.get("name"), "arguments": arguments})
    return calls


@router.post("/v1/chat/completions", include_in_schema=False)
async def chat_completions(request: Request) -> Response:
    state = request.app.state
    try:
        principal = await authenticate_request(request)
    except AgentAuthError as exc:
        return error_response(exc.status_code, "authentication_error", exc.code, exc.message)

    llm = state.snapshot.llm
    if llm is None:
        return error_response(503, "upstream_error", "llm_not_configured", "No LLM upstream is configured")

    try:
        body = await read_body(request, state.settings.max_request_bytes)
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
    models = principal.agent.llm_models
    if models and payload.get("model") not in models:
        return error_response(403, "permission_error", "model_not_allowed", "Model is not allowed for this agent")

    session_id = request.headers.get("x-session-id")
    if session_id:
        try:
            await state.store.require_session(session_id, principal.agent_id)
        except SessionError as exc:
            return error_response(exc.status_code, "session_error", exc.code, exc.message)
        request.state.session_id = session_id
        await state.store.insert_hop(
            session_id=session_id, agent_id=principal.agent_id, direction="request", protocol="llm", app_id=llm.id,
            action="llm.chat_completions", http_method="POST", http_path="/chat/completions",
            payload={"model": payload.get("model"), "body": gateway.body_payload(body, request.app),
                     "request_id": request.state.request_id},
        )

    response = await forward(request, llm, "POST", "/chat/completions", "", body)

    if session_id:
        content = getattr(response, "body", b"")
        parsed = None
        try:
            parsed = json.loads(content) if content else None
        except ValueError:
            pass
        await state.store.insert_hop(
            session_id=session_id, agent_id=principal.agent_id, direction="response", protocol="llm", app_id=llm.id,
            action="llm.chat_completions", http_method="POST", http_path="/chat/completions",
            payload={"status": response.status_code, "body": gateway.body_payload(content, request.app)},
            upstream_status=response.status_code,
        )
        calls = _tool_calls(parsed)
        signals = await state.scorer.scan(_input_texts(payload))
        if calls or signals:
            def update(current: dict) -> dict:
                new_state = dict(current)
                if calls:
                    new_state["llm_tool_calls"] = (list(current.get("llm_tool_calls") or []) + calls)[-MAX_TOOL_CALLS:]
                if signals:
                    history = list(current.get("signals") or [])
                    history.append({"tool": "llm.input", "request_id": request.state.request_id, **signals})
                    new_state["signals"] = history[-50:]
                return new_state

            await state.store.update_state(session_id, update)
    return response
