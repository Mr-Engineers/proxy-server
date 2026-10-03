"""Wykonanie dozwolonej akcji — wspólne dla hopu B (ALLOW) i wykonania zatwierdzonego approvala."""

import logging
from dataclasses import dataclass
from typing import Any

from fastapi import FastAPI

from app.config.models import AppConfig, ToolConfig
from app.core.logging import render_body
from app.pipeline.catalog import apply_capture, parse_json, scan_texts
from app.upstream.client import UpstreamError, UpstreamResponse

logger = logging.getLogger("proxy.gateway")

FORWARDED_HEADERS = {"content-type", "accept", "idempotency-key", "accept-language"}


@dataclass
class StoredRequest:
    app_id: str
    tool: str
    method: str
    path: str
    query: str
    headers: list[tuple[str, str]]
    body: bytes

    def to_json(self) -> dict[str, Any]:
        return {
            "app_id": self.app_id,
            "tool": self.tool,
            "method": self.method,
            "path": self.path,
            "query": self.query,
            "headers": [list(item) for item in self.headers],
            "body": self.body.decode("utf-8", errors="surrogateescape"),
        }

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "StoredRequest":
        return cls(
            app_id=data["app_id"],
            tool=data["tool"],
            method=data["method"],
            path=data["path"],
            query=data.get("query", ""),
            headers=[tuple(item) for item in data.get("headers", [])],
            body=data.get("body", "").encode("utf-8", errors="surrogateescape"),
        )


def keep_headers(headers: list[tuple[str, str]]) -> list[tuple[str, str]]:
    return [(name, value) for name, value in headers if name.lower() in FORWARDED_HEADERS]


def body_payload(raw: bytes, application: FastAPI) -> Any:
    return render_body(raw, application.state.settings.audit_body_max_chars)


async def execute(
    application: FastAPI,
    *,
    app: AppConfig,
    tool: ToolConfig,
    stored: StoredRequest,
    decision_id: str,
    session_id: str,
    agent_id: str,
    request_id: str,
    request_doc: dict[str, Any],
    facts: dict[str, Any],
    record_spend: bool = False,
) -> UpstreamResponse | UpstreamError:
    store = application.state.store
    try:
        upstream = await application.state.upstream.send(
            app, stored.method, stored.path, stored.query, stored.headers, stored.body, request_id,
            extra_headers={"X-On-Behalf-Of": agent_id},
        )
    except UpstreamError as exc:
        logger.warning("upstream_exchange", extra={"fields": {
            "request_id": request_id, "session_id": session_id, "agent_id": agent_id, "app": app.id,
            "method": stored.method, "path": stored.path, "status": exc.status_code, "error": exc.code}})
        await store.insert_hop(
            session_id=session_id, agent_id=agent_id, direction="response", protocol=app.protocol.value,
            app_id=app.id, tool_id=tool.id, action=tool.qualified, http_method=stored.method, http_path=stored.path,
            payload={"error": exc.code, "message": exc.message, "decision_id": decision_id},
            upstream_status=exc.status_code,
        )
        await store.set_decision_status(decision_id, "upstream_error", exc.status_code, exc.status_code)
        return exc

    response_doc = parse_json(upstream.content)
    fields = {
        "request_id": request_id, "session_id": session_id, "agent_id": agent_id, "decision_id": decision_id,
        "protocol": app.protocol.value, "app": app.id, "method": stored.method, "path": stored.path,
        "status": upstream.status_code, "upstream_latency_ms": round(upstream.latency_ms, 1),
    }
    if application.state.settings.log_bodies:
        limit = application.state.settings.log_body_max_chars
        fields |= {"request_body": render_body(stored.body, limit), "response_body": render_body(upstream.content, limit)}
    logger.info("upstream_exchange", extra={"fields": fields})
    await store.insert_hop(
        session_id=session_id, agent_id=agent_id, direction="response", protocol=app.protocol.value,
        app_id=app.id, tool_id=tool.id, action=tool.qualified, http_method=stored.method, http_path=stored.path,
        payload={"status": upstream.status_code, "body": body_payload(upstream.content, application), "decision_id": decision_id},
        upstream_status=upstream.status_code, upstream_latency_ms=upstream.latency_ms,
    )
    ok = 200 <= upstream.status_code < 300
    await store.set_decision_status(decision_id, "executed" if ok else "upstream_error", upstream.status_code, upstream.status_code)

    if ok:
        signals = {}
        texts = scan_texts(tool, response_doc)
        if texts:
            try:
                signals = await application.state.scorer.scan(texts)
            except Exception:
                logger.exception("scan_failed", extra={"fields": {"tool": tool.qualified}})

        def update(state: dict) -> dict:
            new_state = apply_capture(state, tool, request_doc, response_doc)
            if signals:
                history = list(new_state.get("signals") or [])
                history.append({"tool": tool.qualified, "decision_id": decision_id, **signals})
                new_state["signals"] = history[-50:]
            return new_state

        if tool.capture or signals:
            await store.update_state(session_id, update)

        if record_spend and facts.get("order_value_minor") and facts.get("currency"):
            await store.record_spend(agent_id, app.id, decision_id, facts["order_value_minor"], facts["currency"])
    return upstream
