import json
import logging

import httpx

from app.core.logging import JsonFormatter, render_body
from app.core.settings import Settings
from tests.conftest import BEDROCK, WAREHOUSE


def _records(caplog, event: str) -> list[dict]:
    return [record.fields for record in caplog.records if record.getMessage() == event]


def test_logs_llm_exchange_with_bodies_and_correlation(make_client, recorder, caplog) -> None:
    caplog.set_level(logging.INFO)
    recorder.handler = lambda request: httpx.Response(
        200, json={"choices": [{"message": {"content": "Hi"}}], "usage": {"total_tokens": 12}}
    )
    response = make_client().post(
        "/v1/chat/completions",
        json={"model": "qwen.qwen3-32b-v1:0", "messages": [{"role": "user", "content": "Hello"}]},
        headers={"Authorization": "Bearer ak_k7f3a2_agentsecret", "X-Session-Id": "ses_1"},
    )

    exchange = _records(caplog, "upstream_exchange")[-1]
    http = _records(caplog, "http_request")[-1]
    assert exchange["request_id"] == http["request_id"] == response.headers["x-request-id"]
    assert exchange["session_id"] == http["session_id"] == "ses_1"
    assert exchange["protocol"] == "llm"
    assert exchange["model"] == "qwen.qwen3-32b-v1:0"
    assert exchange["usage"] == {"total_tokens": 12}
    assert exchange["request_body"]["messages"][0]["content"] == "Hello"
    assert exchange["response_body"]["choices"][0]["message"]["content"] == "Hi"
    assert http["status"] == 200
    assert "agentsecret" not in json.dumps(caplog.records[-1].fields) + json.dumps(exchange)
    assert "bedrock-key" not in json.dumps(exchange)


def test_logs_upstream_error(make_client, recorder, caplog) -> None:
    caplog.set_level(logging.INFO)

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    recorder.handler = refused
    make_client().get("/apps/warehouse/low-stock")

    exchange = _records(caplog, "upstream_exchange")[-1]
    assert exchange["status"] == 502
    assert exchange["error"] == "upstream_unavailable"
    assert "response_body" not in exchange


def test_bodies_disabled(make_client, recorder, caplog) -> None:
    caplog.set_level(logging.INFO)
    make_client(WAREHOUSE, BEDROCK, settings=Settings(log_bodies=False)).post(
        "/apps/warehouse/purchase-orders", json={"sku": "PAP-A4-80"}
    )

    exchange = _records(caplog, "upstream_exchange")[-1]
    assert "request_body" not in exchange
    assert "response_body" not in exchange


def test_render_body_truncates_and_parses() -> None:
    assert render_body(b"", 10) is None
    assert render_body(b'{"a": 1}', 100) == {"a": 1}
    assert render_body(b"plain", 100) == "plain"
    assert render_body(b"x" * 20, 5) == {"truncated": True, "bytes": 20, "preview": "xxxxx"}


def test_json_formatter() -> None:
    record = logging.LogRecord("proxy.http", logging.INFO, __file__, 1, "http_request", None, None)
    record.fields = {"request_id": "req_1", "status": 200}
    line = json.loads(JsonFormatter().format(record))
    assert line["event"] == "http_request"
    assert line["level"] == "info"
    assert line["request_id"] == "req_1"
