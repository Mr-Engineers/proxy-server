import httpx

from tests.conftest import AUTH, open_session, rows


def test_requires_agent_key(client, upstreams) -> None:
    response = client.get("/apps/warehouse/low-stock")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "missing_agent_key"

    response = client.get("/apps/warehouse/low-stock", headers={"Authorization": "Bearer ak_dev0001_wrong"})
    assert response.status_code == 401
    assert upstreams.requests == []


def test_requires_valid_session(client, upstreams) -> None:
    response = client.get("/apps/warehouse/low-stock", headers=AUTH)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "session_required"

    response = client.get("/apps/warehouse/low-stock", headers={**AUTH, "X-Session-Id": "ses_forged"})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "invalid_session"
    assert upstreams.requests == []


def test_closed_session_is_rejected(client) -> None:
    headers = open_session(client)
    assert client.post(f"/v1/sessions/{headers['X-Session-Id']}/close", headers=AUTH).json()["status"] == "closed"
    response = client.get("/apps/warehouse/low-stock", headers=headers)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "session_closed"


def test_forwards_and_injects_upstream_credentials(client, upstreams) -> None:
    headers = open_session(client)
    response = client.get(
        "/apps/warehouse/low-stock",
        headers={**headers, "Cookie": "session=abc", "X-On-Behalf-Of": "someone-else", "X-Api-Key": "agent-provided",
                 "X-Custom": "dropped"},
    )

    assert response.status_code == 200
    assert response.json()["items"][0]["sku"] == "PAP-A4-80"
    assert response.headers["x-decision-id"].startswith("dec_")
    sent = upstreams.last.headers
    assert str(upstreams.last.url) == "http://warehouse:8000/low-stock"
    assert sent["x-api-key"] == "wh-secret"
    assert sent["x-on-behalf-of"] == "purchasing-agent"
    assert "authorization" not in sent
    assert "x-session-id" not in sent
    assert "cookie" not in sent
    assert "x-custom" not in sent


def test_forwards_body_and_idempotency_key(client, upstreams) -> None:
    headers = open_session(client)
    client.get("/apps/warehouse/low-stock", headers=headers)
    client.get("/apps/marketplace/search?sku=PAP-A4-80", headers=headers)
    response = client.post(
        "/apps/marketplace/orders",
        json={"offer_id": "off_bm_pap", "quantity": 38, "expected_unit_price": {"amount": "118.00", "currency": "PLN"}},
        headers={**headers, "Idempotency-Key": "key-1"},
    )
    assert response.status_code == 201, response.text
    order = upstreams.to("marketplace")[-1]
    assert order.url.path == "/orders"
    assert order.headers["idempotency-key"] == "key-1"
    assert upstreams.last_json()["quantity"] == 38


def test_unknown_route_is_denied(client, upstreams) -> None:
    headers = open_session(client)
    response = client.post("/apps/warehouse/admin/scenarios/x/load", json={}, headers=headers)

    assert response.status_code == 403
    body = response.json()
    assert body["status"] == "blocked"
    assert body["decision_id"].startswith("dec_")
    assert "reasons" not in body
    assert upstreams.to("warehouse") == []
    decision = rows("select tool, verdict, reasons from proxy.decisions where id = $1", body["decision_id"])[0]
    assert decision["tool"] == "warehouse.<unmatched>"
    assert decision["reasons"][0]["code"] == "unknown_route"


def test_unknown_app(client, upstreams) -> None:
    response = client.get("/apps/unknown/anything", headers=open_session(client))
    assert response.status_code == 404
    assert response.json()["error"]["code"] == "unknown_app"


def test_llm_app_not_reachable_via_rest_route(client, upstreams) -> None:
    response = client.post("/apps/bedrock/chat/completions", json={}, headers=open_session(client))
    assert response.status_code == 404
    assert upstreams.requests == []


def test_rejects_dot_segments(client, upstreams) -> None:
    response = client.get("/apps/warehouse/a/%2e%2e/admin", headers=open_session(client))
    assert response.status_code == 400
    assert upstreams.requests == []


def test_propagates_request_id(client, upstreams) -> None:
    response = client.get("/apps/warehouse/low-stock", headers={**open_session(client), "X-Request-Id": "spoofed"})
    request_id = response.headers["x-request-id"]
    assert request_id.startswith("req_")
    assert upstreams.last.headers["x-request-id"] == request_id


def test_strips_set_cookie_from_upstream(client, upstreams) -> None:
    upstreams.handler = lambda request: httpx.Response(200, json={}, headers={"Set-Cookie": "sid=x", "X-Upstream": "1"})
    response = client.get("/apps/warehouse/low-stock", headers=open_session(client))
    assert "set-cookie" not in response.headers
    assert response.headers["x-upstream"] == "1"


def test_upstream_errors(client, upstreams) -> None:
    headers = open_session(client)

    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    upstreams.handler = timeout
    response = client.get("/apps/warehouse/low-stock", headers=headers)
    assert response.status_code == 504
    assert response.json()["error"]["code"] == "upstream_timeout"

    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    upstreams.handler = refused
    response = client.get("/apps/warehouse/low-stock", headers=headers)
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_unavailable"
    statuses = [row["action_status"] for row in rows("select action_status from proxy.decisions order by created_at")]
    assert statuses == ["upstream_error", "upstream_error"]


def test_size_limits(make_client, upstreams) -> None:
    client = make_client(max_response_bytes=1024, max_request_bytes=64)
    headers = open_session(client)
    upstreams.handler = lambda request: httpx.Response(200, content=b"x" * 2048)
    assert client.get("/apps/warehouse/low-stock", headers=headers).json()["error"]["code"] == "upstream_response_too_large"

    response = client.post("/apps/warehouse/purchase-orders", content=b"x" * 128, headers=headers)
    assert response.status_code == 413
