import httpx

from app.core.settings import Settings
from tests.conftest import WAREHOUSE


def test_forwards_method_path_query_and_body(make_client, recorder) -> None:
    client = make_client()
    response = client.post(
        "/apps/warehouse/purchase-orders?dry_run=1&x=a%20b",
        json={"sku": "PAP-A4-80", "quantity": 38},
    )

    assert response.status_code == 200
    assert recorder.last.method == "POST"
    assert str(recorder.last.url) == "http://warehouse:8000/purchase-orders?dry_run=1&x=a%20b"
    assert recorder.last_json() == {"sku": "PAP-A4-80", "quantity": 38}


def test_returns_upstream_status_and_body(make_client, recorder) -> None:
    recorder.handler = lambda request: httpx.Response(404, json={"error": {"code": "unknown_sku"}})
    response = make_client().get("/apps/warehouse/low-stock")

    assert response.status_code == 404
    assert response.json() == {"error": {"code": "unknown_sku"}}


def test_injects_upstream_credentials_and_strips_agent_credentials(make_client, recorder) -> None:
    make_client().get(
        "/apps/warehouse/low-stock",
        headers={
            "Authorization": "Bearer ak_k7f3a2_agentsecret",
            "X-Session-Id": "ses_1",
            "Cookie": "session=abc",
            "X-On-Behalf-Of": "someone-else",
            "X-Api-Key": "agent-provided",
            "X-Custom": "kept",
        },
    )

    sent = recorder.last.headers
    assert sent["x-api-key"] == "wh-secret"
    assert "authorization" not in sent
    assert "x-session-id" not in sent
    assert "cookie" not in sent
    assert "x-on-behalf-of" not in sent
    assert sent["x-custom"] == "kept"


def test_strips_hop_by_hop_and_connection_listed_headers(make_client, recorder) -> None:
    make_client().get(
        "/apps/warehouse/low-stock",
        headers={"Connection": "keep-alive, X-Internal", "X-Internal": "1", "Keep-Alive": "timeout=5"},
    )

    sent = recorder.last.headers
    assert "x-internal" not in sent
    assert "keep-alive" not in sent


def test_propagates_request_id(make_client, recorder) -> None:
    response = make_client().get("/apps/warehouse/low-stock", headers={"X-Request-Id": "spoofed"})

    request_id = response.headers["x-request-id"]
    assert request_id.startswith("req_")
    assert recorder.last.headers["x-request-id"] == request_id


def test_strips_set_cookie_from_upstream(make_client, recorder) -> None:
    recorder.handler = lambda request: httpx.Response(
        200, json={}, headers={"Set-Cookie": "sid=service-account", "X-Upstream": "1"}
    )
    response = make_client().get("/apps/warehouse/low-stock")

    assert "set-cookie" not in response.headers
    assert response.headers["x-upstream"] == "1"


def test_unknown_app(make_client, recorder) -> None:
    response = make_client().get("/apps/unknown/anything")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "unknown_app"
    assert recorder.requests == []


def test_llm_app_not_reachable_via_rest_route(make_client, recorder) -> None:
    response = make_client().post("/apps/bedrock/chat/completions", json={})

    assert response.status_code == 404
    assert recorder.requests == []


def test_rejects_dot_segments(make_client, recorder) -> None:
    response = make_client().get("/apps/warehouse/a/%2e%2e/admin")

    assert response.status_code == 400
    assert recorder.requests == []


def test_upstream_timeout(make_client, recorder) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("timeout", request=request)

    recorder.handler = timeout
    response = make_client().get("/apps/warehouse/low-stock")

    assert response.status_code == 504
    assert response.json()["error"] == {
        "type": "upstream_error",
        "code": "upstream_timeout",
        "message": "Upstream warehouse did not respond in time",
    }


def test_upstream_unavailable(make_client, recorder) -> None:
    def refused(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    recorder.handler = refused
    response = make_client().get("/apps/warehouse/low-stock")

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_unavailable"


def test_response_too_large(make_client, recorder) -> None:
    recorder.handler = lambda request: httpx.Response(200, content=b"x" * 2048)
    response = make_client(WAREHOUSE, settings=Settings(max_response_bytes=1024)).get("/apps/warehouse/low-stock")

    assert response.status_code == 502
    assert response.json()["error"]["code"] == "upstream_response_too_large"


def test_request_too_large(make_client, recorder) -> None:
    response = make_client(WAREHOUSE, settings=Settings(max_request_bytes=16)).post(
        "/apps/warehouse/purchase-orders", content=b"x" * 64
    )

    assert response.status_code == 413
    assert recorder.requests == []
