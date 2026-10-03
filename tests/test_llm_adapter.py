import httpx
from pydantic import SecretStr

from app.config.models import AppConfig, AuthType, Protocol, UpstreamAuth
from tests.conftest import WAREHOUSE

CHAT = {"model": "openai.gpt-oss-120b-1:0", "messages": [{"role": "user", "content": "Hello"}]}


def test_forwards_chat_completion_unchanged(make_client, recorder) -> None:
    recorder.handler = lambda request: httpx.Response(
        200, json={"id": "chatcmpl-1", "choices": [{"message": {"role": "assistant", "content": "Hi"}}]}
    )
    response = make_client().post(
        "/v1/chat/completions",
        json=CHAT,
        headers={"Authorization": "Bearer ak_k7f3a2_agentsecret"},
    )

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Hi"
    assert str(recorder.last.url) == "https://bedrock-runtime.eu-north-1.amazonaws.com/openai/v1/chat/completions"
    assert recorder.last.headers["authorization"] == "Bearer bedrock-key"
    assert recorder.last_json() == CHAT


def test_rejects_streaming(make_client, recorder) -> None:
    response = make_client().post("/v1/chat/completions", json={**CHAT, "stream": True})

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "stream_not_supported"
    assert recorder.requests == []


def test_rejects_invalid_json(make_client, recorder) -> None:
    response = make_client().post(
        "/v1/chat/completions", content=b"{not json", headers={"Content-Type": "application/json"}
    )

    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_json"


def test_no_llm_configured(make_client, recorder) -> None:
    response = make_client(WAREHOUSE).post("/v1/chat/completions", json=CHAT)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "llm_not_configured"


def test_bedrock_sigv4_signing(make_client, recorder) -> None:
    bedrock = AppConfig(
        id="bedrock",
        name="Bedrock",
        protocol=Protocol.LLM,
        upstream_url="https://bedrock-runtime.eu-north-1.amazonaws.com/openai/v1",
        timeout_seconds=60,
        auth=UpstreamAuth(type=AuthType.AWS_SIGV4, aws_region="eu-north-1", aws_service="bedrock"),
    )
    make_client(bedrock).post(
        "/v1/chat/completions",
        json=CHAT,
        headers={"Authorization": "Bearer ak_k7f3a2_agentsecret"},
    )

    sent = recorder.last.headers
    assert sent["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    assert "/eu-north-1/bedrock/aws4_request" in sent["authorization"]
    assert "x-amz-date" in sent
    assert "agentsecret" not in sent["authorization"]


def test_bearer_secret_is_not_logged_in_repr() -> None:
    auth = UpstreamAuth(type=AuthType.BEARER, secret=SecretStr("bedrock-key"))
    assert "bedrock-key" not in repr(auth)
