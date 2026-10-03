from pydantic import SecretStr

from app.config.models import AuthType, UpstreamAuth
from tests.conftest import AUTH, DEV_KEY, open_session, rows, sql

CHAT = {"model": "openai.gpt-oss-120b-1:0", "messages": [{"role": "user", "content": "Hello"}]}


def test_forwards_chat_completion_unchanged(client, upstreams) -> None:
    response = client.post("/v1/chat/completions", json=CHAT, headers=AUTH)

    assert response.status_code == 200
    assert response.json()["choices"][0]["message"]["content"] == "Hi"
    assert str(upstreams.last.url) == "https://bedrock-runtime.eu-north-1.amazonaws.com/openai/v1/chat/completions"
    assert upstreams.last.headers["authorization"] == "Bearer bedrock-key"
    assert DEV_KEY not in str(upstreams.last.headers)
    assert upstreams.last_json() == CHAT


def test_requires_agent_key(client, upstreams) -> None:
    assert client.post("/v1/chat/completions", json=CHAT).status_code == 401
    assert upstreams.requests == []


def test_rejects_streaming(client, upstreams) -> None:
    response = client.post("/v1/chat/completions", json={**CHAT, "stream": True}, headers=AUTH)
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "stream_not_supported"
    assert upstreams.requests == []


def test_rejects_invalid_json(client) -> None:
    response = client.post(
        "/v1/chat/completions", content=b"{not json", headers={**AUTH, "Content-Type": "application/json"}
    )
    assert response.status_code == 400
    assert response.json()["error"]["code"] == "invalid_json"


def test_model_allowlist(make_client, upstreams) -> None:
    sql("update proxy.agents set llm_models = '{qwen3:8b}' where id = 'purchasing-agent'")
    client = make_client()
    response = client.post("/v1/chat/completions", json=CHAT, headers=AUTH)
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "model_not_allowed"
    assert client.post("/v1/chat/completions", json={**CHAT, "model": "qwen3:8b"}, headers=AUTH).status_code == 200


def test_no_llm_configured(make_client) -> None:
    sql("update proxy.apps set enabled = false where id = 'bedrock'")
    response = make_client().post("/v1/chat/completions", json=CHAT, headers=AUTH)
    assert response.status_code == 503
    assert response.json()["error"]["code"] == "llm_not_configured"


def test_session_records_hops_and_tool_call_proposals(client, upstreams) -> None:
    headers = open_session(client)
    upstreams.llm_response = {
        "choices": [{"message": {"role": "assistant", "tool_calls": [
            {"id": "call_1", "type": "function", "function": {"name": "buy", "arguments": '{"qty": 500}'}}
        ]}}]
    }
    response = client.post("/v1/chat/completions", json=CHAT, headers=headers)
    assert response.status_code == 200
    assert response.json() == upstreams.llm_response

    hops = rows("select direction, protocol from proxy.hops where session_id = $1 order by seq", headers["X-Session-Id"])
    assert [(hop["direction"], hop["protocol"]) for hop in hops] == [("request", "llm"), ("response", "llm")]
    state = rows("select state from proxy.sessions where id = $1", headers["X-Session-Id"])[0]["state"]
    assert state["llm_tool_calls"] == [{"id": "call_1", "name": "buy", "arguments": {"qty": 500}}]
    assert rows("select count(*) as n from proxy.decisions")[0]["n"] == 0


def test_bedrock_sigv4_signing(make_client, upstreams) -> None:
    sql(
        """
        update proxy.apps set auth_type = 'aws_sigv4', auth_secret_env = null, aws_region = 'eu-north-1',
                              aws_service = 'bedrock' where id = 'bedrock'
        """
    )
    make_client().post("/v1/chat/completions", json=CHAT, headers=AUTH)

    sent = upstreams.last.headers
    assert sent["authorization"].startswith("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/")
    assert "/eu-north-1/bedrock/aws4_request" in sent["authorization"]
    assert "x-amz-date" in sent
    assert "dev-only-secret" not in sent["authorization"]


def test_bearer_secret_is_not_logged_in_repr() -> None:
    auth = UpstreamAuth(type=AuthType.BEARER, secret=SecretStr("bedrock-key"))
    assert "bedrock-key" not in repr(auth)
