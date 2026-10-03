# proxy-server

Security proxy — jedyny punkt wyjścia agenta. Ruch do LLM, aplikacji, MCP i innych agentów przechodzi przez proxy.

Dokumentacja architektury: [`../docs`](../docs/README.md).

## Stan

Krok 1 — przezroczyste proxy:

| Endpoint | Upstream |
|---|---|
| `POST /v1/chat/completions` | aplikacja z `protocol = 'llm'` (Amazon Bedrock, OpenAI-compatible) |
| `GET/POST/PUT/PATCH/DELETE /apps/{app_id}/{path}` | aplikacja z `protocol = 'rest'` → `upstream_url + /{path}` |
| `GET /health` | — |

Bez uwierzytelniania agentów, sesji, audytu i pipeline'u decyzyjnego (kolejne kroki).

### Zachowanie

- Konfiguracja aplikacji wczytywana z `proxy.apps` przy starcie.
- Proxy usuwa z requestu agenta: `Authorization`, `Cookie`, `X-Session-Id`, `X-Request-Id`, `X-On-Behalf-Of`, nagłówki hop-by-hop i wymienione w `Connection`.
- Proxy dokłada poświadczenia upstreamu (`bearer`, `api_key_header`, `basic`, `aws_sigv4`) i `X-Request-Id` (zwracany też agentowi).
- Z odpowiedzi usuwa `Set-Cookie` i nagłówki hop-by-hop.
- LLM: `stream: true` → `400 stream_not_supported`.
- Błędy upstreamu: `502 upstream_unavailable`, `504 upstream_timeout`, `502 upstream_response_too_large`; format `{"error": {"type", "code", "message"}}`.

### Logi

JSON na stdout (CloudWatch na ECS), jedna linia na zdarzenie:

| `event` | Kiedy | Pola |
|---|---|---|
| `http_request` | każdy request do proxy (poza `/health`) | `request_id`, `session_id`, `method`, `path`, `status`, `latency_ms` |
| `upstream_exchange` | każde wywołanie upstreamu | `request_id`, `session_id`, `protocol`, `app`, `path`, `status`, `upstream_latency_ms`, `error`; dla LLM `model`, `usage`; przy `LOG_BODIES=true` `request_body`, `response_body` |
| `startup` | start proxy | `config_revision`, `apps` |

- `request_id` łączy wpisy jednego requestu; `session_id` (z nagłówka `X-Session-Id`, na razie podawany przez agenta, niezweryfikowany) łączy wszystkie requesty jednego zadania.
- `LOG_BODIES` (domyślnie `true`) — treść requestów i odpowiedzi, przycinana do `LOG_BODY_MAX_CHARS`. Zawiera prompty i dane — wyłączyć poza dev.
- Nagłówki (w tym poświadczenia) nie są logowane.

CloudWatch Logs Insights — cała sesja:

```
fields @timestamp, event, app, path, status, request_body, response_body
| filter session_id = "ses_..."
| sort @timestamp asc
```

### Bedrock

Endpoint: `https://bedrock-runtime.{region}.amazonaws.com/openai/v1/chat/completions`.

| Uwierzytelnianie | Konfiguracja `proxy.apps` |
|---|---|
| Klucz API Bedrock | `auth_type = 'bearer'`, `auth_secret_env = 'BEDROCK_API_KEY'` |
| IAM (SigV4) — zalecane na ECS | `auth_type = 'aws_sigv4'`, `aws_region = 'eu-north-1'`, `aws_service = 'bedrock'`; poświadczenia z łańcucha AWS (rola taska ECS, env, profil) |

## Uruchomienie

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/0001_config.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/0002_runtime.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/0003_aws_sigv4_auth.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f seeds/dev.sql

uvicorn app.main:app --reload --port 8080
```

```bash
curl -s localhost:8080/apps/warehouse/low-stock
curl -s localhost:8080/v1/chat/completions -H 'Content-Type: application/json' \
  -d '{"model": "openai.gpt-oss-120b-1:0", "messages": [{"role": "user", "content": "Hello"}]}'
```

## Testy

```bash
pytest
TEST_DATABASE_URL=postgresql://... pytest
```

Bez `TEST_DATABASE_URL` test wczytywania konfiguracji z Postgresa jest pomijany. Uwaga: test usuwa i odtwarza schema `proxy` w podanej bazie — używać tylko bazy testowej.
