# proxy-server

Security proxy — jedyny punkt wyjścia agenta. Ruch do LLM, aplikacji, MCP i innych agentów przechodzi przez proxy.

Dokumentacja architektury: [`../docs`](../docs/README.md). Kontrakty UI: [`../docs/api`](../docs/api/README.md).

## Stan

Warstwa deterministyczna i HITL gotowe pod pierwszy use case (agent zakupowy). Specjalista: TypeSafe Jev (`JevScorer`) przy `TYPESAFE_API_KEY` — Choice clear/caution/deny na escalate/`needs_ai`; bez klucza `NullScorer` i agregator na regułach.

| Obszar | Co działa |
|---|---|
| Auth agenta (D6) | `Authorization: Bearer ak_<key_id>_<secret>`, w bazie tylko SHA-256; `status` agenta `active` / `disabled` / `revoked` |
| Sesje (D7) | `POST /v1/sessions`, `X-Session-Id` przypięte do agenta, `POST /v1/sessions/{id}/close` |
| Katalog akcji (D3) | `proxy.tools`: trasa → `app.tool`; nieznana trasa = DENY; parametry ścieżki `{id}`; `args` / `capture` / `scan` przez JSONPath |
| Pipeline (S10) | walidacja `input_schema` → kwoty → RBAC → enrichment → Cedar + reguły UI → Jev/ML → agregator → `decisions` |
| Polityki (S9) | pakiety Cedar per aplikacja (`policies/<app>/`), parametry + overrides tylko zaostrzające, grounding z sesji, budżet z `spend_ledger` |
| RBAC (P2) | role (`proxy.roles`) z grantami per tool lub całą aplikację; uprawnienia = rola ∪ `agent_permissions` |
| Reguły UI (P4) | drzewo `when` / `then`, first match wins, `allow` / `deny` / `needs_ai`; ewaluator w Pythonie |
| Kwoty (P6) | `proxy.quotas` (`1m` / `1h` / `1d`, `cap + burst`) + `limits.requests_per_minute`; `429 rate_limited` + `Retry-After` |
| HITL (S11) | `202 pending_approval`, long-poll `GET /v1/approvals/{id}?wait=30`, approve = jednokrotne wykonanie zapamiętanego requestu (hash), reject z feedbackiem, timeout → `expired`, allow-temporary, 3 odmowy → `session_terminated` |
| Hop A — LLM (D12) | tylko obserwacja: auth, allowlista modeli, hopy, `tool_calls` i skan wejścia do stanu sesji |
| Awarie (D14) | read → fail-open, write → fail-closed, `degraded` w audycie |
| Audyt (A1–A3) | jedno źródło: `proxy.decisions` (+ `hops`, `approvals`); `chain[]` w formacie UI, `args_redacted` |
| Admin API | `/api/v1` wg `docs/api` — patrz niżej |
| Konfiguracja (D17) | snapshot w pamięci, przebudowa po `NOTIFY proxy_config` (debounce), błędny snapshot = zostaje poprzedni |
| Retencja (A7) | job wg `audit.retention_days`; wygaszanie approvali co 2 s |

## Endpointy agenta

| Endpoint | Opis |
|---|---|
| `POST /v1/sessions` `{task}` | nowa sesja → `{session_id}` |
| `POST /v1/sessions/{id}/close` | zamknięcie sesji |
| `GET/POST/PUT/PATCH/DELETE /apps/{app_id}/{path}` | hop B — egzekwowanie; wymaga `X-Session-Id` |
| `POST /v1/chat/completions` | hop A — LLM (OpenAI-compatible); `X-Session-Id` opcjonalne |
| `GET /v1/approvals/{id}?wait=30` | long-poll decyzji człowieka |

Odpowiedzi decyzji (D10) — bez uzasadnień, zawsze `decision_id` (także w nagłówku `X-Decision-Id`):

| HTTP | `status` | Kiedy |
|---|---|---|
| status upstreamu | — | ALLOW |
| `403` | `blocked` | automatyczna odmowa |
| `400` | `invalid_arguments` | body niezgodne z `tools.input_schema` |
| `202` | `pending_approval` | eskalacja; `approval_id`, `poll_url`, `expires_at` |
| `429` | `rate_limited` | kwota; `retry_after_seconds` |
| `403` | `session_terminated` | limit odmów w sesji |
| `200` | `approved` / `rejected` / `expired` | wynik long-polla; `result` lub `feedback` |

## Admin API (`/api/v1`)

Auth: JWT Supabase (`SUPABASE_JWT_SECRET` dla HS256 lub `SUPABASE_URL` dla JWKS). Lokalnie `ADMIN_AUTH_DISABLED=true`. Błędy `{detail}`, walidacja → `400`. Każda zmiana konfiguracji zapisuje autora w `config_changes.changed_by`.

| Zasób | Endpointy | Kontrakt |
|---|---|---|
| Overview | `GET /overview` | [overview.md](../docs/api/overview.md) |
| Agents | `GET/POST /agents`, `GET/PATCH /agents/{id}`, `POST …/revoke`, `POST …/keys` (nowy klucz, pokazywany raz), `GET …/overview`, `GET …/posture` | [agents.md](../docs/api/agents.md) |
| Rules | `GET/POST …/rules`, `PUT/DELETE …/rules/{id}`, `GET …/rules/meta`, `POST …/rules/dry-run` (reguły + Cedar) | [agents.md](../docs/api/agents.md) |
| Quotas | `GET/POST /agents/{id}/quotas`, `PATCH /quotas/{id}` | [agents.md](../docs/api/agents.md) |
| Approvals | `GET /approvals`, `GET /approvals/{id}`, `POST …/allow`, `…/deny`, `…/allow-temporary` | [approvals.md](../docs/api/approvals.md) |
| Audit | `GET /audit`, `GET /audit/{id}` | [audit.md](../docs/api/audit.md) |
| Sessions | `GET /sessions`, `GET /sessions/{id}` (timeline) | [sessions.md](../docs/api/sessions.md) |
| Roles | `GET/POST /roles`, `GET/PATCH /roles/{id}`, `POST …/publish`, `…/archive` | [roles.md](../docs/api/roles.md) |
| MCP | `GET /mcp`, `GET /mcp/{id}`, `PATCH /mcp/{id}` (włącz/wyłącz aplikację), `PATCH /mcp/{id}/tools/{tool}` (włącz/wyłącz tool, `kind`, `scanMode`) | [mcp.md](../docs/api/mcp.md) |
| Policies | `GET /policies`, `GET/PUT /policies/{app}`, `PUT/DELETE /policies/{app}/overrides/{agent}` — walidacja przed zapisem | — |
| Settings | `GET/PATCH /settings/workspace`, operatorzy (list / invite / resend / disable / enable) | [settings.md](../docs/api/settings.md) |
| Profile | `GET /me` | [profile.md](../docs/api/profile.md) |
| Specialists | `GET /specialists` — pusta lista do czasu modeli (tor M) | [specialists.md](../docs/api/specialists.md) |
| Poza MVP → `501` | MCP attach / discover / hosted, Simulator | |

Mapowanie: proxy `escalate` = UI `caution`. `chain[]` = `{stage: rbac | rules | specialist | human, outcome, detail}`.

## Pipeline decyzyjny

```
request → auth agenta → sesja → katalog akcji (nieznana trasa → DENY)
  → hop request → walidacja input_schema → kwoty (→ rate_limited)
  → RBAC (rola ∪ bezpośrednie) → enrichment (apps.enrichment, cache)
  → Cedar (pakiet aplikacji, fakty z sesji, budżet z ledgera) + reguły UI (first match)
  → MlScorer.score (Jev gdy `TYPESAFE_API_KEY`, inaczej NullScorer) → agregator
  → allow: upstream → hop response → capture do sesji → ledger
  → deny: 403 (+ licznik odmów) · escalate: approval + 202 · rate_limited: 429
```

Agregator: `deny` z polityk jest ostateczne; specjalista (Jev Choice `clear`/`caution`/`deny` + confidence) odpala się przy Cedar `escalate` lub UI `needs_ai` i może **clear → allow**; bez modelu `needs_ai` → człowiek (gdy `specialistFailClosed`) lub allow. Progi τ w `app/pipeline/aggregator.py`.

### Wpięcie ML (tor M)

`app/pipeline/jev.py` — `JevScorer` (TypeSafe System One) za `MlScorer`. Domyślnie włączany przez `TYPESAFE_API_KEY` w `create_app`, albo wstrzyknięty `create_app(scorer=...)`. `score` dostaje akcję, mandat, sesję, enrichment, fakty i kody powodów polityk; zwraca Choice + confidence. `describe` zasila `GET /api/v1/specialists` (purchasing + dispute).

## Konfiguracja

Źródło prawdy: Postgres, schema `proxy` (ADR 0007). Pakiety polityk trzymamy też jako pliki w `policies/<app>/` (`policy.cedar`, `schema.cedarschema`, `params.json`, `params_schema.json`, `overrides.json`) — review i import do bazy.

| Typ parametru | Łączenie z override | W Cedar |
|---|---|---|
| `allowlist` | część wspólna | `Set<String>` |
| `max_money` | mniejsza | `<name>_minor`, `<name>_currency` |
| `max_number` / `min_number` | mniejsza / większa | `Long` |
| `flag` | `true` wygrywa | `Bool` |
| `budget` | mniejsza per okno | `budget_<window>_minor` |

Reguły Cedar: tylko `forbid` z `@id`, `@severity("deny" | "escalate")`, opcjonalnie `@message`. Fakty w `context` (zawsze obecne, brak danych = wartość najgorsza): `offer_seen_in_session`, `merchant_matches`, `price_matches`, `currency_matches`, `sku_needed`, `qty_ratio_pct`, `order_value_minor`, `order_seen_in_session`, `merchant_known`, `spent_<window>_minor`. Resource: `Merchant` (gdy aplikacja ma enrichment `merchant`) albo `Tool`.

## Uruchomienie

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env

psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/0004_pipeline.sql   # migracje, których baza jeszcze nie ma
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f seeds/seed.sql
python -m app.cli load-policies                  # policies/* → proxy.policy_packs
python -m app.cli create-key purchasing-agent    # → SSM /one/dev/ai-agent/AGENT_KEY

uvicorn app.main:app --reload --port 8080
```

```bash
KEY='Authorization: Bearer ak_...'   # z create-key
SID=$(curl -s -XPOST localhost:8080/v1/sessions -H "$KEY" -H 'content-type: application/json' -d '{"task":"restock"}' | jq -r .session_id)
curl -s localhost:8080/apps/warehouse/low-stock -H "$KEY" -H "X-Session-Id: $SID"
```

### CLI

| Komenda | Opis |
|---|---|
| `python -m app.cli create-key <agent_id>` | nowy klucz agenta (wypisany raz) |
| `python -m app.cli load-policies [policies/<app> ...]` | import pakietów polityk z walidacją |
| `python -m app.cli seed-demo [--sessions N]` | sesje i decyzje demo dla UI |
| `python -m app.cli retention` | jednorazowa retencja audytu |

### Seed

Jeden plik `seeds/seed.sql` (można odpalać wielokrotnie): aplikacje, katalog akcji, rola, agent `purchasing-agent`, kwota. Proxy forwarduje tylko do:

| App | Upstream | Auth |
|---|---|---|
| `bedrock` | `https://bedrock-runtime.eu-north-1.amazonaws.com/openai/v1` | SigV4 rolą taska (lokalnie `~/.aws`) |
| `warehouse` | `http://backend:8000/api/v1` (one-backend, Service Connect) | Bearer `GATEWAY_TOKEN` |
| `marketplace` | `https://one-dev-2-alb-1648560586.eu-north-1.elb.amazonaws.com` (two-backend; cert z `certs/backend-2-ca.crt`, dołożony w Dockerfile) | Bearer `MARKETPLACE_API_TOKEN` |

Klucz agenta: jeden per agent, `python -m app.cli create-key <agent_id>` (wypisany raz, w bazie tylko hash) — identyfikuje agenta. Task ECS musi mieć w env każdą zmienną z `proxy.apps.auth_secret_env`, inaczej proxy nie startuje.

### Baza danych

- `DATABASE_URL` — hasło może zawierać znaki specjalne bez kodowania; `DATABASE_PASSWORD` nadpisuje hasło z URL.
- Supabase z ECS: session pooler (LISTEN/NOTIFY wymaga połączenia sesyjnego, nie transaction poolera), użytkownik `postgres.<project_ref>`, port 5432.

### Logi

JSON na stdout, jedna linia na zdarzenie: `http_request`, `decision` (werdykt, kody powodów, `degraded`), `upstream_exchange` (przy `LOG_BODIES=true` z treścią), `config_reloaded` / `config_reload_failed`, `startup`. `request_id`, `session_id`, `agent_id` łączą wpisy. Klucze agentów i poświadczenia upstreamów nie są logowane.

## Testy

```bash
pytest                                            # jednostkowe; testy z bazą są pomijane
TEST_DATABASE_URL=postgresql://... pytest         # pełny zestaw (CI: postgres:16)
```

Testy z bazą usuwają i odtwarzają schema `proxy` przed każdym testem — tylko baza testowa.
