# Migracje — schema `proxy`

Czysty SQL (PostgreSQL ≥ 13), uruchamiany w kolejności numerów. Działa na Supabase i na dowolnym Postgresie u klienta.

| Plik | Zakres |
|---|---|
| `0001_config.sql` | konfiguracja edytowana z UI: agenci, klucze, aplikacje, toole, uprawnienia, pakiety polityk, ustawienia; wersjonowanie i historia zmian |
| `0002_runtime.sql` | stan działania: sesje, hopy (audyt), decyzje, approvale, rejestr wydatków |
| `0003_aws_sigv4_auth.sql` | uwierzytelnianie upstreamu przez AWS SigV4 (Bedrock z rolą IAM) |
| `0004_pipeline.sql` | role (RBAC), reguły UI, kwoty, redakcja, operatorzy, kolumny audytu w `decisions` (`chain`, `tool`, `args_redacted`, `action_status`), `rate_limited`, temporary grants |

## Uruchomienie

```bash
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/0001_config.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/0002_runtime.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/0003_aws_sigv4_auth.sql
psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -f migrations/0004_pipeline.sql
```

## Mechanizmy

- **Rewizja konfiguracji** — każda zmiana w tabelach konfiguracji podbija `proxy.config_revision.revision` i wysyła `NOTIFY proxy_config, '<revision>'`. Proxy nasłuchuje (`LISTEN`), przebudowuje snapshot w pamięci i podmienia go atomowo.
- **Historia zmian** — `proxy.config_changes` zapisuje każdą zmianę (stary i nowy wiersz, bez zaszyfrowanych sekretów). Autor z `set local proxy.actor = '<user>'` ustawianego przez admin API w transakcji.
- **Approvale** — zmiana statusu wysyła `NOTIFY proxy_approvals, '<approval_id>'`, z którego korzysta long-poll (`GET /v1/approvals/{id}?wait=30`).
- **Dostęp** — RLS włączone, uprawnienia ról `anon` / `authenticated` (Supabase) odebrane. Schema dostępna tylko dla proxy (połączenie bezpośrednie), nie przez PostgREST. Front korzysta z admin API proxy.
- **Audyt niezależny od konfiguracji** — `hops`, `approvals`, `spend_ledger` przechowują `agent_id` / `app_id` jako tekst bez kluczy obcych do konfiguracji; usunięcie agenta lub aplikacji nie usuwa historii.
