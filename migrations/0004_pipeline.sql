-- Pipeline decyzyjny, RBAC, reguły UI, kwoty, HITL, audyt dla /api/v1.

-- ---------------------------------------------------------------------------
-- Konfiguracja: role (RBAC), reguły UI, kwoty, redakcja argumentów
-- ---------------------------------------------------------------------------

create table proxy.roles (
  id text primary key check (id ~ '^[a-z0-9][a-z0-9_-]{1,62}$'),
  name text not null,
  description text not null default '',
  status text not null default 'draft' check (status in ('active', 'draft', 'archived')),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table proxy.role_grants (
  role_id text not null references proxy.roles (id) on delete cascade,
  tool_id uuid not null references proxy.tools (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (role_id, tool_id)
);

create index role_grants_tool_id_idx on proxy.role_grants (tool_id);

-- Dostęp do całej aplikacji (serverWide w UI) — obejmuje także toole dodane później.
create table proxy.role_app_grants (
  role_id text not null references proxy.roles (id) on delete cascade,
  app_id text not null references proxy.apps (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (role_id, app_id)
);

alter table proxy.agents add column role_id text references proxy.roles (id) on delete set null;
alter table proxy.agents drop constraint agents_status_check;
alter table proxy.agents add constraint agents_status_check check (status in ('active', 'disabled', 'revoked'));

alter table proxy.agent_keys add column hint text not null default '';

create table proxy.agent_rules (
  id text primary key check (id ~ '^[a-z0-9_]{3,64}$'),
  agent_id text not null references proxy.agents (id) on delete cascade,
  name text not null,
  tool text not null,
  condition jsonb not null default '{"combinator": "and", "children": []}',
  outcome text not null check (outcome in ('allow', 'deny', 'needs_ai')),
  enabled boolean not null default true,
  position integer not null default 0,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index agent_rules_agent_position_idx on proxy.agent_rules (agent_id, position);

create table proxy.quotas (
  id text primary key check (id ~ '^[a-z0-9_]{3,64}$'),
  agent_id text not null references proxy.agents (id) on delete cascade,
  name text not null,
  "window" text not null check ("window" in ('1m', '1h', '1d')),
  cap integer not null check (cap > 0),
  burst integer not null default 0 check (burst >= 0),
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index quotas_agent_id_idx on proxy.quotas (agent_id);

-- Ścieżki pól maskowanych w audycie (A2), np. ["$.card.number", "$.total_eur"].
alter table proxy.tools add column redact jsonb not null default '[]';

create trigger set_updated_at before update on proxy.roles for each row execute function proxy.set_updated_at();
create trigger set_updated_at before update on proxy.agent_rules for each row execute function proxy.set_updated_at();
create trigger set_updated_at before update on proxy.quotas for each row execute function proxy.set_updated_at();

create trigger track_config_change after insert or update or delete on proxy.roles for each row execute function proxy.track_config_change('id');
create trigger track_config_change after insert or update or delete on proxy.role_grants for each row execute function proxy.track_config_change('role_id', 'tool_id');
create trigger track_config_change after insert or update or delete on proxy.role_app_grants for each row execute function proxy.track_config_change('role_id', 'app_id');
create trigger track_config_change after insert or update or delete on proxy.agent_rules for each row execute function proxy.track_config_change('id');
create trigger track_config_change after insert or update or delete on proxy.quotas for each row execute function proxy.track_config_change('id');

insert into proxy.settings (key, value) values
  ('workspace.org_name', '"Modus Demo"'),
  ('approvals.default_ttl_seconds', '900'),
  ('specialist.fail_closed', 'true'),
  ('audit.retention_days', '90'),
  ('sessions.max_denies', '3'),
  ('workspace.timezone', '"Europe/Warsaw"')
on conflict (key) do nothing;

-- ---------------------------------------------------------------------------
-- Operatorzy (ludzie w UI) — poza snapshotem proxy
-- ---------------------------------------------------------------------------

create table proxy.operators (
  id text primary key,
  email text not null unique check (email ~ '^[^@\s]+@[^@\s]+$'),
  name text not null default '',
  role text not null check (role in ('owner', 'admin', 'operator', 'viewer')),
  status text not null default 'invited' check (status in ('active', 'invited', 'disabled')),
  user_id text unique,
  invited_at timestamptz not null default now(),
  last_active_at timestamptz
);

-- ---------------------------------------------------------------------------
-- Runtime
-- ---------------------------------------------------------------------------

-- Aktywność agenta poza tabelą agents — update agents podbijałby rewizję konfiguracji.
create table proxy.agent_activity (
  agent_id text primary key,
  last_seen_at timestamptz not null default now()
);

alter table proxy.decisions add column agent_id text;
alter table proxy.decisions add column app_id text;
alter table proxy.decisions add column tool text;
alter table proxy.decisions add column kind text check (kind in ('read', 'write'));
alter table proxy.decisions add column chain jsonb not null default '[]';
alter table proxy.decisions add column args_redacted jsonb not null default '{}';
alter table proxy.decisions add column action_status text;
alter table proxy.decisions add column http_status integer;
alter table proxy.decisions add column upstream_status integer;
alter table proxy.decisions add column request_id text;
alter table proxy.decisions add column quota_id text;
alter table proxy.decisions add column retry_after_seconds integer check (retry_after_seconds >= 0);

update proxy.decisions d set agent_id = s.agent_id from proxy.sessions s where s.id = d.session_id;
alter table proxy.decisions alter column agent_id set not null;

alter table proxy.decisions drop constraint decisions_verdict_check;
alter table proxy.decisions add constraint decisions_verdict_check
  check (verdict in ('allow', 'escalate', 'deny', 'rate_limited'));
alter table proxy.decisions add constraint decisions_action_status_check
  check (action_status in (
    'forwarded', 'executed', 'upstream_error', 'blocked', 'rate_limited', 'pending_approval',
    'approved', 'rejected', 'expired', 'session_terminated', 'invalid'
  ));

create index decisions_created_at_idx on proxy.decisions (created_at desc, id desc);
create index decisions_agent_created_at_idx on proxy.decisions (agent_id, created_at desc);
create index decisions_tool_created_at_idx on proxy.decisions (tool, created_at desc);

alter table proxy.sessions add column termination_reason text;

alter table proxy.approvals add column tool text;
alter table proxy.approvals add column resolution_mode text check (resolution_mode in ('once', 'temporary', 'deny'));
alter table proxy.approvals add column temporary_ttl_seconds integer check (temporary_ttl_seconds > 0);

create index approvals_agent_status_idx on proxy.approvals (agent_id, status);

-- "Allow temporarily": ta sama para agent + tool przechodzi bez eskalacji do expires_at.
create table proxy.temporary_grants (
  id bigint generated always as identity primary key,
  agent_id text not null,
  tool text not null,
  approval_id text references proxy.approvals (id) on delete set null,
  expires_at timestamptz not null,
  created_by text,
  created_at timestamptz not null default now()
);

create index temporary_grants_agent_tool_idx on proxy.temporary_grants (agent_id, tool, expires_at desc);

alter table proxy.roles enable row level security;
alter table proxy.role_grants enable row level security;
alter table proxy.role_app_grants enable row level security;
alter table proxy.agent_rules enable row level security;
alter table proxy.quotas enable row level security;
alter table proxy.operators enable row level security;
alter table proxy.agent_activity enable row level security;
alter table proxy.temporary_grants enable row level security;

do $$
declare
  r text;
begin
  foreach r in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      execute format('revoke all on all tables in schema proxy from %I', r);
      execute format('revoke all on all functions in schema proxy from %I', r);
    end if;
  end loop;
end
$$;
