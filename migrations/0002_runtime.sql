create table proxy.sessions (
  id text primary key,
  agent_id text not null references proxy.agents (id),
  task text,
  status text not null default 'active' check (status in ('active', 'closed', 'terminated', 'expired')),
  state jsonb not null default '{}',
  deny_count integer not null default 0 check (deny_count >= 0),
  created_at timestamptz not null default now(),
  last_activity_at timestamptz not null default now(),
  closed_at timestamptz,
  check ((status = 'active') = (closed_at is null))
);

create index sessions_agent_status_idx on proxy.sessions (agent_id, status);

create table proxy.hops (
  id text primary key,
  session_id text not null references proxy.sessions (id),
  agent_id text not null,
  seq integer not null check (seq >= 0),
  direction text not null check (direction in ('request', 'response')),
  protocol text not null check (protocol in ('rest', 'mcp', 'llm', 'web')),
  app_id text not null,
  tool_id uuid,
  action text,
  http_method text,
  http_path text,
  payload jsonb not null,
  upstream_status integer,
  upstream_latency_ms numeric(10, 2) check (upstream_latency_ms >= 0),
  created_at timestamptz not null default now(),
  unique (session_id, seq)
);

create index hops_agent_created_at_idx on proxy.hops (agent_id, created_at desc);
create index hops_app_action_created_at_idx on proxy.hops (app_id, action, created_at desc);

create table proxy.decisions (
  id text primary key,
  hop_id text not null unique references proxy.hops (id),
  session_id text not null references proxy.sessions (id),
  verdict text not null check (verdict in ('allow', 'escalate', 'deny')),
  confidence numeric(5, 4) not null check (confidence between 0 and 1),
  reasons jsonb not null default '[]',
  signals jsonb not null default '{}',
  degraded boolean not null default false,
  latency_ms numeric(10, 2) not null check (latency_ms >= 0),
  config_revision bigint not null,
  created_at timestamptz not null default now()
);

create index decisions_session_created_at_idx on proxy.decisions (session_id, created_at);
create index decisions_verdict_created_at_idx on proxy.decisions (verdict, created_at desc);

create table proxy.approvals (
  id text primary key,
  decision_id text not null unique references proxy.decisions (id),
  session_id text not null references proxy.sessions (id),
  agent_id text not null,
  status text not null default 'pending' check (status in ('pending', 'approved', 'rejected', 'expired')),
  request jsonb not null,
  request_sha256 bytea not null check (octet_length(request_sha256) = 32),
  feedback text,
  resolved_by text,
  resolved_at timestamptz,
  expires_at timestamptz not null,
  executed_at timestamptz,
  execution_result jsonb,
  created_at timestamptz not null default now(),
  check ((status = 'pending') = (resolved_at is null)),
  check (status in ('approved', 'rejected') or resolved_by is null),
  check (executed_at is null or status = 'approved')
);

create index approvals_pending_expires_at_idx on proxy.approvals (expires_at) where status = 'pending';
create index approvals_session_idx on proxy.approvals (session_id);

create function proxy.notify_approval_change() returns trigger
language plpgsql as $$
begin
  if new.status is distinct from old.status or new.executed_at is distinct from old.executed_at then
    perform pg_notify('proxy_approvals', new.id);
  end if;
  return null;
end
$$;

create trigger notify_approval_change after update on proxy.approvals for each row execute function proxy.notify_approval_change();

create table proxy.spend_ledger (
  id bigint generated always as identity primary key,
  agent_id text not null,
  app_id text not null,
  decision_id text references proxy.decisions (id),
  amount numeric(14, 2) not null check (amount >= 0),
  currency char(3) not null check (currency ~ '^[A-Z]{3}$'),
  created_at timestamptz not null default now()
);

create index spend_ledger_agent_app_created_at_idx on proxy.spend_ledger (agent_id, app_id, created_at desc);

alter table proxy.sessions enable row level security;
alter table proxy.hops enable row level security;
alter table proxy.decisions enable row level security;
alter table proxy.approvals enable row level security;
alter table proxy.spend_ledger enable row level security;

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
