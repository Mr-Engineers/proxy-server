create schema if not exists proxy;

create table proxy.config_revision (
  id boolean primary key default true check (id),
  revision bigint not null default 0,
  updated_at timestamptz not null default now()
);

insert into proxy.config_revision default values;

create table proxy.config_changes (
  id bigint generated always as identity primary key,
  table_name text not null,
  operation text not null check (operation in ('INSERT', 'UPDATE', 'DELETE')),
  row_key jsonb not null,
  old_row jsonb,
  new_row jsonb,
  changed_by text,
  changed_at timestamptz not null default now(),
  revision bigint not null
);

create index config_changes_table_changed_at_idx on proxy.config_changes (table_name, changed_at desc);

create function proxy.set_updated_at() returns trigger
language plpgsql as $$
begin
  new.updated_at := now();
  return new;
end
$$;

create function proxy.track_config_change() returns trigger
language plpgsql as $$
declare
  old_json jsonb := case when tg_op in ('UPDATE', 'DELETE') then to_jsonb(old) - 'auth_secret_ciphertext' end;
  new_json jsonb := case when tg_op in ('INSERT', 'UPDATE') then to_jsonb(new) - 'auth_secret_ciphertext' end;
  key jsonb := '{}'::jsonb;
  col text;
  rev bigint;
begin
  foreach col in array tg_argv loop
    key := key || jsonb_build_object(col, coalesce(new_json, old_json) -> col);
  end loop;

  update proxy.config_revision
     set revision = revision + 1, updated_at = now()
   returning revision into rev;

  insert into proxy.config_changes (table_name, operation, row_key, old_row, new_row, changed_by, revision)
  values (tg_table_name, tg_op, key, old_json, new_json, nullif(current_setting('proxy.actor', true), ''), rev);

  perform pg_notify('proxy_config', rev::text);
  return null;
end
$$;

create table proxy.settings (
  key text primary key check (key ~ '^[a-z][a-z0-9_.]{0,127}$'),
  value jsonb not null,
  updated_at timestamptz not null default now()
);

create table proxy.agents (
  id text primary key check (id ~ '^[a-z0-9][a-z0-9-]{1,62}$'),
  name text not null,
  status text not null default 'active' check (status in ('active', 'disabled')),
  mandate text not null check (length(trim(mandate)) > 0),
  llm_models text[] not null default '{}',
  limits jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table proxy.agent_keys (
  id text primary key check (id ~ '^[a-z0-9]{6,32}$'),
  agent_id text not null references proxy.agents (id) on delete cascade,
  sha256 bytea not null check (octet_length(sha256) = 32),
  created_at timestamptz not null default now(),
  revoked_at timestamptz
);

create index agent_keys_agent_id_idx on proxy.agent_keys (agent_id);

create table proxy.apps (
  id text primary key check (id ~ '^[a-z][a-z0-9_]{0,62}$'),
  name text not null,
  protocol text not null check (protocol in ('rest', 'mcp', 'llm', 'web')),
  upstream_url text not null check (upstream_url ~ '^https?://'),
  timeout_ms integer not null default 10000 check (timeout_ms between 100 and 600000),
  auth_type text not null default 'none' check (auth_type in ('none', 'bearer', 'api_key_header', 'basic')),
  auth_header text,
  auth_secret_ciphertext bytea,
  auth_secret_env text,
  enrichment jsonb not null default '{}',
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  check (auth_type <> 'api_key_header' or auth_header is not null),
  check (auth_type = 'none' or num_nonnulls(auth_secret_ciphertext, auth_secret_env) = 1)
);

create table proxy.tools (
  id uuid primary key default gen_random_uuid(),
  app_id text not null references proxy.apps (id) on delete cascade,
  name text not null check (name ~ '^[a-z][a-z0-9_]{0,62}$'),
  kind text not null check (kind in ('read', 'write')),
  description text,
  http_method text check (http_method in ('GET', 'POST', 'PUT', 'PATCH', 'DELETE')),
  http_path text check (http_path ~ '^/'),
  mcp_tool text,
  input_schema jsonb,
  args jsonb not null default '{}',
  capture jsonb not null default '[]',
  scan_mode text not null default 'all_strings' check (scan_mode in ('all_strings', 'selected', 'none')),
  scan jsonb not null default '[]',
  enabled boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  unique (app_id, name),
  check ((http_method is null) = (http_path is null)),
  check (num_nonnulls(http_path, mcp_tool) = 1),
  check (scan_mode <> 'selected' or jsonb_array_length(scan) > 0)
);

create unique index tools_rest_route_uidx on proxy.tools (app_id, http_method, http_path) where http_path is not null;
create unique index tools_mcp_tool_uidx on proxy.tools (app_id, mcp_tool) where mcp_tool is not null;

create table proxy.agent_permissions (
  agent_id text not null references proxy.agents (id) on delete cascade,
  tool_id uuid not null references proxy.tools (id) on delete cascade,
  created_at timestamptz not null default now(),
  primary key (agent_id, tool_id)
);

create index agent_permissions_tool_id_idx on proxy.agent_permissions (tool_id);

create table proxy.policy_packs (
  app_id text primary key references proxy.apps (id) on delete cascade,
  cedar_policies text not null default '',
  cedar_schema text not null default '',
  params jsonb not null default '{}',
  params_schema jsonb not null default '{}',
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table proxy.policy_overrides (
  app_id text not null references proxy.policy_packs (app_id) on delete cascade,
  agent_id text not null references proxy.agents (id) on delete cascade,
  params jsonb not null,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now(),
  primary key (app_id, agent_id)
);

create trigger set_updated_at before update on proxy.settings for each row execute function proxy.set_updated_at();
create trigger set_updated_at before update on proxy.agents for each row execute function proxy.set_updated_at();
create trigger set_updated_at before update on proxy.apps for each row execute function proxy.set_updated_at();
create trigger set_updated_at before update on proxy.tools for each row execute function proxy.set_updated_at();
create trigger set_updated_at before update on proxy.policy_packs for each row execute function proxy.set_updated_at();
create trigger set_updated_at before update on proxy.policy_overrides for each row execute function proxy.set_updated_at();

create trigger track_config_change after insert or update or delete on proxy.settings for each row execute function proxy.track_config_change('key');
create trigger track_config_change after insert or update or delete on proxy.agents for each row execute function proxy.track_config_change('id');
create trigger track_config_change after insert or update or delete on proxy.agent_keys for each row execute function proxy.track_config_change('id');
create trigger track_config_change after insert or update or delete on proxy.apps for each row execute function proxy.track_config_change('id');
create trigger track_config_change after insert or update or delete on proxy.tools for each row execute function proxy.track_config_change('id');
create trigger track_config_change after insert or update or delete on proxy.agent_permissions for each row execute function proxy.track_config_change('agent_id', 'tool_id');
create trigger track_config_change after insert or update or delete on proxy.policy_packs for each row execute function proxy.track_config_change('app_id');
create trigger track_config_change after insert or update or delete on proxy.policy_overrides for each row execute function proxy.track_config_change('app_id', 'agent_id');

alter table proxy.config_revision enable row level security;
alter table proxy.config_changes enable row level security;
alter table proxy.settings enable row level security;
alter table proxy.agents enable row level security;
alter table proxy.agent_keys enable row level security;
alter table proxy.apps enable row level security;
alter table proxy.tools enable row level security;
alter table proxy.agent_permissions enable row level security;
alter table proxy.policy_packs enable row level security;
alter table proxy.policy_overrides enable row level security;

do $$
declare
  r text;
begin
  foreach r in array array['anon', 'authenticated'] loop
    if exists (select 1 from pg_roles where rolname = r) then
      execute format('revoke all on schema proxy from %I', r);
      execute format('revoke all on all tables in schema proxy from %I', r);
      execute format('revoke all on all functions in schema proxy from %I', r);
    end if;
  end loop;
end
$$;
