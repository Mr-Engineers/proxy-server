begin;

set local proxy.actor = 'seed';

insert into proxy.apps (id, name, protocol, upstream_url, timeout_ms, auth_type, auth_secret_env)
values ('bedrock', 'Amazon Bedrock', 'llm', 'https://bedrock-runtime.eu-north-1.amazonaws.com/openai/v1', 120000, 'bearer', 'BEDROCK_API_KEY')
on conflict (id) do nothing;

insert into proxy.apps (id, name, protocol, upstream_url, timeout_ms, auth_type)
values ('warehouse', 'Magazyn', 'rest', 'http://localhost:8001', 10000, 'none')
on conflict (id) do nothing;

insert into proxy.apps (id, name, protocol, upstream_url, timeout_ms, auth_type)
values ('marketplace', 'Marketplace', 'rest', 'http://localhost:8002', 10000, 'none')
on conflict (id) do nothing;

commit;
