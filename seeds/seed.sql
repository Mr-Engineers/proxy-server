-- Konfiguracja proxy: aplikacje, katalog akcji, rola, agent zakupowy, kwota. Można odpalać wielokrotnie.
-- Potem: python -m app.cli load-policies (polityki) i python -m app.cli create-key purchasing-agent (klucz agenta).

begin;

set local proxy.actor = 'seed';

-- Aplikacje: proxy forwarduje tylko do Bedrocka, magazynu (one-backend) i marketplace (two-backend).

-- Bedrock: podpis SigV4 rolą taska ECS (lokalnie: credentiale z ~/.aws)
insert into proxy.apps (id, name, protocol, upstream_url, timeout_ms, auth_type, aws_region, aws_service)
values ('bedrock', 'Amazon Bedrock', 'llm', 'https://bedrock-runtime.eu-north-1.amazonaws.com/openai/v1', 120000,
        'aws_sigv4', 'eu-north-1', 'bedrock')
on conflict (id) do update set upstream_url = excluded.upstream_url, auth_type = excluded.auth_type,
  auth_secret_env = null, aws_region = excluded.aws_region, aws_service = excluded.aws_service;

-- one-backend przez Service Connect, token GATEWAY_TOKEN z SSM
insert into proxy.apps (id, name, protocol, upstream_url, timeout_ms, auth_type, auth_secret_env)
values ('warehouse', 'Magazyn', 'rest', 'http://backend:8000/api/v1', 10000, 'bearer', 'GATEWAY_TOKEN')
on conflict (id) do update set upstream_url = excluded.upstream_url, auth_type = excluded.auth_type,
  auth_secret_env = excluded.auth_secret_env, aws_region = null, aws_service = null;

-- two-backend za ALB klastra 2 (cert z naszego CA: certs/backend-2-ca.crt), token MARKETPLACE_API_TOKEN z SSM
insert into proxy.apps (id, name, protocol, upstream_url, timeout_ms, auth_type, auth_secret_env)
values ('marketplace', 'Marketplace', 'rest', 'https://one-dev-2-alb-1648560586.eu-north-1.elb.amazonaws.com', 10000, 'bearer', 'MARKETPLACE_API_TOKEN')
on conflict (id) do update set upstream_url = excluded.upstream_url, auth_type = excluded.auth_type,
  auth_secret_env = excluded.auth_secret_env, aws_region = null, aws_service = null;

-- Enrichment marketplace (D3): oferta i sprzedawca dociągane przed decyzją o zamówieniu.

update proxy.apps set enrichment = '{
  "offer":    {"path": "/offers/{offer_id}", "tools": ["place_order"], "cache_ttl_seconds": 60},
  "merchant": {"path": "/merchants/{merchant_id}", "tools": ["place_order"],
               "params": {"merchant_id": "$.offer.merchant.id"}, "cache_ttl_seconds": 3600}
}'
where id = 'marketplace';

-- Katalog akcji (D3): trasa → tool. Nieznana trasa = DENY.

insert into proxy.tools (app_id, name, kind, description, http_method, http_path, args, capture, scan_mode)
values ('warehouse', 'list_low_stock', 'read', 'Products below reorder threshold', 'GET', '/low-stock', '{}',
        '[{"into": "stock_needs", "from": "$.items[*]", "key": "sku",
           "fields": {"sku": "sku", "qty_needed": "qty_needed", "on_order": "on_order"}}]', 'none')
on conflict (app_id, name) do update set capture = excluded.capture;

insert into proxy.tools (app_id, name, kind, description, http_method, http_path, args, capture, input_schema)
values ('warehouse', 'register_po', 'write', 'Register a marketplace order as a purchase order', 'POST', '/purchase-orders',
        '{"sku": "$.sku", "quantity": "$.quantity", "unit_price": "$.unit_price",
          "marketplace_order_id": "$.supplier.marketplace_order_id", "merchant_id": "$.supplier.merchant_id"}',
        '[]',
        '{"type": "object", "required": ["sku", "quantity", "unit_price", "supplier"],
          "properties": {"sku": {"type": "string"}, "quantity": {"type": "integer", "minimum": 1},
                         "unit_price": {"type": "object"}, "supplier": {"type": "object"}}}')
on conflict (app_id, name) do update set args = excluded.args, input_schema = excluded.input_schema;

insert into proxy.tools (app_id, name, kind, description, http_method, http_path, args, capture, scan_mode, scan)
values ('marketplace', 'search_products', 'read', 'Search offers by SKU or text', 'GET', '/search',
        '{"sku": "$.sku", "q": "$.q", "limit": "$.limit"}',
        '[{"into": "offers_seen", "from": "$.offers[*]", "key": "offer_id",
           "fields": {"offer_id": "offer_id", "merchant_id": "merchant.id", "sku": "product.sku", "unit_price": "unit_price"}}]',
        'selected', '["$.offers[*].description"]')
on conflict (app_id, name) do update set capture = excluded.capture, scan_mode = excluded.scan_mode, scan = excluded.scan;

insert into proxy.tools (app_id, name, kind, description, http_method, http_path, args, capture, input_schema)
values ('marketplace', 'place_order', 'write', 'Place an order for an offer', 'POST', '/orders',
        '{"offer_id": "$.offer_id", "quantity": "$.quantity", "unit_price": "$.expected_unit_price"}',
        '[{"into": "orders_placed", "from": "$", "key": "order_id",
           "fields": {"order_id": "order_id", "offer_id": "offer_id", "sku": "sku", "quantity": "quantity",
                      "merchant_id": "merchant_id"}}]',
        '{"type": "object", "required": ["offer_id", "quantity", "expected_unit_price"],
          "properties": {"offer_id": {"type": "string"}, "quantity": {"type": "integer", "minimum": 1},
                         "expected_unit_price": {"type": "object", "required": ["amount", "currency"]}}}')
on conflict (app_id, name) do update set args = excluded.args, capture = excluded.capture, input_schema = excluded.input_schema;

-- RBAC: rola z dostępem do całych aplikacji magazyn + marketplace.

insert into proxy.roles (id, name, description, status)
values ('role_purchasing_operator', 'purchasing-operator', 'Restock: read low stock, search and order on the marketplace, register POs.', 'active')
on conflict (id) do nothing;

insert into proxy.role_app_grants (role_id, app_id) values
  ('role_purchasing_operator', 'warehouse'),
  ('role_purchasing_operator', 'marketplace')
on conflict do nothing;

insert into proxy.agents (id, name, mandate, llm_models, role_id, limits)
values ('purchasing-agent', 'Purchasing',
        'Uzupełnia stany magazynowe produktów poniżej progu. Kupuje najtańszą ofertę u sprawdzonych sprzedawców, w ilości potrzebnej do osiągnięcia stanu docelowego.',
        '{}', 'role_purchasing_operator', '{"max_denies_per_session": 3}')
on conflict (id) do nothing;

insert into proxy.quotas (id, agent_id, name, "window", cap, burst)
values ('quota_purchasing_hourly', 'purchasing-agent', 'Hourly cap', '1h', 500, 50)
on conflict (id) do nothing;

commit;
