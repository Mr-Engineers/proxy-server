"""/api/v1 — kontrakty z docs/api/*."""

import threading
import time

import jwt
from pydantic import SecretStr

from app.core.settings import Settings
from app.jobs import apply_retention
from tests.conftest import AUTH, open_session, reload, rows, sql

PLN = {"amount": "36.00", "currency": "PLN"}


def make_traffic(client, upstreams) -> dict[str, str]:
    upstreams.scenario("fresh_domain_discount")
    headers = open_session(client)
    client.get("/apps/warehouse/low-stock", headers=headers)
    client.get("/apps/marketplace/search?sku=PAP-A4-80", headers=headers)
    client.post("/apps/marketplace/orders", json={"offer_id": "off_pr_pap", "quantity": 10, "expected_unit_price": PLN}, headers=headers)
    client.post("/apps/warehouse/nope", json={"token": "secret-token"}, headers=headers)
    return headers


# --- auth -------------------------------------------------------------------


def test_requires_supabase_jwt(make_client, database) -> None:
    secret = "super-secret-jwt-key-for-tests-only-0123456789"
    client = make_client(settings=Settings(database_url=database, listen_notifications=False, background_jobs=False,
                                           supabase_jwt_secret=SecretStr(secret)))
    assert client.get("/api/v1/me").status_code == 401
    assert client.get("/api/v1/me", headers={"Authorization": "Bearer nope"}).status_code == 401

    token = jwt.encode({"sub": "user-1", "email": "ops@modus.dev", "aud": "authenticated", "exp": int(time.time()) + 60,
                        "user_metadata": {"full_name": "Ops"}}, secret, algorithm="HS256")
    headers = {"Authorization": f"Bearer {token}"}
    me = client.get("/api/v1/me", headers=headers).json()
    assert me["email"] == "ops@modus.dev" and me["name"] == "Ops" and me["operator"] is None
    assert me["workspace"] == {"orgName": "Modus Demo", "authMode": "invite_only"}

    sql("insert into proxy.operators (id, email, role, status) values ('op_1', 'ops@modus.dev', 'operator', 'disabled')")
    assert client.get("/api/v1/me", headers=headers).status_code == 403

    expired = jwt.encode({"sub": "u", "aud": "authenticated", "exp": int(time.time()) - 10}, secret, algorithm="HS256")
    assert client.get("/api/v1/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401


def test_validation_errors_use_detail_400(client) -> None:
    response = client.get("/api/v1/audit?limit=999")
    assert response.status_code == 400
    assert "limit" in response.json()["detail"]


# --- audit ------------------------------------------------------------------


def test_audit_list_and_detail(client, upstreams) -> None:
    make_traffic(client, upstreams)
    page = client.get("/api/v1/audit").json()
    items = page["items"]
    assert [item["tool"] for item in items] == [
        "warehouse.<unmatched>", "marketplace.place_order", "marketplace.search_products", "warehouse.list_low_stock"
    ]
    assert [item["decision"] for item in items] == ["deny", "caution", "allow", "allow"]
    first = items[0]
    assert set(first) >= {"id", "timestamp", "tool", "agentId", "agentName", "decision", "decisionChain", "argsRedacted"}
    assert first["agentName"] == "Purchasing"
    assert first["argsRedacted"]["token"] == "***"
    assert {step["stage"] for step in first["decisionChain"]} == {"rbac", "rules", "specialist", "human"}
    assert items[1]["approvalId"].startswith("apr_")

    detail = client.get(f"/api/v1/audit/{items[1]['id']}").json()
    assert detail["reasons"][0]["code"] == "marketplace.merchant_too_young"
    assert detail["facts"]["offer_seen_in_session"] is True
    assert detail["enrichment"]["merchant"]["id"] == "mer_promocje"
    assert client.get("/api/v1/audit/dec_missing").status_code == 404


def test_audit_filters_and_cursor(client, upstreams) -> None:
    make_traffic(client, upstreams)
    assert len(client.get("/api/v1/audit?decision=caution,deny").json()["items"]) == 2
    assert [i["tool"] for i in client.get("/api/v1/audit?tool=marketplace").json()["items"]] == [
        "marketplace.place_order", "marketplace.search_products"]
    assert len(client.get("/api/v1/audit?search=low_stock").json()["items"]) == 1
    assert client.get("/api/v1/audit?agent_name=Purchasing").json()["items"]
    assert client.get("/api/v1/audit?agent_id=ghost").json()["items"] == []
    assert client.get("/api/v1/audit?decision=pending").status_code == 400
    assert client.get("/api/v1/audit?from=2026-10-03T10:00:00Z&to=2026-10-03T09:00:00Z").status_code == 400

    seen = []
    cursor = None
    while True:
        page = client.get("/api/v1/audit", params={"limit": 3, "sort": "tool", "sort_dir": "asc", **({"cursor": cursor} if cursor else {})}).json()
        seen += [item["tool"] for item in page["items"]]
        cursor = page["nextCursor"]
        if cursor is None:
            break
    assert seen == sorted(seen) and len(seen) == 4


# --- agenci, klucze, reguły, kwoty ------------------------------------------


def test_agents_crud_and_keys(client) -> None:
    listed = client.get("/api/v1/agents").json()["items"]
    assert listed[0]["id"] == "purchasing-agent"
    assert listed[0]["roleName"] == "purchasing-operator"
    assert listed[0]["mcpServerIds"] == ["marketplace", "warehouse"]
    assert listed[0]["apiKeyHint"] == "ak_dev0001_••••cret"

    created = client.post("/api/v1/agents", json={"id": "ops-agent", "name": "Ops", "mandate": "read only",
                                                   "roleId": "role_purchasing_operator"})
    assert created.status_code == 201
    key = created.json()["apiKey"]
    assert key.startswith("ak_")
    assert client.post("/api/v1/agents", json={"id": "ops-agent", "name": "x", "mandate": "x"}).status_code == 409

    reload(client)
    assert client.post("/v1/sessions", json={}, headers={"Authorization": f"Bearer {key}"}).status_code == 201

    patched = client.patch("/api/v1/agents/ops-agent", json={"roleId": None, "status": "disabled", "rateLimitOverride": 30}).json()
    assert patched["roleId"] is None and patched["status"] == "disabled" and patched["rateLimitOverride"] == 30
    assert client.patch("/api/v1/agents/ops-agent", json={"roleId": "missing"}).status_code == 400

    revoked = client.post("/api/v1/agents/ops-agent/revoke").json()
    assert revoked["status"] == "revoked" and revoked["apiKeyHint"].startswith("revoked_")
    reload(client)
    assert client.post("/v1/sessions", json={}, headers={"Authorization": f"Bearer {key}"}).status_code == 401
    assert client.patch("/api/v1/agents/ops-agent", json={"status": "active"}).status_code == 409

    rotated = client.post("/api/v1/agents/ops-agent/keys").json()
    assert rotated["status"] == "active"
    assert client.get("/api/v1/agents?status=revoked").json()["items"] == []
    assert client.get("/api/v1/agents/ghost").status_code == 404
    assert client.post("/api/v1/agents/ops-agent/mcp/marketplace").status_code == 501

    changes = rows("select changed_by from proxy.config_changes where table_name = 'agents' order by id desc limit 1")
    assert changes[0]["changed_by"] == "dev@localhost"


def test_rules_crud_meta_dry_run(client) -> None:
    base = "/api/v1/agents/purchasing-agent/rules"
    rule = client.post(base, json={
        "name": "Big orders", "tool": "marketplace.place_order",
        "when": {"id": "g", "combinator": "and", "children": [{"id": "l", "field": "quantity", "op": "gt", "value": 100}]},
        "then": "needs_ai",
    }).json()
    assert rule["then"] == "needs_ai" and rule["position"] == 0
    assert client.post(base, json={"name": "x", "tool": "t", "when": {"field": "a", "op": "bad"}, "then": "deny"}).status_code == 400

    updated = client.put(f"{base}/{rule['id']}", json={**rule, "then": "deny"}).json()
    assert updated["then"] == "deny"
    assert [item["id"] for item in client.get(base).json()["items"]] == [rule["id"]]

    run = client.post(f"{base}/dry-run", json={"tool": "marketplace.place_order", "args": {"quantity": 400}}).json()
    assert run["matchedRuleId"] == rule["id"] and run["outcome"] == "deny"
    assert run["policy"]["verdict"] == "deny"  # brak enrichmentu → merchant_unknown

    draft = client.post(f"{base}/dry-run", json={"tool": "marketplace.place_order", "args": {"quantity": 1},
                                                 "rules": [{"name": "all", "tool": "*", "then": "allow"}]}).json()
    assert draft["outcome"] == "allow" and draft["matchedRuleId"] == "draft_0"

    meta = client.get(f"{base}/meta").json()
    assert {group["serverId"] for group in meta["tools"]} == {"marketplace", "warehouse"}
    fields = {field["id"]: field for field in meta["fields"]}
    assert fields["quantity"]["type"] == "number"
    assert fields["qty_ratio_pct"]["computed"] is True

    assert client.delete(f"{base}/{rule['id']}").status_code == 204
    assert client.delete(f"{base}/{rule['id']}").status_code == 404


def test_quotas(client) -> None:
    created = client.post("/api/v1/agents/purchasing-agent/quotas", json={"name": "Per minute", "window": "1m", "cap": 10, "burst": 2})
    assert created.status_code == 201
    quota = created.json()
    assert quota["used"] == 0 and quota["unit"] == "calls" and quota["enabled"] is True
    assert client.patch(f"/api/v1/quotas/{quota['id']}", json={"enabled": False}).json()["enabled"] is False
    assert len(client.get("/api/v1/agents/purchasing-agent/quotas").json()["items"]) == 2
    assert client.post("/api/v1/agents/purchasing-agent/quotas", json={"name": "x", "window": "2h", "cap": 1}).status_code == 400


def test_agent_overview_and_posture(client, upstreams) -> None:
    sql("update proxy.quotas set enabled = true")
    reload(client)
    make_traffic(client, upstreams)
    overview = client.get("/api/v1/agents/purchasing-agent/overview?range=24h").json()
    assert overview["calls"] == 4
    assert overview["pendingApprovals"] == 1
    assert overview["clear"] == 2 and overview["flagged"] == 2
    assert overview["budget"]["id"] == "quota_purchasing_hourly"

    posture = client.get("/api/v1/agents/purchasing-agent/posture").json()
    assert posture["role"]["id"] == "role_purchasing_operator"
    assert {item["tool"] for item in posture["callable"]} == {
        "marketplace.place_order", "marketplace.search_products", "warehouse.list_low_stock", "warehouse.register_po"}
    assert posture["callable"][0]["via"] == "server"


# --- overview, sesje ----------------------------------------------------------


def test_overview(client, upstreams) -> None:
    make_traffic(client, upstreams)
    data = client.get("/api/v1/overview?range=today&tz=Europe/Warsaw").json()
    assert data["window"]["preset"] == "today" and data["window"]["timezone"] == "Europe/Warsaw"
    assert data["calls"] == 4 and data["callsDeltaPct"] is None
    assert data["denyRatePct"] == 25 and data["cautionRatePct"] == 25
    assert [item["decision"] for item in data["decisionSplit"]] == ["allow", "caution", "deny", "rate_limited"]
    assert sum(bucket["count"] for bucket in data["callsOverTime"]) == 4
    assert data["pendingApprovals"] == 1 and data["activeAgents"] == 1
    assert data["agentSplit"] == [{"agentId": "purchasing-agent", "agentName": "Purchasing", "clear": 2, "flagged": 2}]
    assert data["topTools"][0]["count"] == 1
    assert data["budgets"] == []  # kwota wyłączona w testach
    assert client.get("/api/v1/overview?range=bad").status_code == 400


def test_session_timeline(client, upstreams) -> None:
    headers = make_traffic(client, upstreams)
    session_id = headers["X-Session-Id"]
    listed = client.get("/api/v1/sessions?agent_id=purchasing-agent").json()["items"]
    assert listed[0]["id"] == session_id and listed[0]["decisions"] == 4 and listed[0]["pendingApprovals"] == 1

    timeline = client.get(f"/api/v1/sessions/{session_id}").json()
    assert timeline["state"]["stock_needs"][0]["sku"] == "PAP-A4-80"
    decided = [entry for entry in timeline["timeline"] if "decision" in entry]
    assert [entry["decision"]["decision"] for entry in decided] == ["allow", "allow", "caution", "deny"]
    assert decided[2]["decision"]["approvalStatus"] == "pending"


# --- role, MCP, polityki, ustawienia ------------------------------------------


def test_roles(client) -> None:
    roles = client.get("/api/v1/roles").json()["items"]
    assert roles[0]["grantedToolCount"] == 4 and roles[0]["assignedAgentIds"] == ["purchasing-agent"]

    role = client.post("/api/v1/roles", json={"name": "readonly", "grants": [
        {"serverId": "marketplace", "tools": {"marketplace.search_products": True, "marketplace.place_order": False}}]}).json()
    assert role["status"] == "draft"
    grant = next(g for g in role["grants"] if g["serverId"] == "marketplace")
    assert grant["tools"] == {"marketplace.place_order": False, "marketplace.search_products": True}
    assert grant["serverWide"] is False

    full = client.patch(f"/api/v1/roles/{role['id']}", json={"grants": [
        {"serverId": "warehouse", "tools": {"warehouse.list_low_stock": True, "warehouse.register_po": True}}]}).json()
    assert next(g for g in full["grants"] if g["serverId"] == "warehouse")["serverWide"] is True
    assert client.patch(f"/api/v1/roles/{role['id']}", json={"grants": [{"serverId": "x"}]}).status_code == 400

    assert client.post(f"/api/v1/roles/{role['id']}/publish").json()["status"] == "active"
    assert client.post(f"/api/v1/roles/{role['id']}/publish").status_code == 409
    assert client.post(f"/api/v1/roles/{role['id']}/archive").json()["status"] == "archived"
    assert client.patch(f"/api/v1/roles/{role['id']}", json={"grants": []}).status_code == 409


def test_mcp_registry_and_enablement(client, upstreams) -> None:
    make_traffic(client, upstreams)
    servers = {item["id"]: item for item in client.get("/api/v1/mcp").json()["items"]}
    assert set(servers) == {"marketplace", "warehouse"}
    assert servers["warehouse"]["health"] == "healthy"
    assert servers["marketplace"]["tools"] == ["marketplace.place_order", "marketplace.search_products"]

    patched = client.patch("/api/v1/mcp/marketplace/tools/place_order", json={"enabled": False}).json()
    assert patched["tools"] == ["marketplace.search_products"]
    reload(client)
    headers = open_session(client)
    response = client.post("/apps/marketplace/orders", json={}, headers=headers)
    assert response.status_code == 403
    assert rows("select tool from proxy.decisions where id = $1", response.json()["decision_id"])[0]["tool"] == "marketplace.<unmatched>"

    assert client.patch("/api/v1/mcp/warehouse", json={"enabled": False}).json()["health"] == "down"
    assert client.post("/api/v1/mcp/remote/discover", json={}).status_code == 501
    assert client.get("/api/v1/mcp/nope").status_code == 404


def test_policy_pack_edits_are_validated(client) -> None:
    pack = client.get("/api/v1/policies/marketplace").json()
    assert pack["effectiveParams"]["purchasing-agent"]["place_order"]["allowed_countries"] == ["PL"]
    assert any(rule["id"] == "marketplace.country_not_allowed" for rule in pack["rules"])

    loosen = client.put("/api/v1/policies/marketplace/overrides/purchasing-agent",
                        json={"params": {"place_order": {"allowed_countries": ["PL", "US"]}}})
    assert loosen.status_code == 400

    tighter = client.put("/api/v1/policies/marketplace/overrides/purchasing-agent",
                         json={"params": {"place_order": {"max_order_value": {"amount": "1000.00", "currency": "PLN"}}}}).json()
    assert tighter["effectiveParams"]["purchasing-agent"]["place_order"]["max_order_value_minor"] == 100000

    broken = client.put("/api/v1/policies/marketplace", json={"cedarPolicies": "forbid(principal, action, resource) when {"})
    assert broken.status_code == 400


def test_workspace_settings_and_operators(client) -> None:
    assert client.get("/api/v1/settings/workspace").json() == {
        "orgName": "Modus Demo", "defaultApprovalTtlSeconds": 900, "specialistFailClosed": True,
        "auditRetentionDays": 90, "authMode": "invite_only"}
    updated = client.patch("/api/v1/settings/workspace", json={"defaultApprovalTtlSeconds": 300, "orgName": "Acme"}).json()
    assert updated["defaultApprovalTtlSeconds"] == 300 and updated["orgName"] == "Acme"
    assert client.patch("/api/v1/settings/workspace", json={"auditRetentionDays": 7}).status_code == 400
    reload(client)
    assert client.app.state.snapshot.settings.default_approval_ttl_seconds == 300

    invited = client.post("/api/v1/settings/operators/invite", json={"email": "a@b.co", "role": "viewer"}).json()
    assert invited["status"] == "invited"
    assert client.post("/api/v1/settings/operators/invite", json={"email": "a@b.co", "role": "viewer"}).status_code == 409
    assert client.post(f"/api/v1/settings/operators/{invited['id']}/disable").json()["status"] == "disabled"
    assert client.post(f"/api/v1/settings/operators/{invited['id']}/enable").json()["status"] == "active"
    assert client.post(f"/api/v1/settings/operators/{invited['id']}/resend").status_code == 409
    assert len(client.get("/api/v1/settings/operators").json()["items"]) == 1


def test_specialists_and_simulator(client) -> None:
    assert client.get("/api/v1/specialists").json() == {"items": [], "nextCursor": None}
    assert client.get("/api/v1/specialists/spc_x").status_code == 404
    assert client.post("/api/v1/simulator/runs").status_code == 501


# --- NOTIFY, joby ---------------------------------------------------------------


def test_config_reload_and_long_poll_via_notify(make_client, upstreams) -> None:
    client = make_client(listen_notifications=True, config_reload_debounce_seconds=0.05)
    revision = client.app.state.snapshot.revision
    sql("update proxy.agents set name = 'Renamed' where id = 'purchasing-agent'")
    deadline = time.time() + 3
    while client.app.state.snapshot.revision == revision and time.time() < deadline:
        time.sleep(0.05)
    assert client.app.state.snapshot.agents["purchasing-agent"].name == "Renamed"

    headers = make_traffic(client, upstreams)
    approval_id = rows("select id from proxy.approvals")[0]["id"]
    result = {}

    def poll() -> None:
        started = time.time()
        response = client.get(f"/v1/approvals/{approval_id}?wait=10", headers=AUTH)
        result.update(status=response.json()["status"], elapsed=time.time() - started)

    thread = threading.Thread(target=poll)
    thread.start()
    time.sleep(0.3)
    sql("update proxy.approvals set status = 'rejected', resolved_at = now(), resolved_by = 'db', feedback = 'no'")
    thread.join(timeout=5)
    assert result["status"] == "rejected"
    assert result["elapsed"] < 5
    assert headers


def test_retention_removes_old_audit(client, upstreams) -> None:
    make_traffic(client, upstreams)
    sql("update proxy.decisions set created_at = now() - interval '100 days'")
    sql("update proxy.hops set created_at = now() - interval '100 days'")
    sql("update proxy.approvals set status = 'expired', resolved_at = now()")

    async def run() -> None:
        await apply_retention(client.app.state.db, 90)

    client.portal.call(run)
    assert rows("select count(*) as n from proxy.decisions")[0]["n"] == 0
    assert rows("select count(*) as n from proxy.hops")[0]["n"] == 0


def test_background_expiry_job(make_client, upstreams) -> None:
    client = make_client(background_jobs=True, approval_sweep_seconds=0.05)
    make_traffic(client, upstreams)
    sql("update proxy.approvals set expires_at = now() - interval '1 second', created_at = now() - interval '1 hour'")
    deadline = time.time() + 3
    while time.time() < deadline and rows("select status from proxy.approvals")[0]["status"] == "pending":
        time.sleep(0.05)
    assert rows("select status from proxy.approvals")[0]["status"] == "expired"
