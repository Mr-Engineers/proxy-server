"""Use case referencyjny end-to-end: agent → proxy → magazyn / marketplace, z decyzjami i HITL."""

from types import SimpleNamespace

from app.pipeline.jev import JevScorer
from tests.conftest import AUTH, open_session, reload, rows, sql

PLN = lambda amount: {"amount": amount, "currency": "PLN"}  # noqa: E731


def _mock_jev(choice: str, confidence: float = 0.9) -> JevScorer:
    probs = {"clear": 0.05, "caution": 0.05, "deny": 0.05}
    probs[choice] = 0.9

    async def system_one(**kwargs):
        return SimpleNamespace(
            model="jev-test",
            choices={
                "verdict": SimpleNamespace(choice=choice, probabilities=probs, confidence=confidence),
            },
        )

    return JevScorer(system_one=system_one, model="jev-test")


def order(offer_id: str = "off_bm_pap", quantity: int = 38, price: str = "118.00") -> dict:
    return {"offer_id": offer_id, "quantity": quantity, "expected_unit_price": PLN(price)}


def prepare(client, upstreams, scenario: str = "happy_path") -> dict[str, str]:
    upstreams.scenario(scenario)
    headers = open_session(client)
    assert client.get("/apps/warehouse/low-stock", headers=headers).status_code == 200
    assert client.get("/apps/marketplace/search?sku=PAP-A4-80", headers=headers).status_code == 200
    return headers


def decision(decision_id: str):
    return rows("select * from proxy.decisions where id = $1", decision_id)[0]


def test_happy_path_full_flow(client, upstreams) -> None:
    headers = prepare(client, upstreams)
    response = client.post("/apps/marketplace/orders", json=order(), headers=headers)
    assert response.status_code == 201, response.text
    order_id = response.json()["order_id"]

    po = {"sku": "PAP-A4-80", "quantity": 38, "unit_price": PLN("118.00"),
          "supplier": {"marketplace_order_id": order_id, "merchant_id": "mer_biuromax"}}
    assert client.post("/apps/warehouse/purchase-orders", json=po, headers=headers).status_code == 201

    session = rows("select state from proxy.sessions where id = $1", headers["X-Session-Id"])[0]["state"]
    assert session["stock_needs"][0]["qty_needed"] == 38
    assert {offer["offer_id"] for offer in session["offers_seen"]} == {"off_bm_pap", "off_oh_pap"}
    assert session["orders_placed"][0]["order_id"] == order_id

    placed = decision(response.headers["x-decision-id"])
    assert placed["verdict"] == "allow"
    assert placed["action_status"] == "executed"
    assert [step["stage"] for step in placed["chain"]] == ["rbac", "rules", "specialist", "human"]
    assert placed["args_redacted"]["quantity"] == 38
    assert placed["signals"]["enrichment"]["merchant"]["country"] == "PL"

    spend = rows("select amount, currency from proxy.spend_ledger")
    assert [(str(row["amount"]), row["currency"]) for row in spend] == [("4484.00", "PLN")]
    hops = rows("select direction from proxy.hops where session_id = $1 order by seq", headers["X-Session-Id"])
    assert len(hops) == 8


def test_foreign_cheapest_is_blocked(client, upstreams) -> None:
    headers = prepare(client, upstreams, "foreign_cheapest")
    response = client.post("/apps/marketplace/orders", json=order("off_cd_pap", price="61.00"), headers=headers)

    assert response.status_code == 403
    body = response.json()
    assert body["status"] == "blocked" and "country" not in response.text
    assert upstreams.to("marketplace")[-1].url.path != "/orders"
    row = decision(body["decision_id"])
    assert row["verdict"] == "deny"
    assert "marketplace.country_not_allowed" in {reason["code"] for reason in row["reasons"]}


def test_ungrounded_offer_is_blocked(client, upstreams) -> None:
    headers = open_session(client)
    client.get("/apps/warehouse/low-stock", headers=headers)
    response = client.post("/apps/marketplace/orders", json=order(), headers=headers)
    assert response.status_code == 403
    assert "marketplace.offer_not_grounded" in {r["code"] for r in decision(response.json()["decision_id"])["reasons"]}


def test_jev_clears_policy_escalate(make_client, upstreams) -> None:
    client = make_client(scorer=_mock_jev("clear", confidence=0.9))
    headers = prepare(client, upstreams, "fresh_domain_discount")
    response = client.post("/apps/marketplace/orders", json=order("off_pr_pap", price="36.00"), headers=headers)
    assert response.status_code == 201, response.text
    row = decision(response.headers["x-decision-id"])
    assert row["verdict"] == "allow"
    assert row["chain"][2]["stage"] == "specialist" and row["chain"][2]["outcome"] == "clear"
    assert row["signals"]["choice"] == "clear"


def test_jev_caution_keeps_hitl(make_client, upstreams) -> None:
    client = make_client(scorer=_mock_jev("caution", confidence=0.85))
    headers = prepare(client, upstreams, "fresh_domain_discount")
    response = client.post("/apps/marketplace/orders", json=order("off_pr_pap", price="36.00"), headers=headers)
    assert response.status_code == 202, response.text
    row = decision(response.json()["decision_id"])
    assert row["verdict"] == "escalate"
    assert row["chain"][2]["outcome"] == "caution"


def test_jev_clears_ui_needs_ai(make_client, upstreams) -> None:
    client = make_client(scorer=_mock_jev("clear", confidence=0.9))
    created = client.post("/api/v1/agents/purchasing-agent/rules", json={
        "name": "Review warehouse", "tool": "warehouse.*",
        "when": {"combinator": "and", "children": []}, "then": "needs_ai",
    })
    assert created.status_code == 201, created.text
    reload(client)
    headers = open_session(client)
    response = client.get("/apps/warehouse/low-stock", headers=headers)
    assert response.status_code == 200, response.text
    row = decision(response.headers["x-decision-id"])
    assert row["verdict"] == "allow"
    assert row["chain"][2]["stage"] == "specialist" and row["chain"][2]["outcome"] == "clear"


def test_fresh_domain_escalates_and_approve_executes_once(client, upstreams) -> None:
    headers = prepare(client, upstreams, "fresh_domain_discount")
    response = client.post("/apps/marketplace/orders", json=order("off_pr_pap", price="36.00"), headers=headers)
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["status"] == "pending_approval"
    approval_id = body["approval_id"]
    orders_before = len(upstreams.orders)

    poll = client.get(f"/v1/approvals/{approval_id}", headers=AUTH)
    assert poll.status_code == 202 and poll.json()["status"] == "pending_approval"

    queue = client.get("/api/v1/approvals").json()["items"]
    assert [item["id"] for item in queue] == [approval_id]
    assert queue[0]["matchedRules"] == ["Merchant domain is younger than the minimum age"]
    assert queue[0]["modelChoice"] == "caution → human"

    resolved = client.post(f"/api/v1/approvals/{approval_id}/allow")
    assert resolved.json() == {"id": approval_id, "decision": "allow", "mode": "once"}
    assert len(upstreams.orders) == orders_before + 1

    poll = client.get(f"/v1/approvals/{approval_id}?wait=1", headers=AUTH)
    assert poll.status_code == 200
    assert poll.json()["status"] == "approved"
    assert poll.json()["result"]["status_code"] == 201

    assert client.post(f"/api/v1/approvals/{approval_id}/allow").status_code == 409
    assert len(upstreams.orders) == orders_before + 1
    assert client.get("/api/v1/approvals").json()["items"] == []

    row = decision(body["decision_id"])
    assert row["action_status"] == "executed"
    assert row["chain"][-1]["stage"] == "human" and row["chain"][-1]["outcome"] == "allow"
    state = rows("select state from proxy.sessions where id = $1", headers["X-Session-Id"])[0]["state"]
    assert state["orders_placed"][0]["offer_id"] == "off_pr_pap"


def test_reject_with_feedback_reaches_agent(client, upstreams) -> None:
    headers = prepare(client, upstreams, "fresh_domain_discount")
    body = client.post("/apps/marketplace/orders", json=order("off_pr_pap", price="36.00"), headers=headers).json()

    client.post(f"/api/v1/approvals/{body['approval_id']}/deny", json={"reason": "kup w biuromax"})
    poll = client.get(f"/v1/approvals/{body['approval_id']}", headers=AUTH).json()
    assert poll == {"status": "rejected", "decision_id": body["decision_id"], "approval_id": body["approval_id"],
                    "feedback": "kup w biuromax"}
    assert all(request.url.path != "/orders" for request in upstreams.requests)
    assert decision(body["decision_id"])["chain"][-1]["outcome"] == "deny"

    retry = client.post("/apps/marketplace/orders", json=order(), headers=headers)
    assert retry.status_code == 201


def test_approval_expires(client, upstreams) -> None:
    headers = prepare(client, upstreams, "fresh_domain_discount")
    body = client.post("/apps/marketplace/orders", json=order("off_pr_pap", price="36.00"), headers=headers).json()
    sql("update proxy.approvals set expires_at = now() - interval '1 second', created_at = now() - interval '1 hour'")

    poll = client.get(f"/v1/approvals/{body['approval_id']}", headers=AUTH)
    assert poll.status_code == 200 and poll.json()["status"] == "expired"
    assert decision(body["decision_id"])["action_status"] == "expired"
    assert client.post(f"/api/v1/approvals/{body['approval_id']}/allow").status_code == 409


def test_allow_temporary_skips_next_escalation(client, upstreams) -> None:
    headers = prepare(client, upstreams, "fresh_domain_discount")
    first = client.post("/apps/marketplace/orders", json=order("off_pr_pap", quantity=10, price="36.00"), headers=headers).json()
    assert client.post(f"/api/v1/approvals/{first['approval_id']}/allow-temporary", json={"ttlSeconds": 600}).json()["mode"] == "temporary"

    second = client.post("/apps/marketplace/orders", json=order("off_pr_pap", quantity=10, price="36.00"), headers=headers)
    assert second.status_code == 201
    assert decision(second.headers["x-decision-id"])["chain"][-1]["detail"] == "Temporary allow granted by operator"
    assert client.post(f"/api/v1/approvals/{first['approval_id']}/allow-temporary", json={"ttlSeconds": 600}).status_code == 409
    assert client.post(f"/api/v1/approvals/{first['approval_id']}/allow-temporary", json={"ttlSeconds": 5}).status_code == 400


def test_session_terminated_after_three_denies(client, upstreams) -> None:
    headers = prepare(client, upstreams, "foreign_cheapest")
    statuses = [
        client.post("/apps/marketplace/orders", json=order("off_cd_pap", price="61.00"), headers=headers).json()["status"]
        for _ in range(3)
    ]
    assert statuses == ["blocked", "blocked", "session_terminated"]
    after = client.get("/apps/warehouse/low-stock", headers=headers)
    assert after.status_code == 403 and after.json()["error"]["code"] == "session_terminated"
    session = rows("select status, deny_count, termination_reason from proxy.sessions where id = $1", headers["X-Session-Id"])[0]
    assert (session["status"], session["deny_count"], session["termination_reason"]) == ("terminated", 3, "deny_limit")


def test_rbac_denies_ungranted_tool(client, upstreams) -> None:
    sql("delete from proxy.role_app_grants where app_id = 'marketplace'")
    reload(client)
    headers = open_session(client)
    response = client.get("/apps/marketplace/search?sku=PAP-A4-80", headers=headers)
    assert response.status_code == 403
    row = decision(response.json()["decision_id"])
    assert row["chain"][0] == {"stage": "rbac", "outcome": "deny", "detail": "marketplace.search_products not granted to agent"}


def test_schema_violation_returns_400(client, upstreams) -> None:
    headers = prepare(client, upstreams)
    response = client.post("/apps/marketplace/orders", json={"offer_id": "off_bm_pap", "quantity": -1}, headers=headers)
    assert response.status_code == 400
    assert response.json()["status"] == "invalid_arguments"
    assert decision(response.json()["decision_id"])["action_status"] == "invalid"


def test_quota_rate_limits(client, upstreams) -> None:
    sql("update proxy.quotas set enabled = true, cap = 2, burst = 0")
    reload(client)
    headers = open_session(client)
    codes = [client.get("/apps/warehouse/low-stock", headers=headers).status_code for _ in range(3)]
    assert codes == [200, 200, 429]
    limited = client.get("/apps/warehouse/low-stock", headers=headers)
    assert int(limited.headers["retry-after"]) > 0
    row = decision(limited.json()["decision_id"])
    assert row["verdict"] == "rate_limited" and row["quota_id"] == "quota_purchasing_hourly"


def test_budget_is_enforced_from_ledger(client, upstreams) -> None:
    headers = prepare(client, upstreams)
    sql("insert into proxy.spend_ledger (agent_id, app_id, amount, currency) values ('purchasing-agent', 'marketplace', 19000, 'PLN')")
    response = client.post("/apps/marketplace/orders", json=order(), headers=headers)
    assert response.status_code == 403
    assert "marketplace.budget_exceeded" in {r["code"] for r in decision(response.json()["decision_id"])["reasons"]}


def test_ui_rule_deny_and_needs_ai(client, upstreams) -> None:
    created = client.post("/api/v1/agents/purchasing-agent/rules", json={
        "name": "No big searches", "tool": "marketplace.search_products",
        "when": {"combinator": "and", "children": [{"id": "1", "field": "sku", "op": "eq", "value": "TON-HP-59A"}]},
        "then": "deny",
    })
    assert created.status_code == 201, created.text
    client.post("/api/v1/agents/purchasing-agent/rules", json={
        "name": "Review warehouse", "tool": "warehouse.*", "when": {"combinator": "and", "children": []}, "then": "needs_ai",
    })
    reload(client)
    headers = open_session(client)
    denied = client.get("/apps/marketplace/search?sku=TON-HP-59A", headers=headers)
    assert denied.status_code == 403
    assert decision(denied.json()["decision_id"])["chain"][1]["outcome"] == "deny"

    assert client.get("/apps/marketplace/search?sku=PAP-A4-80", headers=headers).status_code == 200
    escalated = client.get("/apps/warehouse/low-stock", headers=headers)
    assert escalated.status_code == 202
    assert "specialist.unavailable" in {r["code"] for r in decision(escalated.json()["decision_id"])["reasons"]}


def test_enrichment_failure_fails_closed_for_write(client, upstreams) -> None:
    headers = prepare(client, upstreams)
    original = upstreams._marketplace

    def broken(method, path, request):
        if path.startswith("/merchants/"):
            import httpx

            return httpx.Response(500)
        return original(method, path, request)

    upstreams._marketplace = broken
    response = client.post("/apps/marketplace/orders", json=order(), headers=headers)
    assert response.status_code == 403
    row = decision(response.json()["decision_id"])
    assert row["degraded"] is True
    assert "marketplace.merchant_unknown" in {r["code"] for r in row["reasons"]}


def test_agent_cannot_poll_foreign_approval(client, upstreams) -> None:
    headers = prepare(client, upstreams, "fresh_domain_discount")
    body = client.post("/apps/marketplace/orders", json=order("off_pr_pap", price="36.00"), headers=headers).json()
    other = client.post("/api/v1/agents", json={"id": "other-agent", "name": "Other", "mandate": "x"}).json()
    response = client.get(f"/v1/approvals/{body['approval_id']}", headers={"Authorization": f"Bearer {other['apiKey']}"})
    # nowy agent jest w snapshocie dopiero po przeładowaniu
    assert response.status_code == 401
    reload(client)
    response = client.get(f"/v1/approvals/{body['approval_id']}", headers={"Authorization": f"Bearer {other['apiKey']}"})
    assert response.status_code == 404
