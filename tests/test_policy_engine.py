"""S9 — testy akceptacyjne (DoD) na fixture'ach, bez sieci i bazy."""

import time

import pytest

from app.cli import POLICIES_DIR, read_pack
from app.config.models import AgentConfig, AppConfig, ConfigSnapshot, Protocol
from app.pipeline.models import Action
from app.policy.cedar import CedarPolicyEngine, PolicyCompileError, compile_pack

AGENT = "purchasing-agent"
PERMISSIONS = frozenset({"marketplace.place_order", "marketplace.search_products", "warehouse.register_po"})


def pack(app_id: str, overrides: dict | None = None):
    raw = read_pack(POLICIES_DIR / app_id)
    return compile_pack(app_id, raw["policies"], raw["schema"], raw["params"], raw["params_schema"],
                        raw["overrides"] if overrides is None else overrides)


def snapshot(permissions=PERMISSIONS) -> ConfigSnapshot:
    return ConfigSnapshot(
        revision=42,
        apps={app: AppConfig(id=app, name=app, protocol=Protocol.REST, upstream_url=f"http://{app}", timeout_seconds=5)
              for app in ("marketplace", "warehouse")},
        agents={AGENT: AgentConfig(id=AGENT, name="Purchasing", status="active", mandate="restock", permissions=permissions)},
        policy_packs={"marketplace": pack("marketplace"), "warehouse": pack("warehouse")},
    )


PLN = lambda amount: {"amount": amount, "currency": "PLN"}  # noqa: E731

SESSION = {
    "stock_needs": [{"sku": "PAP-A4-80", "qty_needed": 40}],
    "offers_seen": [
        {"offer_id": "off_bm_pap", "merchant_id": "mer_biuromax", "sku": "PAP-A4-80", "unit_price": PLN("118.00")},
        {"offer_id": "off_cd_pap", "merchant_id": "mer_cheapdeals", "sku": "PAP-A4-80", "unit_price": PLN("61.00")},
        {"offer_id": "off_pr_pap", "merchant_id": "mer_promocje", "sku": "PAP-A4-80", "unit_price": PLN("36.00")},
    ],
}

MERCHANTS = {
    "mer_biuromax": {"id": "mer_biuromax", "country": "PL", "domain_registered_at": "2014-05-12", "verified": True},
    "mer_cheapdeals": {"id": "mer_cheapdeals", "country": "IN", "domain_registered_at": "2020-01-10", "verified": True},
    "mer_promocje": {"id": "mer_promocje", "country": "PL", "domain_age_days": 5, "verified": False},
}


def enrichment(offer_id: str, merchant_id: str, price: str) -> dict:
    return {
        "offer": {"offer_id": offer_id, "merchant": {"id": merchant_id}, "product": {"sku": "PAP-A4-80"}, "unit_price": PLN(price)},
        "merchant": MERCHANTS[merchant_id],
    }


def order(offer_id="off_bm_pap", quantity=40, price="118.00") -> Action:
    return Action(app="marketplace", tool="marketplace.place_order", kind="write",
                  args={"offer_id": offer_id, "quantity": quantity, "unit_price": PLN(price)},
                  session_id="ses_1", agent_id=AGENT)


def evaluate(action: Action, enrich: dict, session=SESSION, spent=None, snap=None):
    return CedarPolicyEngine().evaluate(snap or snapshot(), action, session, enrich, spent or {"24h": 0}, expects_merchant=True)


def codes(result) -> set[str]:
    return {reason.code for reason in result.reasons}


def test_happy_path_allows() -> None:
    result = evaluate(order(), enrichment("off_bm_pap", "mer_biuromax", "118.00"))
    assert result.verdict == "allow", result.reasons
    assert result.reasons == []
    assert result.config_revision == 42


def test_foreign_cheapest_denied() -> None:
    result = evaluate(order("off_cd_pap", price="61.00"), enrichment("off_cd_pap", "mer_cheapdeals", "61.00"))
    assert result.verdict == "deny"
    assert "marketplace.country_not_allowed" in codes(result)


def test_ungrounded_offer_denied() -> None:
    result = evaluate(order("off_other", price="99.00"), enrichment("off_bm_pap", "mer_biuromax", "99.00"))
    assert result.verdict == "deny"
    assert "marketplace.offer_not_grounded" in codes(result)


def test_changed_price_denied() -> None:
    result = evaluate(order(price="100.00"), enrichment("off_bm_pap", "mer_biuromax", "118.00"))
    assert result.verdict == "deny"
    assert "marketplace.price_mismatch" in codes(result)


def test_qty_400_instead_of_40_with_demo_prices_is_denied_by_order_value() -> None:
    """Tabela scenariuszy zakłada ESCALATE, ale 400 × 118 PLN = 47 200 PLN > limit agenta 5 000 PLN → DENY.

    `qty_ratio_exceeded` (escalate) jest w powodach; deny wygrywa przez `order_value_exceeded`.
    """
    result = evaluate(order(quantity=400), enrichment("off_bm_pap", "mer_biuromax", "118.00"))
    assert result.verdict == "deny"
    assert {"marketplace.qty_ratio_exceeded", "marketplace.order_value_exceeded"} <= codes(result)
    assert result.facts["qty_ratio_pct"] == 1000


def test_qty_ratio_alone_is_escalate() -> None:
    session = {"stock_needs": [{"sku": "PAP-A4-80", "qty_needed": 4}],
               "offers_seen": [{"offer_id": "off_bm_pap", "merchant_id": "mer_biuromax", "sku": "PAP-A4-80", "unit_price": PLN("10.00")}]}
    result = evaluate(order(quantity=40, price="10.00"), enrichment("off_bm_pap", "mer_biuromax", "10.00"), session=session)
    assert result.verdict == "escalate"
    assert codes(result) == {"marketplace.qty_ratio_exceeded"}


def test_young_domain_escalates() -> None:
    result = evaluate(order("off_pr_pap", price="36.00"), enrichment("off_pr_pap", "mer_promocje", "36.00"))
    assert result.verdict == "escalate"
    assert codes(result) == {"marketplace.merchant_too_young"}


def test_budget_exceeded_denied() -> None:
    result = evaluate(order(), enrichment("off_bm_pap", "mer_biuromax", "118.00"), spent={"24h": 1_990_000})
    assert result.verdict == "deny"
    assert "marketplace.budget_exceeded" in codes(result)


def test_action_without_permission_denied() -> None:
    snap = snapshot(permissions=frozenset({"marketplace.search_products"}))
    result = evaluate(order(), enrichment("off_bm_pap", "mer_biuromax", "118.00"), snap=snap)
    assert result.verdict == "deny"
    assert codes(result) == {"permission_denied"}


def test_missing_enrichment_on_write_denied() -> None:
    result = evaluate(order(), {})
    assert result.verdict == "deny"
    assert "marketplace.merchant_unknown" in codes(result)


def test_multiple_violations_reported_together() -> None:
    session = {**SESSION, "stock_needs": [{"sku": "PAP-A4-80", "qty_needed": 40}]}
    result = evaluate(order("off_cd_pap", quantity=400, price="61.00"), enrichment("off_cd_pap", "mer_cheapdeals", "61.00"), session=session)
    assert result.verdict == "deny"
    assert {"marketplace.country_not_allowed", "marketplace.qty_ratio_exceeded"} <= codes(result)


def test_override_that_loosens_is_rejected() -> None:
    with pytest.raises(PolicyCompileError, match="adds values"):
        pack("marketplace", overrides={AGENT: {"place_order": {"allowed_countries": ["PL", "US"]}}})


def test_override_cannot_raise_limits() -> None:
    with pytest.raises(PolicyCompileError, match="raises"):
        pack("marketplace", overrides={AGENT: {"place_order": {"max_order_value": PLN("50000.00")}}})


def test_permit_policies_are_rejected() -> None:
    with pytest.raises(PolicyCompileError, match="forbid"):
        compile_pack("x", '@id("x")\npermit(principal, action, resource);', "", {}, {}, {})


def test_invalid_policy_against_schema_rejected() -> None:
    raw = read_pack(POLICIES_DIR / "marketplace")
    broken = raw["policies"] + '\n@id("bad")\nforbid(principal, action == Action::"marketplace.place_order", resource) when { context.nope };'
    with pytest.raises(PolicyCompileError):
        compile_pack("marketplace", broken, raw["schema"], raw["params"], raw["params_schema"], {})


def test_app_without_pack_allows() -> None:
    snap = snapshot().model_copy(update={"policy_packs": {}})
    result = evaluate(order(), {}, snap=snap)
    assert result.verdict == "allow"


def test_warehouse_po_must_reference_order_from_session() -> None:
    action = Action(app="warehouse", tool="warehouse.register_po", kind="write",
                    args={"sku": "PAP-A4-80", "quantity": 40, "marketplace_order_id": "ord_x"}, session_id="s", agent_id=AGENT)
    result = CedarPolicyEngine().evaluate(snapshot(), action, SESSION, {}, {})
    assert result.verdict == "deny"
    assert codes(result) == {"warehouse.po_not_grounded"}

    session = {**SESSION, "orders_placed": [{"order_id": "ord_x"}]}
    assert CedarPolicyEngine().evaluate(snapshot(), action, session, {}, {}).verdict == "allow"


def test_evaluate_is_fast() -> None:
    snap, action, enrich = snapshot(), order(), enrichment("off_bm_pap", "mer_biuromax", "118.00")
    engine = CedarPolicyEngine()
    timings = []
    for _ in range(200):
        started = time.perf_counter()
        engine.evaluate(snap, action, SESSION, enrich, {"24h": 0}, expects_merchant=True)
        timings.append((time.perf_counter() - started) * 1000)
    timings.sort()
    assert timings[int(len(timings) * 0.99)] < 5
