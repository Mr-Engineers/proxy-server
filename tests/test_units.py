"""Czyste funkcje: JSONPath, redakcja, katalog/capture, reguły UI, agregator, parametry, okna Overview, klucze."""

from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.admin.overview import resolve_window
from app.auth.agent import AgentAuthError, AgentAuthenticator, generate_key
from app.config.models import AgentConfig, AgentKey, CaptureRule, ConfigSnapshot, RuleConfig, ToolConfig
from app.core.jsonpath import find, first, set_all
from app.core.redact import MASK, redact
from app.pipeline.aggregator import aggregate
from app.pipeline.catalog import apply_capture, extract_args, match_route, request_document, scan_texts
from app.pipeline.models import MlSignals, PolicyResult, Reason, Verdict
from app.pipeline.rules import RuleError, evaluate_rules, validate_condition
from app.policy.params import ParamsError, merge_override, to_cedar

# --- JSONPath ---------------------------------------------------------------


def test_jsonpath_find() -> None:
    doc = {"offers": [{"id": 1, "m": {"id": "a"}}, {"id": 2, "m": {"id": "b"}}], "x": {"y-z": 3}}
    assert find(doc, "$.offers[*].m.id") == ["a", "b"]
    assert first(doc, "$.offers[1].id") == 2
    assert first(doc, "$.x['y-z']") == 3
    assert find(doc, "$.missing.path") == []
    assert first(doc, "$") == doc


def test_jsonpath_set_all() -> None:
    doc = {"items": [{"card": "1"}, {"card": "2"}]}
    set_all(doc, "$.items[*].card", "***")
    assert doc == {"items": [{"card": "***"}, {"card": "***"}]}


# --- redakcja ---------------------------------------------------------------


def test_redact_heuristics_and_paths() -> None:
    payload = {
        "sku": "PAP-A4-80",
        "quantity": 38,
        "api_key": "abc",
        "contact": "jan@example.com",
        "note": "ak_k7f3a2_supersecretvalue123",
        "phone_number": "+48 600 700 800",
        "total_eur": 120,
        "nested": [{"password": "x", "ok": "short"}],
    }
    result = redact(payload, ["$.total_eur"])
    assert result["sku"] == "PAP-A4-80"
    assert result["quantity"] == 38
    assert result["api_key"] == MASK
    assert result["contact"] == MASK
    assert result["note"] == MASK
    assert result["phone_number"] == MASK
    assert result["total_eur"] == MASK
    assert result["nested"] == [{"password": MASK, "ok": "short"}]
    assert payload["api_key"] == "abc"


# --- katalog i capture ------------------------------------------------------

SEARCH = ToolConfig(
    id="t1", app_id="marketplace", name="search_products", kind="read", http_method="GET", http_path="/search",
    args={"sku": "$.sku"},
    capture=(CaptureRule(into="offers_seen", source="$.offers[*]", key="offer_id",
                         fields={"offer_id": "offer_id", "merchant_id": "merchant.id"}),),
    scan_mode="selected", scan=("$.offers[*].description",),
)
OFFER = ToolConfig(id="t2", app_id="marketplace", name="get_offer", kind="read", http_method="GET", http_path="/offers/{offer_id}")


def test_route_matching_with_path_params() -> None:
    snapshot = ConfigSnapshot(revision=1, apps={}, tools={"marketplace": (SEARCH, OFFER)})
    assert match_route(snapshot, "marketplace", "GET", "/search")[0] is SEARCH
    tool, params = match_route(snapshot, "marketplace", "GET", "/offers/off_1")
    assert tool is OFFER and params == {"offer_id": "off_1"}
    assert match_route(snapshot, "marketplace", "POST", "/search") is None
    assert match_route(snapshot, "marketplace", "GET", "/offers/a/b") is None


def test_args_and_request_document() -> None:
    document = request_document("sku=PAP&limit=5", {"id": "x"}, b'{"q": "papier"}')
    assert document == {"sku": "PAP", "limit": "5", "id": "x", "q": "papier"}
    assert extract_args(SEARCH, document) == {"sku": "PAP"}


def test_capture_dedupes_by_key() -> None:
    response = {"offers": [{"offer_id": "o1", "merchant": {"id": "m1"}, "description": "x" * 20},
                           {"offer_id": "o2", "merchant": {"id": "m2"}, "description": "short"}]}
    state = apply_capture({"offers_seen": [{"offer_id": "o1", "merchant_id": "old"}]}, SEARCH, {}, response)
    assert state["offers_seen"] == [{"offer_id": "o1", "merchant_id": "m1"}, {"offer_id": "o2", "merchant_id": "m2"}]
    assert scan_texts(SEARCH, response) == ["x" * 20]


# --- reguły UI ----------------------------------------------------------------


def rule(rule_id: str, tool: str, when: dict, then: str, enabled: bool = True) -> RuleConfig:
    return RuleConfig(id=rule_id, agent_id="a", name=rule_id, tool=tool, condition=when, outcome=then, enabled=enabled)


def test_rules_first_match_wins() -> None:
    rules = [
        rule("off", "*", {"combinator": "and", "children": []}, "deny", enabled=False),
        rule("big", "marketplace.place_order", {"combinator": "or", "children": [
            {"id": "1", "field": "quantity", "op": "gt", "value": 100},
            {"id": "2", "field": "unit_price", "op": "gte", "value": 1000},
        ]}, "needs_ai"),
        rule("orders", "marketplace.*", {"combinator": "and", "children": []}, "allow"),
    ]
    big = evaluate_rules(rules, "marketplace.place_order", {"quantity": 400}, {})
    assert big.rule_id == "big" and big.outcome == "needs_ai"
    priced = evaluate_rules(rules, "marketplace.place_order", {"quantity": 1, "unit_price": {"amount": "1200.00"}}, {})
    assert priced.rule_id == "big"
    small = evaluate_rules(rules, "marketplace.place_order", {"quantity": 4}, {})
    assert small.rule_id == "orders" and small.outcome == "allow"
    assert evaluate_rules(rules, "warehouse.register_po", {}, {}).outcome is None


def test_rule_ops() -> None:
    def check(op, value, actual) -> bool:
        return evaluate_rules([rule("r", "*", {"field": "f", "op": op, "value": value}, "deny")], "t", {"f": actual} if actual is not None else {}, {}).outcome == "deny"

    assert check("eq", "pl", "PL")
    assert check("neq", 1, 2)
    assert check("in", ["PL", "DE"], "DE")
    assert check("not_in", ["IN"], "PL")
    assert check("lte", 5, "5")
    assert check("is_empty", None, None)
    assert check("not_empty", None, "x")
    assert not check("gt", 5, None)
    assert not check("gt", 5, "abc")


def test_rule_validation() -> None:
    validate_condition({"combinator": "and", "children": [{"field": "a", "op": "eq", "value": 1}]})
    with pytest.raises(RuleError):
        validate_condition({"field": "a", "op": "contains", "value": 1})
    with pytest.raises(RuleError):
        validate_condition({"field": "a", "op": "in", "value": 1})


# --- agregator v0 -------------------------------------------------------------


def policy(verdict: str, *reasons: Reason) -> PolicyResult:
    return PolicyResult(verdict=verdict, reasons=list(reasons), config_revision=1)


def test_aggregator_v0() -> None:
    none = MlSignals()
    assert aggregate("write", policy("deny"), none, False, True, True).verdict is Verdict.DENY
    assert aggregate("write", policy("escalate"), none, False, False, True).verdict is Verdict.ESCALATE
    assert aggregate("write", policy("allow"), none, True, False, True).verdict is Verdict.ESCALATE
    assert aggregate("write", policy("allow"), none, True, False, False).verdict is Verdict.ALLOW
    assert aggregate("read", policy("allow"), none, False, False, True).verdict is Verdict.ALLOW
    ruled = aggregate("write", policy("allow"), none, False, True, True)
    assert ruled.verdict is Verdict.ALLOW and ruled.specialist_detail == "Rule short-circuit"
    failed = MlSignals(failed=True, specialist="jev", version="jev-latest")
    failed_agg = aggregate("write", policy("allow"), failed, True, False, True)
    assert failed_agg.verdict is Verdict.ESCALATE
    assert "specialist.failed" in {r.code for r in failed_agg.reasons}
    assert failed_agg.allow_prob is None and failed_agg.deny_prob is None
    skipped = aggregate("write", policy("allow"), none, True, False, True)
    assert skipped.allow_prob is None and skipped.deny_prob is None


def test_aggregator_with_ml_signals() -> None:
    risky = MlSignals(available=True, p_malicious=0.9)
    assert aggregate("write", policy("allow"), risky, False, False, True).verdict is Verdict.DENY
    medium = MlSignals(available=True, p_malicious=0.5)
    result = aggregate("write", policy("allow"), medium, False, False, True)
    assert result.verdict is Verdict.ESCALATE and result.deny_prob == 0.5
    assert aggregate("read", policy("allow"), medium, False, False, True).verdict is Verdict.ALLOW
    cleared = aggregate("write", policy("escalate"), MlSignals(available=True, p_malicious=0.1), False, False, True)
    assert cleared.verdict is Verdict.ALLOW and cleared.specialist_outcome == "clear"


def test_aggregator_choice_confidence() -> None:
    clear = MlSignals(available=True, choice="clear", confidence=0.9, alignment=0.9, p_malicious=0.05)
    assert aggregate("write", policy("escalate"), clear, False, False, True).verdict is Verdict.ALLOW

    low_conf = MlSignals(available=True, choice="clear", confidence=0.4, alignment=0.7, p_malicious=0.1)
    assert aggregate("write", policy("escalate"), low_conf, False, False, True).verdict is Verdict.ESCALATE

    deny = MlSignals(available=True, choice="deny", confidence=0.9, alignment=0.05, p_malicious=0.9)
    assert aggregate("write", policy("escalate"), deny, False, False, True).verdict is Verdict.DENY

    caution = MlSignals(available=True, choice="caution", confidence=0.85, alignment=0.4, p_malicious=0.2)
    assert aggregate("write", policy("escalate"), caution, False, False, True).verdict is Verdict.ESCALATE

    hard = policy("deny", Reason(code="x", severity="deny"))
    assert aggregate("write", hard, clear, False, False, True).verdict is Verdict.DENY


# --- Jev packs / scorer -------------------------------------------------------


def test_resolve_use_case_and_describe() -> None:
    from app.pipeline.jev import JevScorer
    from app.pipeline.jev_packs import load_packs, resolve_use_case
    from app.pipeline.ml import NullScorer

    packs = load_packs()
    assert len(packs) == 1 and packs[0].id == "spc_jev"
    assert resolve_use_case("purchasing-agent") == "purchasing"
    assert resolve_use_case("unknown-agent") == "purchasing"

    # Without a key / inject, JevScorer cannot call TypeSafe.
    unloaded = JevScorer(api_key=None).describe()
    assert {card["id"] for card in unloaded} == {"spc_jev"}
    assert unloaded[0]["health"] == "unavailable"
    live = JevScorer(system_one=None, api_key="test-key-not-used-for-describe").describe()
    # api_key constructs a client → healthy card (no network yet)
    assert live[0]["health"] == "healthy"
    null_cards = NullScorer().describe()
    assert {card["id"] for card in null_cards} == {"spc_jev"}
    assert null_cards[0]["health"] == "unavailable"


def test_jev_scorer_maps_choice() -> None:
    import asyncio
    from types import SimpleNamespace

    from app.pipeline.jev import JevScorer
    from app.pipeline.models import Action
    from typesafe_sdk import Choice

    async def fake_system_one(**kwargs):
        assert kwargs["state"]["tool"] == "marketplace.place_order"
        assert "marketplace.qty_ratio_exceeded" in kwargs["state"]["policy_reasons"]
        question = kwargs["questions"]["verdict"]
        assert isinstance(question, Choice)
        assert question.type == "choice"
        return SimpleNamespace(
            model="jev-test",
            choices={
                "verdict": SimpleNamespace(
                    choice="clear",
                    probabilities={"clear": 0.88, "caution": 0.1, "deny": 0.02},
                    confidence=0.86,
                )
            },
            answers={},
        )

    async def run() -> None:
        scorer = JevScorer(system_one=fake_system_one, model="jev-test")
        agent = AgentConfig(id="purchasing-agent", name="P", status="active", mandate="restock low stock")
        action = Action(
            app="marketplace", tool="marketplace.place_order", kind="write",
            args={"quantity": 40}, session_id="s1", agent_id=agent.id,
        )
        signals = await scorer.score(
            action, agent, {"stock_needs": [{"sku": "PAP"}]}, {},
            {"qty_ratio_pct": 120}, policy_reasons=["marketplace.qty_ratio_exceeded"],
        )
        assert signals.available and signals.choice == "clear"
        assert signals.confidence == 0.86 and signals.alignment == 0.88
        assert signals.specialist == "jev"

    asyncio.run(run())


# --- parametry pakietów -------------------------------------------------------

SCHEMA = {"place_order": {
    "allowed_countries": {"type": "allowlist"}, "max_order_value": {"type": "max_money"},
    "min_merchant_age_days": {"type": "min_number"}, "require_grounded_offer": {"type": "flag"},
    "budget": {"type": "budget"},
}}
BASE = {"place_order": {
    "allowed_countries": ["PL", "DE"], "max_order_value": {"amount": "100.00", "currency": "PLN"},
    "min_merchant_age_days": 30, "require_grounded_offer": True,
    "budget": [{"window": "24h", "amount": "500.00", "currency": "PLN"}],
}}


def test_params_merge_tightens_and_converts() -> None:
    merged = merge_override(SCHEMA, BASE, {"place_order": {
        "allowed_countries": ["PL"], "min_merchant_age_days": 90,
        "budget": [{"window": "24h", "amount": "200.00", "currency": "PLN"}],
    }}, "o")
    cedar = to_cedar(SCHEMA, merged["place_order"], "place_order")
    assert cedar["allowed_countries"] == ["PL"]
    assert cedar["min_merchant_age_days"] == 90
    assert cedar["max_order_value_minor"] == 10000
    assert cedar["budget_24h_minor"] == 20000 and cedar["budget_currency"] == "PLN"


@pytest.mark.parametrize("override", [
    {"min_merchant_age_days": 1},
    {"require_grounded_offer": False},
    {"budget": [{"window": "24h", "amount": "900.00", "currency": "PLN"}]},
    {"max_order_value": {"amount": "100.00", "currency": "EUR"}},
])
def test_params_merge_rejects_loosening(override: dict) -> None:
    with pytest.raises(ParamsError):
        merge_override(SCHEMA, BASE, {"place_order": override}, "o")


# --- okna Overview ----------------------------------------------------------------


def test_overview_window_today_in_timezone() -> None:
    now = datetime(2026, 10, 3, 19, 0, tzinfo=timezone.utc)
    window = resolve_window(None, None, None, "Europe/Warsaw", None, now=now)
    data = window.as_json()
    assert data["preset"] == "today" and data["bucket"] == "5m"
    assert data["start"] == "2026-10-03T00:00:00+02:00"
    assert data["previousStart"] == "2026-10-02T00:00:00+02:00"
    assert data["compareLabel"] == "vs yesterday"


def test_overview_window_validation() -> None:
    assert resolve_window("7d", None, None, "UTC", None).bucket == "1h"
    custom = resolve_window(None, "2026-09-01T00:00:00+02:00", "2026-09-15T00:00:00+02:00", "UTC", None)
    assert custom.preset == "custom" and custom.bucket == "1d"  # 14 dni × 1h = 336 punktów > 300
    for args in [("5d", None, None), (None, "2026-09-01T00:00:00Z", None),
                 (None, "2026-09-15T00:00:00Z", "2026-09-01T00:00:00Z"), (None, "2026-01-01T00:00:00Z", "2026-06-01T00:00:00Z")]:
        with pytest.raises(HTTPException):
            resolve_window(*args, "UTC", None)


# --- klucze agentów -----------------------------------------------------------------


def test_agent_key_roundtrip() -> None:
    key = generate_key()
    agent = AgentConfig(id="a1", name="A", status="active", mandate="m")
    snapshot = ConfigSnapshot(revision=1, apps={}, agents={"a1": agent},
                              keys={key.key_id: AgentKey(id=key.key_id, agent_id="a1", sha256=key.sha256)})
    auth = AgentAuthenticator()
    assert auth.authenticate(snapshot, f"Bearer {key.token}").agent_id == "a1"
    for header in (None, "Basic x", "Bearer nope", f"Bearer {key.token}x"):
        with pytest.raises(AgentAuthError) as exc:
            auth.authenticate(snapshot, header)
        assert exc.value.status_code == 401
    disabled = snapshot.model_copy(update={"agents": {"a1": agent.model_copy(update={"status": "disabled"})}})
    with pytest.raises(AgentAuthError) as exc:
        auth.authenticate(disabled, f"Bearer {key.token}")
    assert exc.value.status_code == 403
