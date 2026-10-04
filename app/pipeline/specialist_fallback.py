"""Deterministic specialist Choice when TypeSafe Jev is unavailable or errors.

Uses policy reasons + facts already computed by the pipeline so escalate demos
(e.g. young merchant) still produce real allow/deny probs for the UI.
"""

from __future__ import annotations

from typing import Any

from app.pipeline.jev_packs import SpecialistPack
from app.pipeline.models import MlSignals

# Policy codes that mean "borderline → human", not hard abuse.
CAUTION_REASONS = {
    "marketplace.merchant_too_young",
    "marketplace.qty_ratio_exceeded",
    "marketplace.sku_not_needed",
}


def heuristic_score(
    pack: SpecialistPack,
    facts: dict[str, Any],
    policy_reasons: list[str] | None,
    *,
    version: str = "jev-fallback",
    latency_ms: float = 1.0,
) -> MlSignals:
    reasons = set(policy_reasons or [])
    qty_ratio = int(facts.get("qty_ratio_pct") or 0)
    sku_needed = bool(facts.get("sku_needed"))
    merchant_age = int(facts.get("merchant_domain_age_days") or 0)
    offer_seen = bool(facts.get("offer_seen_in_session"))

    # Extreme over-order without need → deny.
    if qty_ratio >= 500 or (not sku_needed and "marketplace.sku_not_needed" in reasons):
        choice, probs, confidence = "deny", {"clear": 0.08, "caution": 0.22, "deny": 0.70}, 0.84
    elif reasons & CAUTION_REASONS or merchant_age and merchant_age < 180 or qty_ratio > 120:
        # Young merchant / over-qty / missing SKU need — classic HITL caution.
        choice, probs, confidence = "caution", {"clear": 0.16, "caution": 0.70, "deny": 0.14}, 0.86
    elif sku_needed and offer_seen and qty_ratio and qty_ratio <= 120:
        choice, probs, confidence = "clear", {"clear": 0.88, "caution": 0.09, "deny": 0.03}, 0.87
    else:
        choice, probs, confidence = "caution", {"clear": 0.28, "caution": 0.55, "deny": 0.17}, 0.72

    return MlSignals(
        available=True,
        alignment=probs["clear"],
        p_malicious=probs["deny"],
        choice=choice,  # type: ignore[arg-type]
        confidence=confidence,
        specialist=pack.model_id,
        version=version,
        latency_ms=latency_ms,
    )
