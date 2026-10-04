"""Fakty dla polityk liczone w Pythonie (S9 — grounding).

Cedar nie ma floatów i pomija reguły z błędem ewaluacji, więc wszystkie fakty są zawsze
obecne, liczbowe wartości to `Long`, a brak danych daje wartość „najgorszą”.
"""

import math
from datetime import date, datetime, timezone
from decimal import Decimal, InvalidOperation
from typing import Any

QTY_RATIO_UNKNOWN = 999_999


def _int(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return None


def money(value: Any) -> tuple[int, str] | None:
    """`{"amount": "118.00", "currency": "PLN"}` → (11800, "PLN")."""
    if not isinstance(value, dict):
        return None
    try:
        minor = Decimal(str(value.get("amount"))) * 100
    except (InvalidOperation, TypeError):
        return None
    currency = value.get("currency")
    if not isinstance(currency, str):
        return None
    return int(minor.to_integral_value()), currency


def _get(obj: Any, *path: str) -> Any:
    for key in path:
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def _by_key(items: Any, key: str) -> dict[str, dict]:
    if not isinstance(items, list):
        return {}
    return {str(item[key]): item for item in items if isinstance(item, dict) and item.get(key) is not None}


def domain_age_days(merchant: dict, today: date | None = None) -> int:
    if isinstance(merchant.get("domain_age_days"), int):
        return merchant["domain_age_days"]
    raw = merchant.get("domain_registered_at")
    if not isinstance(raw, str):
        return 0
    try:
        registered = date.fromisoformat(raw[:10])
    except ValueError:
        return 0
    today = today or datetime.now(timezone.utc).date()
    return max((today - registered).days, 0)


def merchant_attrs(merchant: dict | None, today: date | None = None) -> dict[str, Any]:
    if not merchant:
        return {"country": "", "domain_age_days": 0, "verified": False, "reputation_pct": 0, "known": False}
    score = _get(merchant, "reputation", "score")
    return {
        "country": str(merchant.get("country") or ""),
        "domain_age_days": domain_age_days(merchant, today),
        "verified": bool(merchant.get("verified")),
        "reputation_pct": int(round(float(score) * 100)) if isinstance(score, (int, float)) else 0,
        "known": True,
    }


def compute_facts(
    args: dict[str, Any],
    session_state: dict[str, Any],
    enrichment: dict[str, Any],
    spent: dict[str, int],
) -> dict[str, Any]:
    offers_seen = _by_key(session_state.get("offers_seen"), "offer_id")
    stock_needs = _by_key(session_state.get("stock_needs"), "sku")
    orders_placed = _by_key(session_state.get("orders_placed"), "order_id")

    offer_id = args.get("offer_id")
    seen = offers_seen.get(str(offer_id)) if offer_id is not None else None
    offer = enrichment.get("offer") if isinstance(enrichment.get("offer"), dict) else None
    merchant = enrichment.get("merchant") if isinstance(enrichment.get("merchant"), dict) else None

    offer_merchant = _get(offer, "merchant", "id") or _get(offer, "merchant_id")
    merchant_matches = bool(seen and offer_merchant and seen.get("merchant_id") == offer_merchant)
    if merchant and offer_merchant and merchant.get("id") and merchant["id"] != offer_merchant:
        merchant_matches = False

    args_price = money(args.get("unit_price"))
    seen_price = money(seen.get("unit_price")) if seen else None
    live_price = money(offer.get("unit_price")) if offer else None
    price_matches = bool(args_price and seen_price and args_price == seen_price and (live_price is None or live_price == args_price))
    if offer is not None and live_price is None:
        price_matches = False

    sku = (seen or {}).get("sku") or _get(offer, "product", "sku") or args.get("sku")
    need = stock_needs.get(str(sku)) if sku else None
    qty_needed = _int(need.get("qty_needed")) if need else None
    quantity = _int(args.get("quantity"))

    if quantity is not None and qty_needed:
        qty_ratio_pct = math.ceil(quantity * 100 / qty_needed)
    else:
        qty_ratio_pct = QTY_RATIO_UNKNOWN

    price = args_price or seen_price or live_price
    order_value_minor = quantity * price[0] if quantity is not None and price else 0
    currency = price[1] if price else ""

    order_id = args.get("marketplace_order_id")

    facts: dict[str, Any] = {
        "offer_seen_in_session": seen is not None,
        "merchant_matches": merchant_matches,
        "price_matches": price_matches,
        "sku": str(sku or ""),
        "sku_needed": need is not None,
        "quantity": quantity if quantity is not None else 0,
        "qty_needed": qty_needed if qty_needed is not None else 0,
        "qty_ratio_pct": qty_ratio_pct,
        "order_value_minor": order_value_minor,
        "currency": currency,
        "order_seen_in_session": order_id is not None and str(order_id) in orders_placed,
        "merchant_known": merchant is not None,
        "merchant_id": str((merchant or {}).get("id") or offer_merchant or ""),
        "merchant_domain_age_days": int(merchant_attrs(merchant).get("domain_age_days") or 0),
    }
    for window, minor in spent.items():
        facts[f"spent_{window}_minor"] = minor
    return facts
