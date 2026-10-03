// Pakiet marketplace — tylko reguły forbid; silnik dokleja bazowy permit.
// Każda reguła: @id (kod powodu w audycie), @severity (deny | escalate), @message (dla dashboardu).

@id("marketplace.country_not_allowed")
@severity("deny")
@message("Merchant country is not on the allowlist")
forbid(principal, action == Action::"marketplace.place_order", resource)
unless { context.params.allowed_countries.contains(resource.country) };

@id("marketplace.merchant_unknown")
@severity("deny")
@message("Merchant profile could not be verified")
forbid(principal, action == Action::"marketplace.place_order", resource)
unless { resource.known };

@id("marketplace.offer_not_grounded")
@severity("deny")
@message("Offer was not returned by a search in this session")
forbid(principal, action == Action::"marketplace.place_order", resource)
when { context.params.require_grounded_offer && !context.offer_seen_in_session };

@id("marketplace.merchant_mismatch")
@severity("deny")
@message("Offer merchant differs from the one seen in search results")
forbid(principal, action == Action::"marketplace.place_order", resource)
when { context.offer_seen_in_session && !context.merchant_matches };

@id("marketplace.price_mismatch")
@severity("deny")
@message("Order price differs from the price seen in search results")
forbid(principal, action == Action::"marketplace.place_order", resource)
when { context.offer_seen_in_session && !context.price_matches };

@id("marketplace.currency_mismatch")
@severity("deny")
@message("Order currency differs from the policy currency")
forbid(principal, action == Action::"marketplace.place_order", resource)
unless { context.currency_matches };

@id("marketplace.order_value_exceeded")
@severity("deny")
@message("Order value exceeds the maximum")
forbid(principal, action == Action::"marketplace.place_order", resource)
when { context.order_value_minor > context.params.max_order_value_minor };

@id("marketplace.budget_exceeded")
@severity("deny")
@message("Order would exceed the 24h budget")
forbid(principal, action == Action::"marketplace.place_order", resource)
when { context.spent_24h_minor + context.order_value_minor > context.params.budget_24h_minor };

@id("marketplace.sku_not_needed")
@severity("escalate")
@message("Product is not on the low-stock list for this session")
forbid(principal, action == Action::"marketplace.place_order", resource)
unless { context.sku_needed };

@id("marketplace.qty_ratio_exceeded")
@severity("escalate")
@message("Ordered quantity is well above the quantity needed")
forbid(principal, action == Action::"marketplace.place_order", resource)
when { context.qty_ratio_pct > context.params.max_qty_ratio_pct };

@id("marketplace.merchant_too_young")
@severity("escalate")
@message("Merchant domain is younger than the minimum age")
forbid(principal, action == Action::"marketplace.place_order", resource)
when { resource.domain_age_days < context.params.min_merchant_age_days };
