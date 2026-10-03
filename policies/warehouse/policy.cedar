// Pakiet warehouse — rejestracja PO tylko dla zamówień złożonych w tej sesji, w potrzebnej ilości.

@id("warehouse.po_not_grounded")
@severity("deny")
@message("Purchase order references a marketplace order not placed in this session")
forbid(principal, action == Action::"warehouse.register_po", resource)
when { context.params.require_placed_order && !context.order_seen_in_session };

@id("warehouse.qty_ratio_exceeded")
@severity("escalate")
@message("Registered quantity is well above the quantity needed")
forbid(principal, action == Action::"warehouse.register_po", resource)
when { context.qty_ratio_pct > context.params.max_qty_ratio_pct };
