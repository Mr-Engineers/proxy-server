"""TypeSafe Jev question packs — one Choice verdict pack per use case."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SpecialistPack:
    id: str
    name: str
    use_case: str
    model_id: str
    criteria_summary: str
    agent_match: tuple[str, ...]  # substrings matched against agent_id (lowercase)
    instructions: str
    criteria: dict[str, str]


PURCHASING = SpecialistPack(
    id="spc_purchasing",
    name="Purchasing specialist",
    use_case="purchasing",
    model_id="local/purchasing",
    criteria_summary="Mandate alignment for restock orders: SKU need, qty ratio, merchant risk, session grounding.",
    agent_match=("purchasing", "shop", "restock", "buy"),
    instructions=(
        "Decide whether this tool call should be auto-allowed for a purchasing/restock agent. "
        "Compare `tool` and `args` to `mandate` and the session evidence in `facts`, `enrichment`, and `session`. "
        "Policy already flagged this call (`policy_reasons`); judge if it is still consistent with the agent's purpose. "
        "Prefer clear when the purchase restocks a needed SKU at a plausible quantity from a reasonable merchant. "
        "Prefer deny when the action clearly conflicts with the mandate (wrong purpose, abusive quantity, or ungated spend). "
        "Prefer caution when evidence is incomplete or the case is borderline."
    ),
    criteria={
        "clear": (
            "Action matches the purchasing mandate and session evidence "
            "(needed SKU, sensible qty, acceptable merchant); safe to auto-allow."
        ),
        "caution": (
            "Borderline restock risk or missing evidence; a human should review before the order proceeds."
        ),
        "deny": (
            "Action conflicts with the purchasing mandate or looks abusive "
            "(off-purpose buy, extreme over-order, or clearly unsafe merchant context); block."
        ),
    },
)


DISPUTE = SpecialistPack(
    id="spc_dispute",
    name="Dispute specialist",
    use_case="dispute",
    model_id="local/dispute",
    criteria_summary="Mandate alignment for refunds, chargebacks, and billing dispute actions.",
    agent_match=("dispute", "refund", "chargeback", "billing", "support"),
    instructions=(
        "Decide whether this tool call should be auto-allowed for a dispute/refund support agent. "
        "Compare `tool` and `args` to `mandate` and the evidence in `facts`, `enrichment`, and `session`. "
        "Policy already flagged this call (`policy_reasons`); judge if it is still consistent with resolving "
        "the customer's billing dispute within policy. "
        "Prefer clear for in-mandate refunds/adjustments with matching ticket/order evidence. "
        "Prefer deny for cross-tenant, out-of-policy goodwill, or abusive refund patterns. "
        "Prefer caution when ownership, amounts, or ticket context are incomplete or borderline."
    ),
    criteria={
        "clear": (
            "Action matches the dispute mandate and ticket/order evidence; safe to auto-allow."
        ),
        "caution": (
            "Borderline refund/dispute risk or missing evidence; a human should review."
        ),
        "deny": (
            "Action conflicts with the dispute mandate or looks abusive "
            "(wrong customer, excessive refund, privileged misuse); block."
        ),
    },
)


PACKS: dict[str, SpecialistPack] = {
    PURCHASING.use_case: PURCHASING,
    DISPUTE.use_case: DISPUTE,
}


def resolve_use_case(agent_id: str) -> str:
    needle = agent_id.lower()
    for pack in (DISPUTE, PURCHASING):
        if any(token in needle for token in pack.agent_match):
            return pack.use_case
    return PURCHASING.use_case


def pack_for(use_case: str) -> SpecialistPack:
    return PACKS.get(use_case, PURCHASING)


def choice_question(pack: SpecialistPack) -> dict[str, Any]:
    """Raw question dict (works with SDK objects or plain system_one dicts)."""
    return {
        "type": "choice",
        "instructions": pack.instructions,
        "criteria": dict(pack.criteria),
    }
