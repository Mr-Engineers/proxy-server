"""Agregator v0 (S10): reguły. Zastępowany przez v1 (M5) z P(malicious) i progami τ per typ akcji.

Zasady:
- `deny` z polityk / RBAC / reguł UI jest ostateczne — agregator nie zamienia go na allow;
- `escalate` z polityk lub `needs_ai` bez modeli → eskalacja do człowieka
  (gdy `specialist_fail_closed`; inaczej needs_ai przepuszcza);
- przy dostępnych sygnałach ML: p_malicious ≥ τ_high → deny, ≥ τ_low → escalate.
"""

from dataclasses import dataclass

from app.pipeline.models import MlSignals, PolicyResult, Reason, Verdict

TAU = {"read": (0.7, 0.95), "write": (0.3, 0.8)}


@dataclass
class Aggregate:
    verdict: Verdict
    confidence: float
    reasons: list[Reason]
    specialist_outcome: str
    specialist_detail: str
    allow_prob: float
    deny_prob: float


def aggregate(
    kind: str,
    policy: PolicyResult,
    signals: MlSignals,
    needs_ai: bool,
    rule_allowed: bool,
    fail_closed: bool,
) -> Aggregate:
    reasons = list(policy.reasons)
    tau_low, tau_high = TAU.get(kind, TAU["write"])

    if signals.available and signals.p_malicious is not None:
        p = signals.p_malicious
        allow_prob, deny_prob = round(1 - p, 4), round(p, 4)
    else:
        allow_prob = deny_prob = 0.5

    if policy.verdict == "deny":
        return Aggregate(Verdict.DENY, 1.0, reasons, "skipped", "Hard policy deny", 0.0, 1.0)

    if rule_allowed and policy.verdict == "allow":
        return Aggregate(Verdict.ALLOW, 1.0, reasons, "skipped", "Rule short-circuit", 1.0, 0.0)

    if signals.available and signals.p_malicious is not None:
        p = signals.p_malicious
        if p >= tau_high:
            reasons.append(Reason(code="ml.high_risk", severity="deny", message=f"P(malicious)={p:.2f}", source="ml"))
            return Aggregate(Verdict.DENY, p, reasons, "deny", f"P(malicious) {p:.2f} ≥ τ_high {tau_high}", allow_prob, deny_prob)
        if p >= tau_low or policy.verdict == "escalate" or needs_ai:
            if p >= tau_low:
                reasons.append(Reason(code="ml.elevated_risk", severity="escalate", message=f"P(malicious)={p:.2f}", source="ml"))
            return Aggregate(Verdict.ESCALATE, max(p, 0.5), reasons, "caution", "caution → human", allow_prob, deny_prob)
        return Aggregate(Verdict.ALLOW, 1 - p, reasons, "clear", f"P(malicious) {p:.2f} < τ_low {tau_low}", allow_prob, deny_prob)

    if policy.verdict == "escalate":
        return Aggregate(Verdict.ESCALATE, 0.5, reasons, "caution", "caution → human (policy)", allow_prob, deny_prob)
    if needs_ai:
        if fail_closed:
            reasons.append(Reason(code="specialist.unavailable", severity="escalate", message="No specialist model loaded", source="ml"))
            return Aggregate(Verdict.ESCALATE, 0.5, reasons, "caution", "No specialist loaded → human", allow_prob, deny_prob)
        return Aggregate(Verdict.ALLOW, 0.5, reasons, "skipped", "No specialist loaded, fail-open", allow_prob, deny_prob)
    return Aggregate(Verdict.ALLOW, 0.8, reasons, "skipped", "No specialist loaded", allow_prob, deny_prob)
