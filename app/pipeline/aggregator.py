"""Agregator v1: reguły + specjalista (Choice clear/caution/deny z confidence).

Zasady:
- `deny` z polityk / RBAC / reguł UI jest ostateczne — agregator nie zamienia go na allow;
- przy Choice ze specjalisty: confidence < τ_conf → HITL; clear/deny przy wystarczającej
  pewności mogą nadpisać escalate/needs_ai (w tym clear → allow);
- bez Choice, przy p_malicious: ≥ τ_high → deny, ≥ τ_low → escalate, inaczej allow
  (w tym clear escalate gdy ryzyko poniżej τ_low);
- `escalate` / `needs_ai` bez sygnałów → człowiek (gdy fail-closed).
"""

from dataclasses import dataclass

from app.pipeline.models import MlSignals, PolicyResult, Reason, Verdict

TAU = {"read": (0.7, 0.95), "write": (0.3, 0.8)}

# Confidence-gated routing for specialist Choice answers (TypeSafe pattern).
TAU_CONF = 0.6
TAU_CLEAR = {"read": 0.6, "write": 0.82}
TAU_DENY = {"read": 0.7, "write": 0.82}


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

    if signals.available and signals.alignment is not None and signals.p_malicious is not None:
        allow_prob, deny_prob = round(signals.alignment, 4), round(signals.p_malicious, 4)
    elif signals.available and signals.p_malicious is not None:
        p = signals.p_malicious
        allow_prob, deny_prob = round(1 - p, 4), round(p, 4)
    else:
        allow_prob = deny_prob = 0.5

    if policy.verdict == "deny":
        return Aggregate(Verdict.DENY, 1.0, reasons, "skipped", "Hard policy deny", 0.0, 1.0)

    if rule_allowed and policy.verdict == "allow":
        return Aggregate(Verdict.ALLOW, 1.0, reasons, "skipped", "Rule short-circuit", 1.0, 0.0)

    if signals.available and signals.choice is not None:
        return _aggregate_choice(kind, signals, reasons, allow_prob, deny_prob)

    if signals.available and signals.p_malicious is not None:
        p = signals.p_malicious
        if p >= tau_high:
            reasons.append(Reason(code="ml.high_risk", severity="deny", message=f"P(malicious)={p:.2f}", source="ml"))
            return Aggregate(Verdict.DENY, p, reasons, "deny", f"P(malicious) {p:.2f} ≥ τ_high {tau_high}", allow_prob, deny_prob)
        if p >= tau_low:
            reasons.append(Reason(code="ml.elevated_risk", severity="escalate", message=f"P(malicious)={p:.2f}", source="ml"))
            return Aggregate(Verdict.ESCALATE, max(p, 0.5), reasons, "caution", "caution → human", allow_prob, deny_prob)
        if policy.verdict == "escalate" or needs_ai:
            return Aggregate(
                Verdict.ALLOW, 1 - p, reasons, "clear",
                f"Specialist cleared (P(malicious) {p:.2f} < τ_low {tau_low})", allow_prob, deny_prob,
            )
        return Aggregate(Verdict.ALLOW, 1 - p, reasons, "clear", f"P(malicious) {p:.2f} < τ_low {tau_low}", allow_prob, deny_prob)

    if policy.verdict == "escalate":
        return Aggregate(Verdict.ESCALATE, 0.5, reasons, "caution", "caution → human (policy)", allow_prob, deny_prob)
    if needs_ai:
        if fail_closed:
            reasons.append(Reason(code="specialist.unavailable", severity="escalate", message="No specialist model loaded", source="ml"))
            return Aggregate(Verdict.ESCALATE, 0.5, reasons, "caution", "No specialist loaded → human", allow_prob, deny_prob)
        return Aggregate(Verdict.ALLOW, 0.5, reasons, "skipped", "No specialist loaded, fail-open", allow_prob, deny_prob)
    return Aggregate(Verdict.ALLOW, 0.8, reasons, "skipped", "No specialist loaded", allow_prob, deny_prob)


def _aggregate_choice(
    kind: str,
    signals: MlSignals,
    reasons: list[Reason],
    allow_prob: float,
    deny_prob: float,
) -> Aggregate:
    choice = signals.choice
    conf = signals.confidence if signals.confidence is not None else 0.0
    tau_clear = TAU_CLEAR.get(kind, TAU_CLEAR["write"])
    tau_deny = TAU_DENY.get(kind, TAU_DENY["write"])

    if conf < TAU_CONF:
        reasons.append(Reason(
            code="ml.low_confidence", severity="escalate",
            message=f"Specialist confidence {conf:.2f} < {TAU_CONF}", source="ml",
        ))
        return Aggregate(
            Verdict.ESCALATE, conf, reasons, "caution",
            f"low confidence ({conf:.2f}) → human", allow_prob, deny_prob,
        )

    if choice == "clear" and conf >= tau_clear:
        return Aggregate(
            Verdict.ALLOW, conf, reasons, "clear",
            f"specialist clear (confidence {conf:.2f})", allow_prob, deny_prob,
        )

    if choice == "deny" and conf >= tau_deny:
        reasons.append(Reason(
            code="ml.specialist_deny", severity="deny",
            message=f"Specialist deny (confidence {conf:.2f})", source="ml",
        ))
        return Aggregate(
            Verdict.DENY, conf, reasons, "deny",
            f"specialist deny (confidence {conf:.2f})", allow_prob, deny_prob,
        )

    reasons.append(Reason(
        code="ml.specialist_caution", severity="escalate",
        message=f"Specialist {choice} (confidence {conf:.2f})", source="ml",
    ))
    return Aggregate(
        Verdict.ESCALATE, max(conf, 0.5), reasons, "caution",
        f"specialist {choice} → human", allow_prob, deny_prob,
    )
