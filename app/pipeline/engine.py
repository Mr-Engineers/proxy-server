"""Pipeline decyzyjny v0 (S10 / C5) — wspólny dla wszystkich adapterów (D1).

walidacja → kwoty → RBAC → enrichment → polityki (Cedar) + reguły UI → sygnały ML → agregator.
Awaria komponentu: `kind: read` fail-open, `kind: write` fail-closed, zawsze `degraded` (D14).
"""

import logging
import time
from dataclasses import dataclass, field
from typing import Any

import jsonschema

from app.config.models import AgentConfig, AppConfig, ConfigSnapshot, ToolConfig
from app.core.ids import new_id
from app.pipeline.aggregator import aggregate
from app.pipeline.enrichment import Enricher
from app.pipeline.ml import MlScorer
from app.pipeline.models import Action, ChainStep, Decision, MlSignals, PolicyResult, Reason, Verdict
from app.pipeline.rules import evaluate_rules
from app.policy.cedar import CedarPolicyEngine, budget_windows
from app.store.runtime import RuntimeStore

logger = logging.getLogger("proxy.pipeline")


@dataclass
class DecisionContext:
    snapshot: ConfigSnapshot
    agent: AgentConfig
    app: AppConfig
    tool: ToolConfig | None
    action: Action
    session_state: dict[str, Any]
    request_id: str
    enrichment: dict[str, Any] = field(default_factory=dict)


def _ms(started: float) -> float:
    return (time.perf_counter() - started) * 1000


def _hard_deny(ctx: DecisionContext, started: float, chain: list[ChainStep], reason: Reason) -> Decision:
    return Decision(
        id=new_id("dec"),
        verdict=Verdict.DENY,
        confidence=1.0,
        reasons=[reason],
        chain=chain,
        latency_ms=_ms(started),
        config_revision=ctx.snapshot.revision,
        allow_prob=0.0,
        deny_prob=1.0,
    )


class DecisionPipeline:
    def __init__(self, store: RuntimeStore, enricher: Enricher, scorer: MlScorer, policy: CedarPolicyEngine | None = None) -> None:
        self.store = store
        self.enricher = enricher
        self.scorer = scorer
        self.policy = policy or CedarPolicyEngine()

    async def decide(self, ctx: DecisionContext) -> Decision:
        started = time.perf_counter()
        action, agent, snapshot = ctx.action, ctx.agent, ctx.snapshot
        human_skip = ChainStep(stage="human", outcome="skipped", detail="Not required")

        if ctx.tool is None:
            return _hard_deny(
                ctx, started,
                [ChainStep(stage="rbac", outcome="deny", detail="Route is not in the action catalog"),
                 ChainStep(stage="rules", outcome="skipped", detail="RBAC short-circuit"),
                 ChainStep(stage="specialist", outcome="skipped", detail="RBAC short-circuit"), human_skip],
                Reason(code="unknown_route", severity="deny", message="Route is not in the action catalog", source="catalog"),
            )

        if ctx.tool.input_schema:
            try:
                jsonschema.validate(action.request, ctx.tool.input_schema)
            except jsonschema.ValidationError as exc:
                return _hard_deny(
                    ctx, started,
                    [ChainStep(stage="rbac", outcome="pass", detail="Request validation"),
                     ChainStep(stage="rules", outcome="deny", detail=f"Invalid arguments: {exc.message}"),
                     ChainStep(stage="specialist", outcome="skipped", detail="Validation short-circuit"), human_skip],
                    Reason(code="schema_violation", severity="deny", message=exc.message, source="validation"),
                )
            except jsonschema.SchemaError:
                logger.warning("invalid_input_schema", extra={"fields": {"tool": action.tool}})

        limited = await self._check_quotas(ctx, started)
        if limited is not None:
            return limited

        role = f"Role {agent.role_id}" if agent.role_id else "Direct grant"
        if action.tool not in agent.permissions:
            return _hard_deny(
                ctx, started,
                [ChainStep(stage="rbac", outcome="deny", detail=f"{action.tool} not granted to agent"),
                 ChainStep(stage="rules", outcome="skipped", detail="RBAC short-circuit"),
                 ChainStep(stage="specialist", outcome="skipped", detail="RBAC short-circuit"), human_skip],
                Reason(code="permission_denied", severity="deny", message=f"{action.tool} not granted", source="rbac"),
            )
        chain = [ChainStep(stage="rbac", outcome="pass", detail=role)]
        degraded = False
        notes: list[str] = []

        try:
            ctx.enrichment, errors = await self.enricher.enrich(ctx.app, ctx.tool, action.args, ctx.request_id)
            if errors:
                degraded = True
                notes.extend(f"enrichment {error}" for error in errors)
        except Exception:
            logger.exception("enrichment_error", extra={"fields": {"tool": action.tool}})
            ctx.enrichment, degraded = {}, True
            notes.append("enrichment failed")

        policy = await self._evaluate_policy(ctx)
        if policy.errors:
            degraded = True
            notes.extend(policy.errors)

        rule = evaluate_rules(snapshot.rules.get(agent.id, ()), action.tool, action.args, action.request, policy.facts)
        if rule.outcome == "deny":
            policy = policy.model_copy(update={
                "verdict": "deny",
                "reasons": [*policy.reasons, Reason(code=f"rule.{rule.rule_id}", severity="deny", message=rule.detail, source="rules")],
            })
        chain.append(self._rules_step(policy, rule.outcome, rule.detail))

        needs_ai = rule.outcome == "needs_ai"
        signals = await self._score(ctx, policy, needs_ai=needs_ai)
        if signals.failed:
            degraded = True
            notes.append("specialist failed")
            # Fail closed to HITL on escalate/needs_ai; only hard-deny unexpected write failures.
            if action.kind == "write" and policy.verdict == "allow" and not needs_ai:
                policy = policy.model_copy(update={
                    "verdict": "deny",
                    "reasons": [*policy.reasons, Reason(code="pipeline_degraded", severity="deny", message="Specialist unavailable for write action", source="ml")],
                })

        result = aggregate(
            action.kind,
            policy,
            signals,
            needs_ai=needs_ai,
            rule_allowed=rule.outcome == "allow",
            fail_closed=snapshot.settings.specialist_fail_closed,
        )
        chain.append(ChainStep(stage="specialist", outcome=result.specialist_outcome, detail=result.specialist_detail))

        verdict = result.verdict
        if verdict is Verdict.ESCALATE and await self.store.has_temporary_grant(agent.id, action.tool):
            verdict = Verdict.ALLOW
            chain.append(ChainStep(stage="human", outcome="allow", detail="Temporary allow granted by operator"))
        elif verdict is Verdict.ESCALATE:
            chain.append(ChainStep(stage="human", outcome="pending", detail="Waiting for operator"))
        else:
            chain.append(human_skip)

        return Decision(
            id=new_id("dec"),
            verdict=verdict,
            confidence=result.confidence,
            reasons=result.reasons,
            signals={**signals.model_dump(), "notes": notes, "matched_rule": rule.rule_id, "enrichment": ctx.enrichment},
            chain=chain,
            degraded=degraded,
            latency_ms=_ms(started),
            config_revision=snapshot.revision,
            allow_prob=result.allow_prob,
            deny_prob=result.deny_prob,
            facts=policy.facts,
        )

    async def _check_quotas(self, ctx: DecisionContext, started: float) -> Decision | None:
        limits: list[tuple[str, str, int, int]] = [
            (quota.id, quota.name, quota.window_seconds, quota.limit)
            for quota in ctx.snapshot.quotas.get(ctx.agent.id, ())
            if quota.enabled
        ]
        rpm = ctx.agent.limits.get("requests_per_minute")
        if isinstance(rpm, int) and rpm > 0:
            limits.append(("agent_rpm", "requests_per_minute", 60, rpm))
        for quota_id, name, seconds, limit in limits:
            used = await self.store.count_calls(ctx.agent.id, seconds)
            if used < limit:
                continue
            age = await self.store.oldest_call_age(ctx.agent.id, seconds) or 0
            retry_after = max(int(seconds - age) + 1, 1)
            return Decision(
                id=new_id("dec"),
                verdict=Verdict.RATE_LIMITED,
                confidence=1.0,
                reasons=[Reason(code="rate_limited", severity="deny", message=f"{name}: {used}/{limit}", source="quota")],
                chain=[
                    ChainStep(stage="rbac", outcome="pass", detail="Not evaluated"),
                    ChainStep(stage="rules", outcome="rate_limited", detail=f"Quota {name} exceeded ({used}/{limit})"),
                    ChainStep(stage="specialist", outcome="skipped", detail="Rate limit short-circuit"),
                    ChainStep(stage="human", outcome="skipped", detail="Not required"),
                ],
                latency_ms=_ms(started),
                config_revision=ctx.snapshot.revision,
                quota_id=quota_id,
                retry_after_seconds=retry_after,
                allow_prob=0.0,
                deny_prob=1.0,
            )
        return None

    async def _evaluate_policy(self, ctx: DecisionContext) -> PolicyResult:
        action = ctx.action
        pack = ctx.snapshot.policy_packs.get(action.app)
        try:
            spent = await self.store.spent(action.agent_id, action.app, budget_windows(pack, action.agent_id, action.name))
            expects_merchant = any(source.name == "merchant" and (not source.tools or ctx.tool.name in source.tools) for source in ctx.app.enrichment)
            return self.policy.evaluate(ctx.snapshot, action, ctx.session_state, ctx.enrichment, spent, expects_merchant)
        except Exception as exc:
            logger.exception("policy_error", extra={"fields": {"tool": action.tool}})
            if action.kind == "write":
                return PolicyResult(
                    verdict="deny",
                    reasons=[Reason(code="policy_evaluation_error", severity="deny", message=type(exc).__name__)],
                    config_revision=ctx.snapshot.revision,
                    errors=[str(exc)],
                )
            return PolicyResult(verdict="allow", config_revision=ctx.snapshot.revision, errors=[str(exc)])

    async def _score(self, ctx: DecisionContext, policy: PolicyResult, *, needs_ai: bool) -> MlSignals:
        if policy.verdict == "deny":
            return MlSignals()
        # Specialist only when it can change the outcome (cost/latency).
        if policy.verdict != "escalate" and not needs_ai:
            return MlSignals()
        try:
            return await self.scorer.score(
                ctx.action,
                ctx.agent,
                ctx.session_state,
                ctx.enrichment,
                policy.facts,
                policy_reasons=[reason.code for reason in policy.reasons],
            )
        except Exception:
            logger.exception("specialist_error", extra={"fields": {"tool": ctx.action.tool}})
            return MlSignals(failed=True)

    @staticmethod
    def _rules_step(policy: PolicyResult, rule_outcome: str | None, rule_detail: str) -> ChainStep:
        parts = [reason.code for reason in policy.reasons]
        if rule_outcome is not None:
            parts.append(rule_detail)
        if policy.verdict == "deny":
            outcome = "deny"
        elif policy.verdict == "escalate":
            outcome = "caution"
        elif rule_outcome is not None:
            outcome = rule_outcome
        else:
            outcome = "pass"
        return ChainStep(stage="rules", outcome=outcome, detail="; ".join(parts) or "No rule matched")
