"""TypeSafe Jev specialist scorer (hosted System One) behind MlScorer."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from app.config.models import AgentConfig
from app.pipeline.jev_packs import PACKS, SpecialistPack, choice_question, pack_for, resolve_use_case
from app.pipeline.models import Action, MlSignals

logger = logging.getLogger("proxy.jev")

SESSION_KEYS = ("stock_needs", "offers_seen", "orders_placed", "llm_tool_calls")
MAX_LIST_ITEMS = 8

SystemOneFn = Callable[..., Awaitable[Any]]


def _truncate(value: Any, depth: int = 0) -> Any:
    if depth > 4:
        return "…"
    if isinstance(value, Mapping):
        return {str(k): _truncate(v, depth + 1) for k, v in list(value.items())[:40]}
    if isinstance(value, list):
        return [_truncate(item, depth + 1) for item in value[:MAX_LIST_ITEMS]]
    if isinstance(value, str) and len(value) > 500:
        return value[:500] + "…"
    return value


def build_state(
    action: Action,
    agent: AgentConfig,
    session_state: dict[str, Any],
    enrichment: dict[str, Any],
    facts: dict[str, Any],
    *,
    use_case: str,
    policy_reasons: list[str] | None = None,
) -> dict[str, Any]:
    session = {key: _truncate(session_state.get(key, [])) for key in SESSION_KEYS if key in session_state}
    if "llm_tool_calls" in session and isinstance(session["llm_tool_calls"], list):
        session["recent_llm_tool_calls"] = session.pop("llm_tool_calls")
    return {
        "mandate": agent.mandate,
        "agent_id": agent.id,
        "use_case": use_case,
        "tool": action.tool,
        "args": _truncate(action.args),
        "policy_reasons": list(policy_reasons or []),
        "facts": _truncate(facts),
        "enrichment": _truncate(enrichment),
        "session": session,
    }


def _signals_from_choice(
    *,
    choice: str,
    probabilities: Mapping[str, float],
    confidence: float,
    specialist: str,
    version: str,
    latency_ms: float,
) -> MlSignals:
    normalized = choice if choice in {"clear", "caution", "deny"} else "caution"
    alignment = float(probabilities.get("clear", 0.0))
    p_malicious = float(probabilities.get("deny", 0.0))
    return MlSignals(
        available=True,
        alignment=alignment,
        p_malicious=p_malicious,
        choice=normalized,  # type: ignore[arg-type]
        confidence=float(confidence),
        specialist=specialist,
        version=version,
        latency_ms=latency_ms,
    )


class JevScorer:
    """Hosted Jev evaluate worker: Choice clear/caution/deny + confidence."""

    name = "jev"

    def __init__(
        self,
        *,
        api_key: str | None = None,
        model: str = "jev-latest",
        timeout_seconds: float = 0.8,
        system_one: SystemOneFn | None = None,
    ) -> None:
        self.api_key = api_key
        self.model = model
        self.timeout_seconds = timeout_seconds
        self._system_one = system_one
        self._client: Any = None

    async def _ensure_client(self) -> Any:
        if self._system_one is not None:
            return None
        if self._client is not None:
            return self._client
        from typesafe_sdk import AsyncTypeSafeClient

        self._client = AsyncTypeSafeClient(api_key=self.api_key, model=self.model, timeout=self.timeout_seconds)
        return self._client

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def score(
        self,
        action: Action,
        agent: AgentConfig,
        session_state: dict[str, Any],
        enrichment: dict[str, Any],
        facts: dict[str, Any],
        *,
        policy_reasons: list[str] | None = None,
    ) -> MlSignals:
        use_case = resolve_use_case(agent.id)
        pack = pack_for(use_case)
        state = build_state(
            action, agent, session_state, enrichment, facts,
            use_case=use_case, policy_reasons=policy_reasons,
        )
        questions = {"verdict": choice_question(pack)}
        started = time.perf_counter()
        try:
            response = await self._call(state, questions)
        except Exception:
            logger.exception("jev_score_failed", extra={"fields": {"tool": action.tool, "agent_id": agent.id}})
            return MlSignals(failed=True, specialist=pack.model_id, version=self.model)

        latency_ms = (time.perf_counter() - started) * 1000
        answer = _extract_choice(response, "verdict")
        if answer is None:
            logger.error("jev_missing_verdict", extra={"fields": {"tool": action.tool}})
            return MlSignals(failed=True, specialist=pack.model_id, version=self.model, latency_ms=latency_ms)

        choice, probabilities, confidence, model_version = answer
        return _signals_from_choice(
            choice=choice,
            probabilities=probabilities,
            confidence=confidence,
            specialist=pack.model_id,
            version=model_version or self.model,
            latency_ms=latency_ms,
        )

    async def _call(self, state: dict[str, Any], questions: dict[str, Any]) -> Any:
        if self._system_one is not None:
            return await self._system_one(state=state, questions=questions, model=self.model)

        client = await self._ensure_client()
        return await client.system_one(state=state, questions=questions, model=self.model, timeout=self.timeout_seconds)

    async def scan(self, texts: list[str]) -> dict[str, float]:
        return {}

    def describe(self) -> list[dict[str, Any]]:
        return [_describe_pack(pack, self.model, int(self.timeout_seconds * 1000)) for pack in PACKS.values()]


def _describe_pack(pack: SpecialistPack, model: str, latency_budget_ms: int) -> dict[str, Any]:
    return {
        "id": pack.id,
        "name": pack.name,
        "agentId": None,
        "modelId": pack.model_id,
        "version": model,
        "health": "healthy",
        "latencyP95Ms": None,
        "latencyBudgetMs": latency_budget_ms,
        "errorRatePct": None,
        "falseClearRatePct": None,
        "evaluatesToday": 0,
        "clearToday": 0,
        "cautionToday": 0,
        "clearThreshold": 0.82,
        "onFailure": "escalate_human",
        "circuitBreaker": {"open": False, "failures": 0, "threshold": 5, "cooldownSeconds": 60},
        "criteriaSummary": pack.criteria_summary,
        "useCase": pack.use_case,
        "loadedAt": None,
        "lastEvaluateAt": None,
    }


def _extract_choice(response: Any, key: str) -> tuple[str, dict[str, float], float, str | None] | None:
    choices = getattr(response, "choices", None)
    if isinstance(choices, Mapping) and key in choices:
        answer = choices[key]
        choice = getattr(answer, "choice", None)
        probabilities = dict(getattr(answer, "probabilities", {}) or {})
        confidence = float(getattr(answer, "confidence", 0.0) or 0.0)
        model = getattr(response, "model", None)
        if choice is None:
            return None
        return str(choice), {str(k): float(v) for k, v in probabilities.items()}, confidence, str(model) if model else None

    answers = getattr(response, "answers", None)
    if isinstance(answers, Mapping) and key in answers:
        answer = answers[key]
        if isinstance(answer, Mapping):
            choice = answer.get("choice")
            probabilities = dict(answer.get("probabilities") or {})
            confidence = float(answer.get("confidence") or 0.0)
        else:
            choice = getattr(answer, "choice", None)
            probabilities = dict(getattr(answer, "probabilities", {}) or {})
            confidence = float(getattr(answer, "confidence", 0.0) or 0.0)
        model = getattr(response, "model", None)
        if choice is None:
            return None
        return str(choice), {str(k): float(v) for k, v in probabilities.items()}, confidence, str(model) if model else None

    return None
