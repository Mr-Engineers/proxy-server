"""TypeSafe Jev specialist scorer (hosted System One) behind MlScorer."""

from __future__ import annotations

import logging
import time
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

from app.config.models import AgentConfig
from app.pipeline.jev_packs import SpecialistPack, describe_all, pack_for, resolve_use_case
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


def choice_question(pack: SpecialistPack) -> Any:
    """Build a TypeSafe Choice question from the specialist pack."""
    from typesafe_sdk import Choice

    return Choice(instructions=pack.instructions, criteria=dict(pack.criteria))


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
    return MlSignals(
        available=True,
        alignment=float(probabilities.get("clear", 0.0)),
        p_malicious=float(probabilities.get("deny", 0.0)),
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
        timeout_seconds: float = 10.0,
        system_one: SystemOneFn | None = None,
    ) -> None:
        self.api_key = (api_key or "").strip() or None
        self.model = model
        self.timeout_seconds = timeout_seconds
        self._system_one = system_one
        self._client: Any = None
        if self._system_one is None and self.api_key:
            # Fail fast on invalid key shape at construction (same checks as the SDK).
            from typesafe_sdk import AsyncTypeSafeClient

            self._client = AsyncTypeSafeClient(api_key=self.api_key, model=self.model, timeout=self.timeout_seconds)

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
        if self._system_one is None and self._client is None:
            return MlSignals(failed=True, specialist=pack.model_id, version=self.model)

        state = build_state(
            action, agent, session_state, enrichment, facts,
            use_case=use_case, policy_reasons=policy_reasons,
        )
        questions = {"verdict": choice_question(pack)}
        started = time.perf_counter()
        try:
            response = await self._call(state, questions)
        except Exception as exc:
            latency_ms = (time.perf_counter() - started) * 1000
            logger.exception(
                "jev_score_failed",
                extra={"fields": {
                    "tool": action.tool, "agent_id": agent.id, "model": self.model,
                    "error": type(exc).__name__, "detail": str(exc)[:500], "latency_ms": round(latency_ms, 1),
                }},
            )
            return MlSignals(failed=True, specialist=pack.model_id, version=self.model, latency_ms=latency_ms)

        latency_ms = (time.perf_counter() - started) * 1000
        answer = _extract_choice(response, "verdict")
        if answer is None:
            logger.error(
                "jev_missing_verdict",
                extra={"fields": {
                    "tool": action.tool,
                    "answer_keys": sorted(getattr(response, "answers", {}) or {}),
                    "choice_keys": sorted(getattr(response, "choices", {}) or {}),
                }},
            )
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
        return await self._client.system_one(
            state=state, questions=questions, model=self.model, timeout=self.timeout_seconds,
        )

    async def scan(self, texts: list[str]) -> dict[str, float]:
        return {}

    def describe(self) -> list[dict[str, Any]]:
        health = "healthy" if (self._client is not None or self._system_one is not None) else "unavailable"
        return describe_all(
            model=self.model,
            latency_budget_ms=int(self.timeout_seconds * 1000),
            health=health,
        )


def _extract_choice(response: Any, key: str) -> tuple[str, dict[str, float], float, str | None] | None:
    """Read Choice answer from SystemOneResponse (.choices / .answers) or plain dicts."""
    for container_name in ("choices", "answers"):
        container = getattr(response, container_name, None)
        if not isinstance(container, Mapping) or key not in container:
            continue
        answer = container[key]
        if isinstance(answer, Mapping):
            choice = answer.get("choice")
            probabilities = dict(answer.get("probabilities") or {})
            confidence = float(answer.get("confidence") or 0.0)
        else:
            choice = getattr(answer, "choice", None)
            probabilities = dict(getattr(answer, "probabilities", {}) or {})
            confidence = float(getattr(answer, "confidence", 0.0) or 0.0)
        if choice is None:
            return None
        model = getattr(response, "model", None)
        return str(choice), {str(k): float(v) for k, v in probabilities.items()}, confidence, str(model) if model else None
    return None
