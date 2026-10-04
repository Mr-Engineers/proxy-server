"""Punkt wpięcia toru M (S18). Jev (TypeSafe) lub inny specjalista — reszta pipeline'u się nie zmienia.

`score` — sygnały dla akcji w hopie B (Choice clear/caution/deny, alignment, fraud).
`scan` — skan tekstów z odpowiedzi aplikacji i wejścia do LLM; wynik trafia do `sessions.state.signals`.
"""

from typing import Any, Protocol

from app.config.models import AgentConfig
from app.pipeline.models import Action, MlSignals


class MlScorer(Protocol):
    name: str

    async def score(
        self,
        action: Action,
        agent: AgentConfig,
        session_state: dict[str, Any],
        enrichment: dict[str, Any],
        facts: dict[str, Any],
        *,
        policy_reasons: list[str] | None = None,
    ) -> MlSignals: ...

    async def scan(self, texts: list[str]) -> dict[str, float]: ...

    def describe(self) -> list[dict[str, Any]]: ...


class NullScorer:
    """Brak modeli: sygnały niedostępne, agregator decyduje na regułach.

    `describe` nadal zwraca specjalistów z `specialists.json` (health=unavailable).
    """

    name = "none"

    async def score(
        self, action, agent, session_state, enrichment, facts, *, policy_reasons: list[str] | None = None,
    ) -> MlSignals:
        return MlSignals()

    async def scan(self, texts: list[str]) -> dict[str, float]:
        return {}

    def describe(self) -> list[dict[str, Any]]:
        from app.pipeline.jev_packs import describe_all

        return describe_all(model="unloaded", latency_budget_ms=0, health="unavailable")
