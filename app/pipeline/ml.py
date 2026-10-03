"""Punkt wpięcia toru M (S18). Tu podłączamy modele ONNX — reszta pipeline'u się nie zmienia.

`score` — sygnały dla akcji w hopie B (injection z historii sesji, fraud, alignment).
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
    ) -> MlSignals: ...

    async def scan(self, texts: list[str]) -> dict[str, float]: ...

    def describe(self) -> list[dict[str, Any]]: ...


class NullScorer:
    """Brak modeli: sygnały niedostępne, agregator v0 decyduje na regułach."""

    name = "none"

    async def score(self, action, agent, session_state, enrichment, facts) -> MlSignals:
        return MlSignals()

    async def scan(self, texts: list[str]) -> dict[str, float]:
        return {}

    def describe(self) -> list[dict[str, Any]]:
        return []
