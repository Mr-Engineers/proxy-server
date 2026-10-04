"""Wspólny kontrakt pipeline'u decyzyjnego (Dzień 0 w STORIES).

Nazewnictwo: proxy `escalate` = UI `caution`; `rate_limited` to osobny werdykt.
`chain[]` od razu w formacie UI: `{stage: rbac|rules|specialist|human, outcome, detail}`.
"""

from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, Field


class Verdict(StrEnum):
    ALLOW = "allow"
    ESCALATE = "escalate"
    DENY = "deny"
    RATE_LIMITED = "rate_limited"

    @property
    def ui(self) -> str:
        return "caution" if self is Verdict.ESCALATE else self.value


UI_TO_VERDICT = {"allow": "allow", "caution": "escalate", "deny": "deny", "rate_limited": "rate_limited"}


class Action(BaseModel):
    app: str
    tool: str  # "{app_id}.{tool_name}", np. "marketplace.place_order"; nieznana trasa: "{app_id}.<unmatched>"
    kind: Literal["read", "write"]
    args: dict[str, Any] = {}
    request: dict[str, Any] = {}  # query + parametry ścieżki + body (do reguł UI i redakcji)
    session_id: str
    agent_id: str

    @property
    def name(self) -> str:
        return self.tool.partition(".")[2]


class ChainStep(BaseModel):
    stage: Literal["rbac", "rules", "specialist", "human"]
    outcome: str
    detail: str = ""


class Reason(BaseModel):
    code: str
    severity: Literal["deny", "escalate"]
    message: str = ""
    source: str = "policy"


class PolicyResult(BaseModel):
    verdict: Literal["allow", "deny", "escalate"]
    reasons: list[Reason] = []
    config_revision: int
    latency_ms: float = 0.0
    errors: list[str] = []
    facts: dict[str, Any] = {}


class MlSignals(BaseModel):
    """Sygnały z modeli (tor M). Bez modeli: `available = False`, wszystkie wyniki `None`."""

    available: bool = False
    injection: float | None = None
    malicious_code: float | None = None
    alignment: float | None = None
    fraud: float | None = None
    p_malicious: float | None = None
    choice: Literal["clear", "caution", "deny"] | None = None
    confidence: float | None = None
    specialist: str = "rules/v0"
    version: str = "v0"
    latency_ms: float = 0.0
    failed: bool = False


class Decision(BaseModel):
    id: str
    verdict: Verdict
    confidence: float
    reasons: list[Reason] = []
    signals: dict[str, Any] = {}
    chain: list[ChainStep] = []
    degraded: bool = False
    latency_ms: float = 0.0
    config_revision: int
    approval_id: str | None = None
    quota_id: str | None = None
    retry_after_seconds: int | None = None
    allow_prob: float | None = None
    deny_prob: float | None = None
    facts: dict[str, Any] = Field(default_factory=dict)
