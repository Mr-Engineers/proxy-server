"""Specialist packs loaded from `specialists.json` (code-side config)."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

CONFIG_PATH = Path(__file__).with_name("specialists.json")


@dataclass(frozen=True)
class SpecialistPack:
    id: str
    name: str
    provider: str
    use_case: str
    model_id: str
    criteria_summary: str
    agent_id: str | None
    agent_match: tuple[str, ...]
    instructions: str
    criteria: dict[str, str]
    clear_threshold: float = 0.82
    on_failure: str = "escalate_human"


def _pack_from_dict(raw: dict[str, Any]) -> SpecialistPack:
    criteria = raw.get("criteria") or {}
    if not isinstance(criteria, dict) or set(criteria) != {"clear", "caution", "deny"}:
        raise ValueError(f"specialist {raw.get('id')!r}: criteria must be clear/caution/deny")
    match = raw.get("agent_match") or []
    if not isinstance(match, list) or not all(isinstance(item, str) for item in match):
        raise ValueError(f"specialist {raw.get('id')!r}: agent_match must be a list of strings")
    return SpecialistPack(
        id=str(raw["id"]),
        name=str(raw["name"]),
        provider=str(raw.get("provider") or "typesafe"),
        use_case=str(raw["use_case"]),
        model_id=str(raw["model_id"]),
        criteria_summary=str(raw.get("criteria_summary") or ""),
        agent_id=str(raw["agent_id"]) if raw.get("agent_id") else None,
        agent_match=tuple(str(item).lower() for item in match),
        instructions=str(raw["instructions"]),
        criteria={key: str(criteria[key]) for key in ("clear", "caution", "deny")},
        clear_threshold=float(raw.get("clear_threshold") or 0.82),
        on_failure=str(raw.get("on_failure") or "escalate_human"),
    )


@lru_cache(maxsize=1)
def load_packs() -> tuple[SpecialistPack, ...]:
    data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    items = data.get("specialists") if isinstance(data, dict) else None
    if not isinstance(items, list) or not items:
        raise ValueError(f"{CONFIG_PATH.name}: expected nonempty specialists list")
    packs = tuple(_pack_from_dict(item) for item in items)
    ids = [pack.id for pack in packs]
    if len(ids) != len(set(ids)):
        raise ValueError(f"{CONFIG_PATH.name}: duplicate specialist id")
    return packs


def all_packs() -> tuple[SpecialistPack, ...]:
    return load_packs()


def default_pack() -> SpecialistPack:
    return load_packs()[0]


def resolve_use_case(agent_id: str) -> str:
    needle = agent_id.lower()
    for pack in load_packs():
        if any(token in needle for token in pack.agent_match):
            return pack.use_case
    return default_pack().use_case


def pack_for(use_case: str) -> SpecialistPack:
    for pack in load_packs():
        if pack.use_case == use_case:
            return pack
    return default_pack()


def pack_by_id(specialist_id: str) -> SpecialistPack | None:
    return next((pack for pack in load_packs() if pack.id == specialist_id), None)


def choice_question(pack: SpecialistPack) -> dict[str, Any]:
    """Raw question dict (works with SDK objects or plain system_one dicts)."""
    return {
        "type": "choice",
        "instructions": pack.instructions,
        "criteria": dict(pack.criteria),
    }


def describe_pack(
    pack: SpecialistPack,
    *,
    model: str,
    latency_budget_ms: int,
    health: str = "healthy",
) -> dict[str, Any]:
    return {
        "id": pack.id,
        "name": pack.name,
        "agentId": pack.agent_id,
        "modelId": pack.model_id,
        "version": model,
        "health": health,
        "latencyP95Ms": 0,
        "latencyBudgetMs": latency_budget_ms,
        "errorRatePct": 0,
        "falseClearRatePct": 0,
        "evaluatesToday": 0,
        "clearToday": 0,
        "cautionToday": 0,
        "clearThreshold": pack.clear_threshold,
        "onFailure": pack.on_failure,
        "circuitBreaker": {"open": False, "failures": 0, "threshold": 5, "cooldownSeconds": 60},
        "criteriaSummary": pack.criteria_summary,
        "useCase": pack.use_case,
        "provider": pack.provider,
        "loadedAt": None,
        "lastEvaluateAt": None,
    }


def describe_all(*, model: str, latency_budget_ms: int, health: str = "healthy") -> list[dict[str, Any]]:
    return [
        describe_pack(pack, model=model, latency_budget_ms=latency_budget_ms, health=health)
        for pack in load_packs()
    ]
