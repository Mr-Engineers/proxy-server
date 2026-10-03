import json
import time
from typing import Any

import cedarpy

from app.config.models import ConfigSnapshot, PolicyAnnotation, PolicyPack
from app.pipeline.models import Action, PolicyResult, Reason
from app.policy.facts import compute_facts, merchant_attrs
from app.policy.params import BUDGET_WINDOWS, ParamsError, merge_override, to_cedar, validate_params

BASE_POLICY_ID = "__base_permit__"
BASE_POLICY = f'\n@id("{BASE_POLICY_ID}")\npermit(principal, action, resource);\n'


class PolicyCompileError(ValueError):
    pass


def _annotations(policies: str) -> dict[str, PolicyAnnotation]:
    try:
        parsed = json.loads(cedarpy.policies_to_json_str(policies))
    except ValueError as exc:
        raise PolicyCompileError(f"cedar parse error: {exc}") from exc
    result = {}
    for policy_id, policy in parsed.get("staticPolicies", {}).items():
        notes = policy.get("annotations", {})
        if notes.get("id") == BASE_POLICY_ID:
            continue
        if policy.get("effect") != "forbid":
            raise PolicyCompileError(f"{notes.get('id', policy_id)}: packs may only contain forbid policies")
        if "id" not in notes:
            raise PolicyCompileError(f"{policy_id}: missing @id annotation")
        severity = notes.get("severity", "deny")
        if severity not in ("deny", "escalate"):
            raise PolicyCompileError(f"{notes['id']}: @severity must be deny or escalate")
        result[policy_id] = PolicyAnnotation(id=notes["id"], severity=severity, message=notes.get("message", ""))
    return result


def compile_pack(
    app_id: str,
    policies: str,
    schema_text: str,
    params: dict[str, Any],
    params_schema: dict[str, Any],
    overrides: dict[str, dict[str, Any]],
) -> PolicyPack:
    full = policies + BASE_POLICY
    annotations = _annotations(full)
    if schema_text.strip():
        result = cedarpy.validate_policies(policies, schema_text)
        if not result.validation_passed:
            raise PolicyCompileError("; ".join(error.error for error in result.errors))
    try:
        validate_params(params_schema, params, "params")
        cedar_params = {action: to_cedar(params_schema, values, action) for action, values in params.items()}
        agent_params = {}
        for agent_id, override in overrides.items():
            validate_params(params_schema, override, f"overrides.{agent_id}")
            merged = merge_override(params_schema, params, override, f"overrides.{agent_id}")
            agent_params[agent_id] = {action: to_cedar(params_schema, values, action) for action, values in merged.items()}
    except ParamsError as exc:
        raise PolicyCompileError(str(exc)) from exc
    return PolicyPack(
        app_id=app_id,
        policies=full,
        schema_text=schema_text,
        annotations=annotations,
        params_schema=params_schema,
        params=cedar_params,
        agent_params=agent_params,
    )


def budget_windows(pack: PolicyPack | None, agent_id: str, action: str) -> dict[str, int]:
    """Okna budżetu, dla których pipeline musi policzyć wydatki z ledgera (sekundy)."""
    if pack is None:
        return {}
    params = pack.params_for(agent_id, action)
    return {window: seconds for window, seconds in BUDGET_WINDOWS.items() if f"budget_{window}_minor" in params}


def build_request(
    pack: PolicyPack,
    action: Action,
    session_state: dict[str, Any],
    enrichment: dict[str, Any],
    spent: dict[str, int],
    expects_merchant: bool,
) -> tuple[dict, list[dict], dict[str, Any]]:
    params = pack.params_for(action.agent_id, action.name)
    facts = compute_facts(action.args, session_state, enrichment, spent)
    for window in BUDGET_WINDOWS:
        if f"budget_{window}_minor" in params:
            facts.setdefault(f"spent_{window}_minor", 0)
    param_currency = params.get("budget_currency") or next(
        (value for key, value in params.items() if key.endswith("_currency")), None
    )
    facts["currency_matches"] = param_currency is None or facts["currency"] in ("", param_currency)

    principal = {"uid": {"type": "Agent", "id": action.agent_id}, "attrs": {}, "parents": []}
    if expects_merchant:
        merchant = enrichment.get("merchant") if isinstance(enrichment.get("merchant"), dict) else None
        attrs = merchant_attrs(merchant)
        resource_uid = {"type": "Merchant", "id": str((merchant or {}).get("id") or "unknown")}
        resource = {"uid": resource_uid, "attrs": attrs, "parents": []}
    else:
        resource_uid = {"type": "Tool", "id": action.tool}
        resource = {"uid": resource_uid, "attrs": {"kind": action.kind}, "parents": []}

    request = {
        "principal": f'Agent::"{action.agent_id}"',
        "action": f'Action::"{action.tool}"',
        "resource": f'{resource_uid["type"]}::"{resource_uid["id"]}"',
        "context": {"params": params, **facts},
    }
    return request, [principal, resource], facts


class CedarPolicyEngine:
    def evaluate(
        self,
        snapshot: ConfigSnapshot,
        action: Action,
        session_state: dict[str, Any],
        enrichment: dict[str, Any],
        spent: dict[str, int],
        expects_merchant: bool = False,
    ) -> PolicyResult:
        started = time.perf_counter()
        agent = snapshot.agents.get(action.agent_id)
        if agent is None or action.tool not in agent.permissions:
            return PolicyResult(
                verdict="deny",
                reasons=[Reason(code="permission_denied", severity="deny", message=f"{action.tool} not granted")],
                config_revision=snapshot.revision,
                latency_ms=(time.perf_counter() - started) * 1000,
            )

        pack = snapshot.policy_packs.get(action.app)
        if pack is None:
            return PolicyResult(verdict="allow", config_revision=snapshot.revision)

        request, entities, facts = build_request(pack, action, session_state, enrichment, spent, expects_merchant)
        result = cedarpy.is_authorized(request, pack.policies, entities)

        reasons = []
        for policy_id in result.diagnostics.reasons:
            note = pack.annotations.get(policy_id)
            if note is not None:
                reasons.append(Reason(code=note.id, severity=note.severity, message=note.message or note.id))
        errors = list(result.diagnostics.errors)
        if errors and action.kind == "write":
            reasons.append(Reason(code="policy_evaluation_error", severity="deny", message="; ".join(errors)))

        if any(reason.severity == "deny" for reason in reasons):
            verdict = "deny"
        elif reasons:
            verdict = "escalate"
        else:
            verdict = "allow"
        return PolicyResult(
            verdict=verdict,
            reasons=reasons,
            config_revision=snapshot.revision,
            latency_ms=(time.perf_counter() - started) * 1000,
            errors=errors,
            facts=facts,
        )
