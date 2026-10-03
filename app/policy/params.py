"""Parametry pakietów polityk: łączenie z overrides (tylko zaostrzanie) i konwersja do Cedar.

Typy parametrów (deklarowane w `params_schema` pakietu, per akcja):

| typ          | wartość                                   | łączenie z override  | w Cedar                                  |
|--------------|-------------------------------------------|----------------------|------------------------------------------|
| `allowlist`  | lista stringów                            | część wspólna        | `<name>`: Set<String>                    |
| `max_money`  | `{"amount": "5000.00", "currency": "PLN"}`| mniejsza wartość     | `<name>_minor`: Long, `<name>_currency`  |
| `max_number` | liczba całkowita                          | mniejsza wartość     | `<name>`: Long                           |
| `min_number` | liczba całkowita                          | większa wartość      | `<name>`: Long                           |
| `flag`       | bool                                      | `true` wygrywa       | `<name>`: Bool                           |
| `budget`     | `[{"window": "24h", "amount", "currency"}]`| mniejsza per okno   | `budget_<window>_minor`, `budget_currency`|
"""

from decimal import Decimal, InvalidOperation
from typing import Any

BUDGET_WINDOWS = {"1h": 3600, "24h": 86400, "7d": 604800, "30d": 2592000}


class ParamsError(ValueError):
    pass


def money_minor(value: Any, where: str) -> tuple[int, str]:
    if not isinstance(value, dict) or "amount" not in value or "currency" not in value:
        raise ParamsError(f"{where}: expected {{amount, currency}}")
    try:
        amount = Decimal(str(value["amount"]))
    except InvalidOperation as exc:
        raise ParamsError(f"{where}: invalid amount {value['amount']!r}") from exc
    minor = amount * 100
    if minor != minor.to_integral_value():
        raise ParamsError(f"{where}: amount has more than 2 decimal places")
    return int(minor), str(value["currency"])


def _check_value(kind: str, value: Any, where: str) -> None:
    match kind:
        case "allowlist":
            if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
                raise ParamsError(f"{where}: expected a list of strings")
        case "max_money":
            money_minor(value, where)
        case "max_number" | "min_number":
            if isinstance(value, bool) or not isinstance(value, int):
                raise ParamsError(f"{where}: expected an integer")
        case "flag":
            if not isinstance(value, bool):
                raise ParamsError(f"{where}: expected a boolean")
        case "budget":
            if not isinstance(value, list):
                raise ParamsError(f"{where}: expected a list of budget windows")
            for entry in value:
                if not isinstance(entry, dict) or entry.get("window") not in BUDGET_WINDOWS:
                    raise ParamsError(f"{where}: budget window must be one of {sorted(BUDGET_WINDOWS)}")
                money_minor(entry, where)
        case _:
            raise ParamsError(f"{where}: unknown parameter type {kind!r}")


def validate_params(schema: dict[str, dict[str, Any]], params: dict[str, dict[str, Any]], where: str) -> None:
    for action, values in params.items():
        action_schema = schema.get(action)
        if action_schema is None:
            raise ParamsError(f"{where}: action {action!r} is not declared in params_schema")
        if not isinstance(values, dict):
            raise ParamsError(f"{where}.{action}: expected an object")
        for name, value in values.items():
            spec = action_schema.get(name)
            if spec is None:
                raise ParamsError(f"{where}.{action}.{name}: not declared in params_schema")
            _check_value(spec.get("type"), value, f"{where}.{action}.{name}")


def _tighten(kind: str, base: Any, override: Any, where: str) -> Any:
    if base is None:
        return override
    match kind:
        case "allowlist":
            if not set(override) <= set(base):
                raise ParamsError(f"{where}: override adds values not allowed by default: {sorted(set(override) - set(base))}")
            return [item for item in base if item in set(override)]
        case "max_money":
            base_minor, base_currency = money_minor(base, where)
            override_minor, override_currency = money_minor(override, where)
            if base_currency != override_currency:
                raise ParamsError(f"{where}: override currency differs from default")
            if override_minor > base_minor:
                raise ParamsError(f"{where}: override raises the maximum")
            return override
        case "max_number":
            if override > base:
                raise ParamsError(f"{where}: override raises the maximum")
            return override
        case "min_number":
            if override < base:
                raise ParamsError(f"{where}: override lowers the minimum")
            return override
        case "flag":
            if base and not override:
                raise ParamsError(f"{where}: override disables a required flag")
            return override
        case "budget":
            merged = {entry["window"]: entry for entry in base}
            for entry in override:
                current = merged.get(entry["window"])
                if current is not None:
                    current_minor, current_currency = money_minor(current, where)
                    override_minor, override_currency = money_minor(entry, where)
                    if current_currency != override_currency:
                        raise ParamsError(f"{where}: override budget currency differs from default")
                    if override_minor > current_minor:
                        raise ParamsError(f"{where}: override raises budget {entry['window']}")
                merged[entry["window"]] = entry
            return list(merged.values())
    raise ParamsError(f"{where}: unknown parameter type {kind!r}")


def merge_override(
    schema: dict[str, dict[str, Any]],
    base: dict[str, dict[str, Any]],
    override: dict[str, dict[str, Any]],
    where: str,
) -> dict[str, dict[str, Any]]:
    merged = {action: dict(values) for action, values in base.items()}
    for action, values in override.items():
        target = merged.setdefault(action, {})
        for name, value in values.items():
            target[name] = _tighten(schema[action][name]["type"], target.get(name), value, f"{where}.{action}.{name}")
    return merged


def to_cedar(schema: dict[str, dict[str, Any]], params: dict[str, Any], action: str) -> dict[str, Any]:
    action_schema = schema.get(action, {})
    result: dict[str, Any] = {}
    for name, value in params.items():
        kind = action_schema.get(name, {}).get("type")
        match kind:
            case "max_money":
                minor, currency = money_minor(value, name)
                result[f"{name}_minor"] = minor
                result[f"{name}_currency"] = currency
            case "budget":
                for entry in value:
                    minor, currency = money_minor(entry, name)
                    result[f"budget_{entry['window']}_minor"] = minor
                    result["budget_currency"] = currency
            case _:
                result[name] = value
    return result
