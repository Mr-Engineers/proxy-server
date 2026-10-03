"""Redakcja argumentów do audytu (A2): pola z `tools.redact` + heurystyki.

Heurystyki maskują sekrety (nazwy kluczy), e-maile, numery kart / telefonów i długie tokeny.
Kwoty nie są maskowane domyślnie — człowiek przy approvalu musi widzieć ilość i cenę;
żeby je ukryć, wpisz ścieżkę w `tools.redact` (np. `$.total_eur`).
"""

import copy
import re
from collections.abc import Iterable
from typing import Any

from app.core.jsonpath import JsonPathError, set_all

MASK = "***"

SENSITIVE_KEY = re.compile(
    r"(pass(word)?|secret|token|api[_-]?key|authorization|auth|cookie|session|credential|private[_-]?key|"
    r"card|cvv|cvc|iban|account[_-]?number|ssn|pesel|email|e-mail|phone)",
    re.IGNORECASE,
)
EMAIL = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
CARD_OR_PHONE = re.compile(r"^\+?[\d\s-]{9,23}$")
TOKEN_LIKE = re.compile(r"^(ak_|sk-|ghp_|eyJ|AKIA)[A-Za-z0-9._\-]{8,}$|^[A-Za-z0-9+/_\-]{40,}={0,2}$")


def _mask_value(value: str) -> bool:
    return bool(EMAIL.match(value) or TOKEN_LIKE.match(value) or (CARD_OR_PHONE.match(value) and sum(c.isdigit() for c in value) >= 9))


def _walk(node: Any) -> Any:
    if isinstance(node, dict):
        return {
            key: MASK if isinstance(key, str) and SENSITIVE_KEY.search(key) and node[key] not in (None, "") else _walk(node[key])
            for key in node
        }
    if isinstance(node, list):
        return [_walk(item) for item in node]
    if isinstance(node, str) and _mask_value(node):
        return MASK
    return node


def redact(payload: Any, paths: Iterable[str] = ()) -> Any:
    result = copy.deepcopy(payload)
    for path in paths:
        try:
            set_all(result, path, MASK)
        except JsonPathError:
            continue
    return _walk(result)
