from collections.abc import Iterable

HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    }
)

STRIPPED_REQUEST = HOP_BY_HOP | {
    "host",
    "content-length",
    "authorization",
    "cookie",
    "x-session-id",
    "x-request-id",
    "x-on-behalf-of",
}

STRIPPED_RESPONSE = HOP_BY_HOP | {
    "content-length",
    "content-encoding",
    "set-cookie",
}


def _connection_tokens(headers: Iterable[tuple[str, str]]) -> set[str]:
    return {
        token.strip().lower()
        for name, value in headers
        if name.lower() == "connection"
        for token in value.split(",")
        if token.strip()
    }


def _filter(headers: Iterable[tuple[str, str]], stripped: frozenset[str] | set[str]) -> list[tuple[str, str]]:
    items = list(headers)
    blocked = stripped | _connection_tokens(items)
    return [(name, value) for name, value in items if name.lower() not in blocked]


def filter_request_headers(headers: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    return _filter(headers, STRIPPED_REQUEST)


def filter_response_headers(headers: Iterable[tuple[str, str]]) -> list[tuple[str, str]]:
    return _filter(headers, STRIPPED_RESPONSE)
