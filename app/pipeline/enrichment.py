"""Enrichment (S8): endpointy tylko dla proxy z `apps.enrichment`, z cache TTL.

Przykład konfiguracji aplikacji marketplace:

    {"offer":    {"path": "/offers/{offer_id}", "tools": ["place_order"], "cache_ttl_seconds": 60},
     "merchant": {"path": "/merchants/{merchant_id}", "tools": ["place_order"],
                  "params": {"merchant_id": "$.offer.merchant.id"}, "cache_ttl_seconds": 3600}}
"""

import json
import logging
import time
from typing import Any, Protocol
from urllib.parse import quote

from app.config.models import AppConfig, ToolConfig
from app.core.jsonpath import JsonPathError, first
from app.upstream.client import UpstreamClient, UpstreamError

logger = logging.getLogger("proxy.enrichment")


class Enricher(Protocol):
    async def enrich(self, app: AppConfig, tool: ToolConfig, args: dict[str, Any], request_id: str) -> tuple[dict[str, Any], list[str]]: ...


class HttpEnricher:
    def __init__(self, upstream: UpstreamClient, max_entries: int = 4096) -> None:
        self._upstream = upstream
        self._cache: dict[tuple[str, str], tuple[float, Any]] = {}
        self._max_entries = max_entries

    def clear(self) -> None:
        self._cache.clear()

    async def enrich(
        self, app: AppConfig, tool: ToolConfig, args: dict[str, Any], request_id: str
    ) -> tuple[dict[str, Any], list[str]]:
        context: dict[str, Any] = {"args": args}
        result: dict[str, Any] = {}
        errors: list[str] = []
        for source in app.enrichment:
            if source.tools and tool.name not in source.tools:
                continue
            path = self._resolve_path(source.path, source.params, context)
            if path is None:
                errors.append(f"{source.name}: missing path parameter")
                continue
            value = await self._fetch(app, source.method, path, source.cache_ttl_seconds, request_id)
            if value is None:
                errors.append(f"{source.name}: unavailable")
                continue
            result[source.name] = value
            context[source.name] = value
        return result, errors

    @staticmethod
    def _resolve_path(template: str, params: dict[str, str], context: dict[str, Any]) -> str | None:
        path = template
        while "{" in path:
            start = path.index("{")
            end = path.index("}", start)
            name = path[start + 1 : end]
            expression = params.get(name, f"$.args.{name}")
            try:
                value = first(context, expression)
            except JsonPathError:
                value = None
            if value is None or isinstance(value, (dict, list)):
                return None
            path = path[:start] + quote(str(value), safe="") + path[end + 1 :]
        return path

    async def _fetch(self, app: AppConfig, method: str, path: str, ttl: int, request_id: str) -> Any:
        key = (app.id, f"{method} {path}")
        cached = self._cache.get(key)
        now = time.monotonic()
        if cached is not None and cached[0] > now:
            return cached[1]
        try:
            response = await self._upstream.send(app, method, path, "", [("Accept", "application/json")], b"", request_id)
        except UpstreamError as exc:
            logger.warning("enrichment_failed", extra={"fields": {"app": app.id, "path": path, "error": exc.code}})
            return None
        if response.status_code != 200:
            logger.warning(
                "enrichment_failed", extra={"fields": {"app": app.id, "path": path, "status": response.status_code}}
            )
            return None
        try:
            value = json.loads(response.content)
        except ValueError:
            return None
        if len(self._cache) >= self._max_entries:
            self._cache.clear()
        self._cache[key] = (now + ttl, value)
        return value
