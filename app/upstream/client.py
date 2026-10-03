import time
from dataclasses import dataclass

import httpx

from app.config.models import AppConfig
from app.upstream.auth import Authenticator
from app.upstream.headers import filter_request_headers, filter_response_headers


class UpstreamError(Exception):
    def __init__(self, status_code: int, code: str, message: str) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.code = code
        self.message = message


@dataclass(frozen=True)
class UpstreamResponse:
    status_code: int
    headers: list[tuple[str, str]]
    content: bytes
    latency_ms: float


class UpstreamClient:
    def __init__(self, http: httpx.AsyncClient, authenticator: Authenticator, max_response_bytes: int) -> None:
        self._http = http
        self._authenticator = authenticator
        self._max_response_bytes = max_response_bytes

    async def send(
        self,
        app: AppConfig,
        method: str,
        path: str,
        query: str,
        headers: list[tuple[str, str]],
        body: bytes,
        request_id: str,
        extra_headers: dict[str, str] | None = None,
    ) -> UpstreamResponse:
        """`extra_headers` dokłada proxy (np. X-On-Behalf-Of) — po filtrze nagłówków agenta."""
        url = app.upstream_url + path + (f"?{query}" if query else "")
        forwarded = filter_request_headers(headers)
        content_type = next((value for name, value in forwarded if name.lower() == "content-type"), None)
        auth_headers = self._authenticator.headers_for(app, method, url, content_type, body)
        proxy_headers = {**(extra_headers or {}), **auth_headers, "X-Request-Id": request_id}
        overridden = {name.lower() for name in proxy_headers}
        outgoing = [(name, value) for name, value in forwarded if name.lower() not in overridden]
        outgoing += list(proxy_headers.items())

        request = self._http.build_request(
            method,
            url,
            headers=outgoing,
            content=body,
            timeout=app.timeout_seconds,
        )
        started = time.perf_counter()
        try:
            response = await self._http.send(request, stream=True)
        except httpx.TimeoutException as exc:
            raise UpstreamError(504, "upstream_timeout", f"Upstream {app.id} did not respond in time") from exc
        except httpx.TransportError as exc:
            raise UpstreamError(502, "upstream_unavailable", f"Upstream {app.id} is unavailable") from exc

        try:
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                size += len(chunk)
                if size > self._max_response_bytes:
                    raise UpstreamError(502, "upstream_response_too_large", f"Upstream {app.id} response exceeds limit")
                chunks.append(chunk)
        except httpx.TimeoutException as exc:
            raise UpstreamError(504, "upstream_timeout", f"Upstream {app.id} did not respond in time") from exc
        except httpx.TransportError as exc:
            raise UpstreamError(502, "upstream_unavailable", f"Upstream {app.id} connection failed") from exc
        finally:
            await response.aclose()

        return UpstreamResponse(
            status_code=response.status_code,
            headers=filter_response_headers(response.headers.multi_items()),
            content=b"".join(chunks),
            latency_ms=(time.perf_counter() - started) * 1000,
        )
