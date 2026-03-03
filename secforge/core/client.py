"""
Async HTTP client for SecForge.

Wraps httpx with:
- Auth injection (Bearer, API key, Basic)
- Rate limiting
- Consistent headers
- SSL verification control
- Request/response logging for evidence capture
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional, Any

import httpx

from secforge.models.target import TargetConfig


class RateLimiter:
    """Simple token-bucket rate limiter."""

    def __init__(self, rate: int):
        self.rate = rate          # requests per second
        self.tokens = rate
        self.last_refill = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_refill
            refill = elapsed * self.rate
            self.tokens = min(self.rate, self.tokens + refill)
            self.last_refill = now

            if self.tokens < 1:
                wait = (1 - self.tokens) / self.rate
                await asyncio.sleep(wait)
                self.tokens = 0
            else:
                self.tokens -= 1


class SecForgeClient:
    """
    The SecForge HTTP client. Use as an async context manager.

    Usage:
        async with SecForgeClient(target) as client:
            response = await client.get("/api/v1/users")
    """

    def __init__(self, target: TargetConfig):
        self.target = target
        self._rate_limiter = RateLimiter(target.options.rate_limit)
        self._client: Optional[httpx.AsyncClient] = None

    async def __aenter__(self) -> "SecForgeClient":
        opts = self.target.options

        # Build headers: base → target custom → auth
        headers = {
            "User-Agent": opts.user_agent,
            "Accept": "application/json, text/html, */*",
            **self.target.headers,
            **self.target.auth.build_headers(),
        }

        auth_tuple = self.target.auth.build_auth_tuple()

        self._base_headers = headers  # Exposed for plugins that need to override auth

        self._client = httpx.AsyncClient(
            base_url=self.target.url,
            headers=headers,
            auth=auth_tuple,
            timeout=httpx.Timeout(opts.timeout),
            follow_redirects=opts.follow_redirects,
            max_redirects=opts.max_redirects,
            verify=opts.verify_ssl,
            http2=True,
        )
        return self

    async def __aexit__(self, *args) -> None:
        if self._client:
            await self._client.aclose()

    async def get(self, path: str, **kwargs) -> httpx.Response:
        await self._rate_limiter.acquire()
        return await self._client.get(path, **kwargs)

    async def post(self, path: str, **kwargs) -> httpx.Response:
        await self._rate_limiter.acquire()
        return await self._client.post(path, **kwargs)

    async def put(self, path: str, **kwargs) -> httpx.Response:
        await self._rate_limiter.acquire()
        return await self._client.put(path, **kwargs)

    async def patch(self, path: str, **kwargs) -> httpx.Response:
        await self._rate_limiter.acquire()
        return await self._client.patch(path, **kwargs)

    async def delete(self, path: str, **kwargs) -> httpx.Response:
        await self._rate_limiter.acquire()
        return await self._client.delete(path, **kwargs)

    async def request(self, method: str, path: str, **kwargs) -> httpx.Response:
        await self._rate_limiter.acquire()
        return await self._client.request(method, path, **kwargs)

    @property
    def base_url(self) -> str:
        return self.target.url
