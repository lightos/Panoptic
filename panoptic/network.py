"""Async HTTP client for Panoptic.

Wraps httpx with retry, timeout, proxy support, and header validation.
"""

from __future__ import annotations

import asyncio
import ssl
from types import TracebackType

import httpx

from panoptic.models import ScanConfig
from panoptic.utils import validate_header


class NetworkClient:
    """Async HTTP client with concurrency control and error handling.

    Usage:
        async with NetworkClient(config) as client:
            response = await client.fetch(url)
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._client: httpx.AsyncClient | None = None
        self._semaphore = asyncio.Semaphore(config.concurrency)

    async def __aenter__(self) -> NetworkClient:
        timeout = httpx.Timeout(self.config.timeout, connect=5.0)

        proxy = self.config.proxy

        # SSL verification
        ssl_verify: bool | ssl.SSLContext = True
        if self.config.invalid_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssl_verify = ctx

        # Transport with retry
        transport = httpx.AsyncHTTPTransport(retries=self.config.retries)

        # Build default headers
        headers = self._build_headers()

        self._client = httpx.AsyncClient(
            timeout=timeout,
            proxy=proxy,
            verify=ssl_verify,
            transport=transport,
            headers=headers,
            follow_redirects=False,
            trust_env=not self.config.ignore_proxy,
        )

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._client:
            await self._client.aclose()

    async def fetch(
        self,
        url: str,
        data: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response | None:
        """Fetch a URL with concurrency limiting and error handling.

        Returns the response on success, None on any error.
        Per-request headers override client defaults.
        """
        if self._client is None:
            raise RuntimeError("NetworkClient must be used as async context manager")

        async with self._semaphore:
            try:
                if data is not None:
                    post_headers = {"Content-Type": "application/x-www-form-urlencoded"}
                    if headers:
                        post_headers.update(headers)
                    response = await self._client.post(
                        url,
                        content=data.encode("utf-8"),
                        headers=post_headers,
                    )
                else:
                    response = await self._client.get(url, headers=headers)
                return response
            except httpx.HTTPStatusError as e:
                # Return the response even on HTTP errors (404/500) —
                # the body is needed for heuristic comparison
                return e.response
            except httpx.HTTPError:
                # Connection/timeout errors have no response body
                return None

    def _build_headers(self) -> dict[str, str]:
        """Build default headers from config, with validation."""
        headers: dict[str, str] = {}

        # User-Agent
        if self.config.user_agent:
            headers["User-Agent"] = self.config.user_agent
        else:
            from panoptic import __version__

            headers["User-Agent"] = f"Panoptic {__version__}"

        # Cookie
        if self.config.cookie:
            headers["Cookie"] = self.config.cookie

        # Custom header (Name: Value format, with CRLF validation)
        if self.config.header:
            name, value = validate_header(self.config.header)
            headers[name] = value

        return headers
