"""Async HTTP client for Panoptic.

Wraps httpx with retry, timeout, proxy support, and header validation.
"""

from __future__ import annotations

import sys
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

    async def __aenter__(self) -> NetworkClient:
        timeout = httpx.Timeout(self.config.timeout)

        # Build default headers
        headers = self._build_headers()

        # Do not pass an explicit transport here. In HTTPX, doing so makes
        # client-level verify/trust_env settings inapplicable to direct requests
        # and prevents environment proxy mounts from being created. Retries are
        # handled uniformly in fetch() so they also work with proxy transports.
        self._client = httpx.AsyncClient(
            timeout=timeout,
            proxy=self.config.proxy,
            verify=not self.config.invalid_ssl,
            headers=headers,
            follow_redirects=self.config.follow_redirects,
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

        for attempt in range(self.config.retries + 1):
            try:
                if data is not None:
                    # Infer content type from payload: JSON bodies get application/json,
                    # everything else defaults to form-encoded.
                    content_type = "application/x-www-form-urlencoded"
                    stripped = data.lstrip()
                    if stripped.startswith(("{", "[")):
                        content_type = "application/json"
                    post_headers = {"Content-Type": content_type}
                    if headers:
                        post_headers.update(headers)
                    return await self._client.post(
                        url,
                        content=data.encode("utf-8"),
                        headers=post_headers,
                    )
                return await self._client.get(url, headers=headers)
            except (httpx.ConnectError, httpx.ConnectTimeout):
                if attempt >= self.config.retries:
                    return None
            except httpx.HTTPError:
                return None

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

        # Custom headers (Name: Value format, with CRLF validation)
        if self.config.headers:
            for hdr in self.config.headers:
                name, value = validate_header(hdr)
                if name.lower() == "cookie" and "Cookie" in headers:
                    print("[!] Warning: --header 'Cookie: ...' overrides --cookie value", file=sys.stderr)
                headers[name] = value

        return headers
