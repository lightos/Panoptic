"""Async HTTP client for Panoptic.

Wraps httpx with retry/backoff, an overall per-request deadline, a response
size cap, origin-aware redirect handling, proxy support, and header validation.
"""

from __future__ import annotations

import asyncio
import random
import sys
import zlib
from collections import Counter
from collections.abc import Iterable
from datetime import UTC
from email.utils import parsedate_to_datetime
from http.cookiejar import CookieJar, DefaultCookiePolicy
from types import TracebackType
from typing import Any
from urllib.parse import quote, urlsplit

import httpx

from panoptic.models import ScanConfig
from panoptic.utils import validate_header

# Maximum number of response body bytes kept per request. Larger bodies are
# truncated: the first MAX_RESPONSE_BYTES (after content decoding) are kept and
# the rest of the stream is discarded. Detection only needs a prefix of a file,
# and the cap protects the scanner from huge or decompression-bomb responses.
MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# Only encodings that can be decompressed with an output bound are requested;
# a body in any other encoding is kept as raw (undecoded) bytes.
ACCEPT_ENCODING = "gzip, deflate"

# Maximum number of redirects followed when --follow-redirects is enabled.
MAX_REDIRECTS = 10

# Each attempt (including its redirect chain and body download) must finish
# within ``timeout * REQUEST_DEADLINE_FACTOR`` seconds. httpx timeouts apply per
# network operation, so without this a slow-drip server could stall a worker.
REQUEST_DEADLINE_FACTOR = 3.0

# Exponential backoff between retries: base * 2**attempt, capped, with jitter.
RETRY_BACKOFF_BASE = 0.5
RETRY_BACKOFF_MAX = 8.0
# Upper bound for honouring a server-provided Retry-After header.
RETRY_AFTER_MAX = 30.0

# Indirection so tests can replace the backoff sleep without patching asyncio.
_sleep = asyncio.sleep

RETRYABLE_EXCEPTIONS: tuple[type[Exception], ...] = (
    httpx.ConnectError,
    httpx.ConnectTimeout,
    httpx.ReadTimeout,
    httpx.PoolTimeout,
    httpx.RemoteProtocolError,
)


class _RequestDeadlineExceeded(Exception):
    """Raised when a single attempt exceeds the overall request deadline."""


_RETRYABLE: tuple[type[Exception], ...] = (*RETRYABLE_EXCEPTIONS, _RequestDeadlineExceeded)


class _NoStoreCookiePolicy(DefaultCookiePolicy):
    """Cookie policy that never stores server-set cookies.

    Panoptic compares every response with a baseline, so cookies set by the
    target must not leak into later requests. User-provided cookies are sent
    as an explicit Cookie header instead.
    """

    def set_ok(self, cookie: Any, request: Any) -> bool:
        return False


def _origin(url: httpx.URL) -> tuple[str, str, int | None]:
    """Return the (scheme, host, port) origin of a URL, with default ports filled."""
    default_ports = {"http": 80, "https": 443}
    return (url.scheme, url.host, url.port or default_ports.get(url.scheme))


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with jitter for the given zero-based attempt."""
    delay: float = min(RETRY_BACKOFF_MAX, RETRY_BACKOFF_BASE * (2**attempt))
    return delay * random.uniform(0.5, 1.0)


def _retry_after_delay(response: httpx.Response) -> float | None:
    """Parse a Retry-After header (seconds or HTTP date), capped at RETRY_AFTER_MAX."""
    value = response.headers.get("retry-after")
    if value is None:
        return None
    value = value.strip()
    try:
        seconds = float(value)
    except ValueError:
        try:
            parsed = parsedate_to_datetime(value)
        except (TypeError, ValueError):
            return None
        from datetime import datetime

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=UTC)
        seconds = (parsed - datetime.now(UTC)).total_seconds()
    return max(0.0, min(seconds, RETRY_AFTER_MAX))


class _BoundedDecoder:
    """Content-Encoding decoder that never produces more than a given number of bytes.

    Supports gzip and deflate (zlib-wrapped or raw); identity and any other
    encoding are passed through undecoded.
    """

    def __init__(self, content_encoding: str) -> None:
        encoding = content_encoding.strip().lower()
        self._deflate = encoding == "deflate"
        self._decompressor: zlib._Decompress | None = None
        if encoding in ("gzip", "x-gzip"):
            self._decompressor = zlib.decompressobj(zlib.MAX_WBITS | 16)
        elif self._deflate:
            self._decompressor = zlib.decompressobj()
        self._started = False

    def decode(self, data: bytes, limit: int) -> bytes:
        if limit <= 0:
            return b""
        if self._decompressor is None:
            return data[:limit]
        try:
            output = self._decompressor.decompress(data, limit)
        except zlib.error:
            if not (self._deflate and not self._started):
                raise httpx.DecodingError("invalid compressed response body") from None
            # Some servers send raw deflate without the zlib wrapper.
            self._decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            output = self._decompressor.decompress(data, limit)
        self._started = True
        return output


# RFC 3986 pchar plus "/" and "%" so existing percent-escapes are sent as given.
_RAW_PATH_SAFE = "!$&'()*+,;=:@/%-._~"


def _set_raw_path(request: httpx.Request, path: str) -> None:
    """Send ``path`` verbatim, bypassing httpx's dot-segment removal.

    httpx drops ``.``/``..`` segments whenever it parses a URL and has no
    public way to send a path unmodified, so the parsed path is replaced
    directly. tests/test_core_review_fixes.py asserts the bytes on the wire.
    """
    request.url._uri_reference = request.url._uri_reference._replace(path=quote(path, safe=_RAW_PATH_SAFE))


class NetworkClient:
    """Async HTTP client with concurrency control and error handling.

    Usage:
        async with NetworkClient(config) as client:
            response = await client.fetch(url)

    ``error_counts`` tracks the exception type names of failed attempts and
    ``last_error`` holds the most recent one, for operational error reporting.
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._client: httpx.AsyncClient | None = None
        self._user_header_names: frozenset[str] = frozenset()
        self.error_counts: Counter[str] = Counter()
        self.last_error: str | None = None

    async def __aenter__(self) -> NetworkClient:
        timeout = httpx.Timeout(self.config.timeout)

        # Build default headers
        headers = self._build_headers()

        # Size the connection pool to the worker count.
        limits = httpx.Limits(
            max_connections=self.config.concurrency,
            max_keepalive_connections=self.config.concurrency,
        )

        # Do not pass an explicit transport here. In HTTPX, doing so makes
        # client-level verify/trust_env settings inapplicable to direct requests
        # and prevents environment proxy mounts from being created. Retries are
        # handled uniformly in fetch() so they also work with proxy transports.
        # Redirects are followed manually in fetch() so user-supplied headers
        # can be stripped when the redirect leaves the original origin.
        self._client = httpx.AsyncClient(
            timeout=timeout,
            proxy=self.config.proxy,
            verify=not self.config.invalid_ssl,
            headers=headers,
            cookies=CookieJar(policy=_NoStoreCookiePolicy()),
            follow_redirects=False,
            limits=limits,
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
        raw_path: bool = False,
    ) -> httpx.Response | None:
        """Fetch a URL with retries, backoff, a deadline, and a body size cap.

        Returns the response on success, None on any error.
        Per-request headers override client defaults. With ``raw_path`` the
        URL path is sent as given, keeping ``.``/``..`` segments.
        """
        if self._client is None:
            raise RuntimeError("NetworkClient must be used as async context manager")

        request_headers = httpx.Headers(headers or {})
        if data is not None and "content-type" not in request_headers and "content-type" not in self._client.headers:
            # Infer content type from payload: JSON bodies get application/json,
            # everything else defaults to form-encoded. An explicit Content-Type
            # (client default via --header, or per request) always wins.
            stripped = data.lstrip()
            if stripped.startswith(("{", "[")):
                request_headers["Content-Type"] = "application/json"
            else:
                request_headers["Content-Type"] = "application/x-www-form-urlencoded"

        deadline = self.config.timeout * REQUEST_DEADLINE_FACTOR

        for attempt in range(self.config.retries + 1):
            last_attempt = attempt >= self.config.retries
            try:
                request = self._client.build_request(
                    "POST" if data is not None else "GET",
                    url,
                    content=data.encode("utf-8") if data is not None else None,
                    headers=request_headers,
                )
                if raw_path:
                    _set_raw_path(request, urlsplit(url).path)
                try:
                    async with asyncio.timeout(deadline):
                        response = await self._send(request, request_headers.keys())
                except TimeoutError as exc:
                    raise _RequestDeadlineExceeded(f"request exceeded {deadline:.1f}s deadline") from exc
            except _RETRYABLE as exc:
                self._record_error(exc)
                if last_attempt:
                    return None
                await _sleep(_backoff_delay(attempt))
                continue
            except httpx.HTTPError as exc:
                self._record_error(exc)
                return None

            retry_after = _retry_after_delay(response)
            throttled = response.status_code == 429 or (response.status_code == 503 and retry_after is not None)
            if throttled and not last_attempt:
                self._record_error(f"HTTP {response.status_code}")
                await _sleep(retry_after if retry_after is not None else _backoff_delay(attempt))
                continue
            return response

        return None

    async def _send(self, request: httpx.Request, request_header_names: Iterable[str] = ()) -> httpx.Response:
        """Send a request, following redirects manually when enabled.

        User headers (from config and ``request_header_names``, the per-request
        headers) are stripped on cross-origin hops and restored on return.
        """
        assert self._client is not None
        original_origin = _origin(request.url)
        names = set(self._user_header_names) | {name.lower() for name in request_header_names}
        # The inferred body Content-Type is not a secret and must follow a 307/308.
        names.discard("content-type")
        user_headers = {name: request.headers[name] for name in names if name in request.headers}
        history: list[httpx.Response] = []

        while True:
            response = await self._send_capped(request)
            next_request = response.next_request
            if not self.config.follow_redirects or next_request is None or len(history) >= MAX_REDIRECTS:
                response.history = list(history)
                return response
            history.append(response)

            if next_request.method != request.method and next_request.method == "GET":
                next_request.headers.pop("Content-Type", None)
            if _origin(next_request.url) == original_origin:
                # httpx drops the Cookie header on redirects; restore user values.
                for name, value in user_headers.items():
                    next_request.headers[name] = value
            else:
                for name in user_headers:
                    next_request.headers.pop(name, None)
            request = next_request

    async def _send_capped(self, request: httpx.Request) -> httpx.Response:
        """Send one request and read at most MAX_RESPONSE_BYTES of its body."""
        assert self._client is not None
        response = await self._client.send(request, stream=True)
        try:
            # Decode from the raw stream with an output bound: httpx's own
            # decoders inflate each chunk without a limit before yielding it.
            decoder = _BoundedDecoder(response.headers.get("content-encoding", ""))
            chunks: list[bytes] = []
            size = 0
            async for raw in response.aiter_raw():
                chunk = decoder.decode(raw, MAX_RESPONSE_BYTES - size)
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_RESPONSE_BYTES:
                    break
        finally:
            await response.aclose()
        # Expose the (possibly truncated) body as the response content.
        response._content = b"".join(chunks)
        return response

    def _record_error(self, error: BaseException | str) -> None:
        name = error if isinstance(error, str) else type(error).__name__
        self.error_counts[name] += 1
        self.last_error = name

    def _build_headers(self) -> dict[str, str]:
        """Build default headers from config, with validation."""
        headers: dict[str, str] = {}
        user_header_names: set[str] = set()

        # User-Agent
        if self.config.user_agent:
            headers["User-Agent"] = self.config.user_agent
        else:
            from panoptic import __version__

            headers["User-Agent"] = f"Panoptic {__version__}"

        headers["Accept-Encoding"] = ACCEPT_ENCODING

        # Cookie
        if self.config.cookie:
            headers["Cookie"] = self.config.cookie
            user_header_names.add("cookie")

        # Custom headers (Name: Value format, with CRLF validation)
        if self.config.headers:
            for hdr in self.config.headers:
                name, value = validate_header(hdr)
                if name.lower() == "cookie" and "Cookie" in headers:
                    print("[!] Warning: --header 'Cookie: ...' overrides --cookie value", file=sys.stderr)
                headers[name] = value
                user_header_names.add(name.lower())

        # Credentials are never forwarded to a different origin.
        user_header_names.add("authorization")
        self._user_header_names = frozenset(user_header_names)
        return headers
