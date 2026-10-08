"""Async HTTP client for Panoptic.

Wraps aiohttp with retry/backoff, an overall per-request deadline, a response
size cap, origin-aware redirect handling, proxy support, and header validation.
Callers only see the library-independent :class:`Response` type.
"""

from __future__ import annotations

import asyncio
import codecs
import random
import sys
import zlib
from collections import Counter
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from functools import cached_property
from types import TracebackType
from urllib.parse import unquote, urljoin, urlsplit
from urllib.request import getproxies, proxy_bypass

import aiohttp
import aiohttp_socks
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

from panoptic.models import ScanConfig
from panoptic.utils import validate_header

# Maximum number of response body bytes kept per request. Larger bodies are
# truncated: the first MAX_RESPONSE_BYTES (after content decoding) are kept and
# the rest of the stream is discarded. Detection only needs a prefix of a file,
# and the cap protects the scanner from huge or decompression-bomb responses.
MAX_RESPONSE_BYTES = 10 * 1024 * 1024

# Size of the raw (still encoded) body chunks read from the connection.
READ_CHUNK_SIZE = 64 * 1024

# Only encodings that can be decompressed with an output bound are requested;
# a body in any other encoding is kept as raw (undecoded) bytes.
ACCEPT_ENCODING = "gzip, deflate"

# Maximum number of redirects followed when --follow-redirects is enabled.
MAX_REDIRECTS = 10
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})

# Longest accepted response status/header line. aiohttp defaults to 8190 bytes;
# real servers send larger Set-Cookie and Content-Security-Policy headers.
MAX_HEADER_LINE = 64 * 1024

# Each attempt (including its redirect chain and body download) must finish
# within ``timeout * REQUEST_DEADLINE_FACTOR`` seconds. aiohttp's socket
# timeouts apply per network operation, so without this a slow-drip server
# could stall a worker.
REQUEST_DEADLINE_FACTOR = 3.0

# Exponential backoff between retries: base * 2**attempt, capped, with jitter.
RETRY_BACKOFF_BASE = 0.5
RETRY_BACKOFF_MAX = 8.0
# Upper bound for honouring a server-provided Retry-After header.
RETRY_AFTER_MAX = 30.0

SOCKS_PROXY_TYPES = {
    "socks4": aiohttp_socks.ProxyType.SOCKS4,
    "socks5": aiohttp_socks.ProxyType.SOCKS5,
    "socks5h": aiohttp_socks.ProxyType.SOCKS5,
}

# Indirection so tests can replace the backoff sleep without patching asyncio.
_sleep = asyncio.sleep

RETRYABLE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    # Connect failures (DNS, refused, TLS handshake, HTTP proxy unreachable)
    # and OS-level errors such as connection resets while sending or reading.
    aiohttp.ClientOSError,
    aiohttp.ClientConnectionResetError,
    ConnectionResetError,
    aiohttp.ServerDisconnectedError,
    aiohttp.ClientPayloadError,
    # aiohttp.ServerTimeoutError (connect and socket read timeouts) is a TimeoutError.
    TimeoutError,
    aiohttp_socks.ProxyConnectionError,
    aiohttp_socks.ProxyTimeoutError,
)

# Failures that are recorded and end the request without a retry.
NON_RETRYABLE_EXCEPTIONS: tuple[type[BaseException], ...] = (
    aiohttp.ClientError,
    aiohttp_socks.ProxyError,
)


class DecodingError(Exception):
    """Raised when a compressed response body cannot be decoded."""


class _RequestDeadlineExceeded(Exception):
    """Raised when a single attempt exceeds the overall request deadline."""


_RETRYABLE: tuple[type[BaseException], ...] = (*RETRYABLE_EXCEPTIONS, _RequestDeadlineExceeded)
_NON_RETRYABLE: tuple[type[BaseException], ...] = (*NON_RETRYABLE_EXCEPTIONS, DecodingError)


@dataclass(frozen=True)
class Response:
    """An HTTP response with its (decoded, possibly truncated) body.

    ``content`` holds at most MAX_RESPONSE_BYTES after Content-Encoding
    decoding. ``history`` lists the redirect responses that led here.
    """

    status_code: int
    headers: CIMultiDictProxy[str]
    content: bytes
    url: str
    history: tuple[Response, ...] = ()
    encoding: str = "utf-8"

    @cached_property
    def text(self) -> str:
        return self.content.decode(self.encoding, errors="replace")


def _text_encoding(charset: str | None) -> str:
    """Return the response charset when Python knows it, otherwise utf-8."""
    if charset:
        try:
            return codecs.lookup(charset).name
        except LookupError:
            pass
    return "utf-8"


# Characters sent as-is in a URL; every other character is percent-encoded as
# UTF-8. "%" is kept, so existing escapes (and stray percent signs) are sent
# exactly as given. Query and path follow the WHATWG percent-encode sets.
_QUERY_SAFE = frozenset(chr(i) for i in range(0x21, 0x7F)) - set('"#<>')
_PATH_SAFE = _QUERY_SAFE - set("?`{}")
# Traversal (raw) paths are restricted to RFC 3986 pchar plus "/", "%" and a
# backslash, sent literally so Windows-style ..\ traversal is not turned into %5C.
_RAW_PATH_SAFE = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!$&'()*+,;=:@/%-._~\\")


def _percent_encode(value: str, safe: frozenset[str]) -> str:
    if all(char in safe for char in value):
        return value
    return "".join(char if char in safe else "".join(f"%{byte:02X}" for byte in char.encode()) for char in value)


def _remove_dot_segments(path: str) -> str:
    """Drop ``.`` and ``..`` segments (RFC 3986, section 5.2.4)."""
    segments = path.split("/")
    if "." not in segments and ".." not in segments:
        return path
    output: list[str] = []
    for segment in segments:
        if segment == ".":
            continue
        if segment == "..":
            if output and output != [""]:
                output.pop()
        else:
            output.append(segment)
    return "/".join(output)


def _request_url(url: str, raw_path: bool = False) -> URL:
    """Build the URL that is sent verbatim on the wire.

    Characters that are invalid in a URL are percent-encoded, while existing
    escapes are kept, so encoded payloads (``%2F``) are never decoded or
    double-encoded. With ``raw_path`` the ``.``/``..`` segments are kept;
    otherwise they are resolved, as for any normal URL.
    """
    parts = urlsplit(url)
    try:
        authority = URL(f"{parts.scheme}://{parts.netloc}").raw_authority
    except ValueError as exc:
        raise aiohttp.InvalidURL(url) from exc
    if raw_path:
        path = _percent_encode(parts.path, _RAW_PATH_SAFE)
    else:
        path = _remove_dot_segments(_percent_encode(parts.path, _PATH_SAFE))
    query = _percent_encode(parts.query, _QUERY_SAFE)
    target = f"{parts.scheme}://{authority}{path or '/'}"
    if query:
        target += f"?{query}"
    return URL(target, encoded=True)


def _origin(url: URL) -> tuple[str, str | None, int | None]:
    """Return the (scheme, host, port) origin of a URL, with default ports filled."""
    return (url.scheme, url.host, url.port)


def _backoff_delay(attempt: int) -> float:
    """Exponential backoff with jitter for the given zero-based attempt."""
    delay: float = min(RETRY_BACKOFF_MAX, RETRY_BACKOFF_BASE * (2**attempt))
    return delay * random.uniform(0.5, 1.0)


def _retry_after_delay(response: Response) -> float | None:
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
                raise DecodingError("invalid compressed response body") from None
            # Some servers send raw deflate without the zlib wrapper.
            self._decompressor = zlib.decompressobj(-zlib.MAX_WBITS)
            output = self._decompressor.decompress(data, limit)
        self._started = True
        return output


@dataclass
class _Request:
    method: str
    url: URL
    headers: CIMultiDict[str]
    body: bytes | None = None
    # Lower-cased names of the per-request headers passed to fetch().
    header_names: frozenset[str] = field(default_factory=frozenset)


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
        self._session: aiohttp.ClientSession | None = None
        self._proxy: str | None = None
        self._headers: CIMultiDict[str] = CIMultiDict()
        self._user_header_names: frozenset[str] = frozenset()
        self.error_counts: Counter[str] = Counter()
        self.last_error: str | None = None

    async def __aenter__(self) -> NetworkClient:
        self._headers = self._build_headers()
        timeout = aiohttp.ClientTimeout(
            connect=self.config.timeout,
            sock_connect=self.config.timeout,
            sock_read=self.config.timeout,
        )
        connector, self._proxy = self._build_connector()
        # Redirects are followed manually in _send() so user-supplied headers
        # can be stripped when the redirect leaves the original origin. Bodies
        # are decoded in _send_once() with an output bound.
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            cookie_jar=aiohttp.DummyCookieJar(),
            auto_decompress=False,
            # trust_env would also send ~/.netrc credentials to scanned hosts;
            # environment proxies are resolved per request in _proxy_for().
            trust_env=False,
            max_line_size=MAX_HEADER_LINE,
            max_field_size=MAX_HEADER_LINE,
        )
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._session:
            await self._session.close()

    def _build_connector(self) -> tuple[aiohttp.TCPConnector, str | None]:
        """Return the connection pool and the per-request (HTTP) proxy URL.

        The pool is sized to the worker count. SOCKS proxies are implemented
        by the connector; HTTP(S) proxies are passed with every request.
        """
        ssl = not self.config.invalid_ssl
        proxy = self.config.proxy
        scheme = urlsplit(proxy).scheme.lower() if proxy else ""
        if proxy and scheme in SOCKS_PROXY_TYPES:
            parsed = urlsplit(proxy)
            connector = aiohttp_socks.ProxyConnector(
                proxy_type=SOCKS_PROXY_TYPES[scheme],
                host=parsed.hostname or "",
                port=parsed.port or 1080,
                username=unquote(parsed.username) if parsed.username else None,
                password=unquote(parsed.password) if parsed.password else None,
                rdns=True if scheme == "socks5h" else None,
                limit=self.config.concurrency,
                ssl=ssl,
            )
            return connector, None
        return aiohttp.TCPConnector(limit=self.config.concurrency, ssl=ssl), proxy

    async def fetch(
        self,
        url: str,
        data: str | None = None,
        headers: dict[str, str] | None = None,
        raw_path: bool = False,
    ) -> Response | None:
        """Fetch a URL with retries, backoff, a deadline, and a body size cap.

        Returns the response on success, None on any error.
        Per-request headers override client defaults. With ``raw_path`` the
        URL path is sent as given, keeping ``.``/``..`` segments.
        """
        if self._session is None:
            raise RuntimeError("NetworkClient must be used as async context manager")

        request_headers: CIMultiDict[str] = CIMultiDict(headers or {})
        if data is not None and "content-type" not in request_headers and "content-type" not in self._headers:
            # Infer content type from payload: JSON bodies get application/json,
            # everything else defaults to form-encoded. An explicit Content-Type
            # (client default via --header, or per request) always wins.
            stripped = data.lstrip()
            if stripped.startswith(("{", "[")):
                request_headers["Content-Type"] = "application/json"
            else:
                request_headers["Content-Type"] = "application/x-www-form-urlencoded"
        merged = self._headers.copy()
        merged.update(request_headers)

        deadline = self.config.timeout * REQUEST_DEADLINE_FACTOR

        for attempt in range(self.config.retries + 1):
            last_attempt = attempt >= self.config.retries
            try:
                request = _Request(
                    method="POST" if data is not None else "GET",
                    url=_request_url(url, raw_path),
                    headers=merged.copy(),
                    body=data.encode("utf-8") if data is not None else None,
                    header_names=frozenset(name.lower() for name in request_headers),
                )
                attempt_deadline = asyncio.timeout(deadline)
                try:
                    async with attempt_deadline:
                        response = await self._send(request)
                except TimeoutError as exc:
                    if not attempt_deadline.expired():
                        raise
                    raise _RequestDeadlineExceeded(f"request exceeded {deadline:.1f}s deadline") from exc
            except _RETRYABLE as exc:
                self._record_error(exc)
                if last_attempt:
                    return None
                await _sleep(_backoff_delay(attempt))
                continue
            except _NON_RETRYABLE as exc:
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

    async def _send(self, request: _Request) -> Response:
        """Send a request, following redirects manually when enabled.

        User headers (from config and the per-request headers) are stripped on
        cross-origin hops and restored on return. Redirect targets are normal
        URLs: their dot segments are resolved.
        """
        original_origin = _origin(request.url)
        names = set(self._user_header_names) | request.header_names
        # The inferred body Content-Type is not a secret and must follow a 307/308.
        names.discard("content-type")
        user_headers = {name: request.headers.getall(name) for name in names if name in request.headers}
        history: list[Response] = []

        while True:
            response = await self._send_once(request)
            location = response.headers.get("location")
            if (
                not self.config.follow_redirects
                or response.status_code not in REDIRECT_STATUSES
                or location is None
                or len(history) >= MAX_REDIRECTS
            ):
                return replace(response, history=tuple(history))
            history.append(response)

            method, body, headers = request.method, request.body, request.headers.copy()
            if (response.status_code == 303 and method != "HEAD") or (
                response.status_code in (301, 302) and method == "POST"
            ):
                method, body = "GET", None
                headers.popall("content-type", None)
            next_url = _request_url(urljoin(str(request.url), location.strip()))
            for name, values in user_headers.items():
                headers.popall(name, None)
                if _origin(next_url) == original_origin:
                    for value in values:
                        headers.add(name, value)
            request = _Request(method, next_url, headers, body, request.header_names)

    def _proxy_for(self, url: URL) -> str | None:
        """Return the HTTP proxy for ``url``: --proxy, else HTTP(S)_PROXY unless NO_PROXY matches.

        An explicit proxy (HTTP or SOCKS) replaces environment proxies, and
        --ignore-proxy disables them.
        """
        if self.config.proxy or self.config.ignore_proxy:
            return self._proxy
        proxy = getproxies().get(url.scheme)
        if proxy is None or proxy_bypass(url.host_port_subcomponent or ""):
            return None
        return proxy

    async def _send_once(self, request: _Request) -> Response:
        """Send one request and read at most MAX_RESPONSE_BYTES of its decoded body."""
        assert self._session is not None
        async with self._session.request(
            request.method,
            request.url,
            headers=request.headers,
            data=request.body,
            proxy=self._proxy_for(request.url),
            allow_redirects=False,
        ) as resp:
            # Decode from the raw stream with an output bound, so a small
            # compressed body cannot inflate into an unbounded buffer.
            decoder = _BoundedDecoder(resp.headers.get("content-encoding", ""))
            chunks: list[bytes] = []
            size = 0
            async for raw in resp.content.iter_chunked(READ_CHUNK_SIZE):
                chunk = decoder.decode(raw, MAX_RESPONSE_BYTES - size)
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_RESPONSE_BYTES:
                    # Drop the connection rather than reading the rest of the body.
                    resp.close()
                    break
            return Response(
                status_code=resp.status,
                headers=resp.headers,
                content=b"".join(chunks),
                url=str(resp.url),
                encoding=_text_encoding(resp.charset),
            )

    def _record_error(self, error: BaseException | str) -> None:
        name = error if isinstance(error, str) else type(error).__name__
        self.error_counts[name] += 1
        self.last_error = name

    def _build_headers(self) -> CIMultiDict[str]:
        """Build default headers from config, with validation."""
        headers: CIMultiDict[str] = CIMultiDict()
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

        # Custom headers (Name: Value format, with CRLF validation). A custom
        # header replaces a default of the same name, whatever its case.
        if self.config.headers:
            for hdr in self.config.headers:
                name, value = validate_header(hdr)
                if name.lower() == "cookie" and self.config.cookie:
                    print("[!] Warning: --header 'Cookie: ...' overrides --cookie value", file=sys.stderr)
                headers[name] = value
                user_header_names.add(name.lower())

        # Credentials are never forwarded to a different origin.
        user_header_names.add("authorization")
        self._user_header_names = frozenset(user_header_names)
        return headers
