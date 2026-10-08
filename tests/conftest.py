"""Shared test fixtures for Panoptic tests."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

import pytest
from aiohttp import web
from aiohttp.test_utils import RawTestServer
from multidict import CIMultiDictProxy
from pytest_aiohttp import AiohttpRawServer

PROXY_ENV_VARS = ("http_proxy", "https_proxy", "all_proxy", "ws_proxy", "wss_proxy", "no_proxy")


@pytest.fixture(autouse=True)
def _no_environment_proxies(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep requests to the local test servers off any proxy set in the environment."""
    for name in PROXY_ENV_VARS:
        monkeypatch.delenv(name, raising=False)
        monkeypatch.delenv(name.upper(), raising=False)


@pytest.fixture
def sample_passwd() -> str:
    """Sample /etc/passwd content for parser tests."""
    return (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "user:x:1000:1000:Test User:/home/user:/bin/bash\n"
    )


@dataclass(frozen=True)
class RecordedRequest:
    """A request exactly as the local test server received it."""

    method: str
    raw_path: str
    headers: CIMultiDictProxy[str]
    body: bytes

    @property
    def path(self) -> str:
        return self.raw_path.partition("?")[0]


Responder = Callable[[web.BaseRequest], Awaitable[web.StreamResponse]]


@dataclass
class RecordingServer:
    """Local HTTP server that records every request and replays queued responses.

    Responses are queued per path (without query string) with :meth:`add`; the
    last response queued for a path is reused once the others are consumed.
    Paths without a queued response get ``200 ok``.
    """

    server: RawTestServer | None = None
    requests: list[RecordedRequest] = field(default_factory=list)
    _routes: dict[str, list[Responder]] = field(default_factory=dict)

    @property
    def origin(self) -> str:
        assert self.server is not None
        return f"http://127.0.0.1:{self.server.port}"

    def url(self, path: str = "/") -> str:
        return f"{self.origin}{path}"

    def add(
        self,
        path: str,
        body: bytes | str = b"",
        *,
        status: int = 200,
        headers: dict[str, str] | None = None,
    ) -> None:
        payload = body.encode() if isinstance(body, str) else body

        async def respond(request: web.BaseRequest) -> web.StreamResponse:
            return web.Response(status=status, body=payload, headers=headers)

        self.add_handler(path, respond)

    def add_handler(self, path: str, responder: Responder) -> None:
        self._routes.setdefault(path, []).append(responder)

    async def handle(self, request: web.BaseRequest) -> web.StreamResponse:
        self.requests.append(RecordedRequest(request.method, request.raw_path, request.headers, await request.read()))
        responders = self._routes.get(request.raw_path.partition("?")[0])
        if not responders:
            return web.Response(text="ok")
        responder = responders.pop(0) if len(responders) > 1 else responders[0]
        return await responder(request)

    @property
    def last(self) -> RecordedRequest:
        assert self.requests, "the server received no request"
        return self.requests[-1]


ServerFactory = Callable[[], Awaitable[RecordingServer]]


@pytest.fixture
def make_server(aiohttp_raw_server: AiohttpRawServer) -> ServerFactory:
    """Factory for independent recording servers (each on its own port, i.e. origin)."""

    async def make() -> RecordingServer:
        recorder = RecordingServer()
        recorder.server = await aiohttp_raw_server(recorder.handle)
        return recorder

    return make


@pytest.fixture
async def server(make_server: ServerFactory) -> RecordingServer:
    return await make_server()
