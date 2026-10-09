"""Tests for panoptic.network — async HTTP client.

Requests go to real local aiohttp servers that record what arrives on the wire.
"""

import asyncio
import gzip
import socket
import zlib
from collections.abc import AsyncIterator, Callable
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import aiohttp
import aiohttp_socks
import pytest
from aiohttp import web
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

from panoptic import network
from panoptic.models import ScanConfig
from panoptic.network import NetworkClient, Response
from tests.conftest import RecordingServer, ServerFactory


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep retry tests fast: no backoff sleeps."""
    monkeypatch.setattr(network, "RETRY_BACKOFF_BASE", 0.0)


def _free_port() -> int:
    """Return a local port with nothing listening on it."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port: int = sock.getsockname()[1]
    return port


def _fail_first_send(monkeypatch: pytest.MonkeyPatch, *errors: BaseException) -> list[int]:
    """Make the first sends raise ``errors`` in turn, then send for real."""
    real_send_once = NetworkClient._send_once
    remaining = list(errors)
    calls: list[int] = []

    async def send_once(self: NetworkClient, request: Any) -> Response:
        calls.append(1)
        if remaining:
            raise remaining.pop(0)
        return await real_send_once(self, request)

    monkeypatch.setattr(NetworkClient, "_send_once", send_once)
    return calls


def _make_response(status: int = 200, headers: dict[str, str] | None = None) -> Response:
    return Response(status, CIMultiDictProxy(CIMultiDict(headers or {})), b"", "http://example.com/")


class TestNetworkClient:
    @pytest.fixture
    def config(self) -> ScanConfig:
        return ScanConfig(url="http://example.com", timeout=5.0, retries=1, concurrency=2)

    async def test_context_manager(self, config: ScanConfig) -> None:
        client = NetworkClient(config)
        async with client:
            assert client._session is not None
            assert not client._session.closed
        assert client._session.closed

    async def test_fetch_outside_context_raises(self, config: ScanConfig) -> None:
        with pytest.raises(RuntimeError):
            await NetworkClient(config).fetch("http://example.com/")

    async def test_fetch_get(self, config: ScanConfig, server: RecordingServer) -> None:
        server.add("/test", "hello")
        async with NetworkClient(config) as client:
            response = await client.fetch(server.url("/test"))
        assert response is not None
        assert response.text == "hello"
        assert response.status_code == 200
        assert response.url == server.url("/test")
        assert response.history == ()
        assert server.last.method == "GET"
        assert server.last.body == b""

    async def test_fetch_post(self, config: ScanConfig, server: RecordingServer) -> None:
        server.add("/test", "posted")
        async with NetworkClient(config) as client:
            response = await client.fetch(server.url("/test"), data="file=test")
        assert response is not None
        assert response.text == "posted"
        assert server.last.method == "POST"
        assert server.last.body == b"file=test"
        assert server.last.headers["content-type"] == "application/x-www-form-urlencoded"

    async def test_response_headers_are_case_insensitive(self, config: ScanConfig, server: RecordingServer) -> None:
        server.add("/h", "x", headers={"X-Thing": "1"})
        async with NetworkClient(config) as client:
            response = await client.fetch(server.url("/h"))
        assert response is not None
        assert response.headers["x-thing"] == response.headers["X-THING"] == "1"

    async def test_text_uses_response_charset(self, config: ScanConfig, server: RecordingServer) -> None:
        server.add("/l1", "café".encode("latin-1"), headers={"Content-Type": "text/plain; charset=iso-8859-1"})
        server.add("/bad", b"caf\xe9", headers={"Content-Type": "text/plain; charset=no-such-codec"})
        server.add("/none", "café".encode(), headers={"Content-Type": "text/plain"})
        server.add("/b64", "café".encode(), headers={"Content-Type": "text/plain; charset=base64"})
        async with NetworkClient(config) as client:
            latin = await client.fetch(server.url("/l1"))
            unknown = await client.fetch(server.url("/bad"))
            default = await client.fetch(server.url("/none"))
            binary_codec = await client.fetch(server.url("/b64"))
        assert latin is not None and latin.text == "café"
        assert unknown is not None and unknown.text == "caf\ufffd"
        assert default is not None and default.text == "café"
        assert binary_codec is not None and binary_codec.text == "café"

    async def test_connection_refused_is_retried_then_none(self, config: ScanConfig) -> None:
        async with NetworkClient(config) as client:
            assert await client.fetch(f"http://127.0.0.1:{_free_port()}/down") is None
            assert client.error_counts == {"ClientConnectorError": 2}
            assert client.last_error == "ClientConnectorError"

    async def test_connect_error_is_retried(
        self, config: ScanConfig, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server.add("/retry", "recovered")
        calls = _fail_first_send(monkeypatch, aiohttp.ClientOSError(111, "refused"))
        async with NetworkClient(config) as client:
            response = await client.fetch(server.url("/retry"))
        assert response is not None
        assert response.text == "recovered"
        assert len(calls) == 2

    async def test_custom_user_agent(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", user_agent="CustomBot/1.0")
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/test"))
        assert server.last.headers.getall("user-agent") == ["CustomBot/1.0"]

    async def test_default_user_agent(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/test"))
        assert server.last.headers["user-agent"].startswith("Panoptic ")

    async def test_custom_cookie(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", cookie="sid=abc123")
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/test"))
        assert server.last.headers["cookie"] == "sid=abc123"

    async def test_custom_header(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", headers=["X-Custom: value123"])
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/test"))
        assert server.last.headers["x-custom"] == "value123"

    async def test_multiple_custom_headers(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", headers=["X-Custom: val1", "X-Other: val2"])
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/test"))
        assert server.last.headers["x-custom"] == "val1"
        assert server.last.headers["x-other"] == "val2"

    async def test_custom_header_replaces_default_of_any_case(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", headers=["user-agent: lower/1.0"])
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/test"))
        assert server.last.headers.getall("user-agent") == ["lower/1.0"]

    async def test_per_request_header_overrides_default(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", headers=["X-Fuzz: base"])
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/test"), headers={"x-fuzz": "FUZZED"})
        assert server.last.headers.getall("x-fuzz") == ["FUZZED"]

    async def test_no_follow_redirects(self, config: ScanConfig, server: RecordingServer) -> None:
        server.add("/redir", status=302, headers={"Location": "/other"})
        async with NetworkClient(config) as client:
            response = await client.fetch(server.url("/redir"))
        assert response is not None
        assert response.status_code == 302  # Should NOT follow
        assert len(server.requests) == 1

    async def test_follow_redirects_when_enabled(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        server.add("/start", status=302, headers={"Location": server.url("/final")})
        server.add("/final", "followed")
        async with NetworkClient(config) as client:
            resp = await client.fetch(server.url("/start"))
        assert resp is not None
        assert resp.text == "followed"
        assert resp.status_code == 200
        assert resp.url == server.url("/final")
        assert [hop.status_code for hop in resp.history] == [302]


class TestWirePaths:
    async def test_raw_path_keeps_dot_segments(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/a/b/../../../etc/./passwd"), raw_path=True)
        assert server.last.raw_path == "/a/b/../../../etc/./passwd"

    async def test_normal_path_resolves_dot_segments(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/app/../x/./inc.php?file=../../etc/passwd"))
        assert server.last.raw_path == "/x/inc.php?file=../../etc/passwd"

    async def test_raw_path_encodes_only_invalid_characters(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/a/../my file/é/..%2f..\\win.ini?q=a b"), raw_path=True)
        # Backslashes stay literal so Windows-style ..\ traversal is sent as written.
        assert server.last.raw_path == "/a/../my%20file/%C3%A9/..%2f..\\win.ini?q=a%20b"

    @pytest.mark.parametrize(
        ("query", "expected"),
        [
            ("file=%2Fetc%2Fpasswd", "file=%2Fetc%2Fpasswd"),
            ("file=..%2F..%2Fetc%2Fpasswd%00", "file=..%2F..%2Fetc%2Fpasswd%00"),
            ("file=/etc/passwd&x=a+b", "file=/etc/passwd&x=a+b"),
            ("file=a b&y=%", "file=a%20b&y=%"),
            ("file=%zz%41%2b%7e%25", "file=%zz%41%2b%7e%25"),
            ('file=C:\\win.ini|^[]{}`"<>', "file=C:\\win.ini|^[]{}`%22%3C%3E"),
            ("file=é€&k=;:@!$'()*,/?", "file=%C3%A9%E2%82%AC&k=;:@!$'()*,/?"),
        ],
    )
    async def test_query_is_neither_decoded_nor_double_encoded(
        self, server: RecordingServer, query: str, expected: str
    ) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url(f"/inc.php?{query}#fragment"))
        assert server.last.raw_path == f"/inc.php?{expected}"

    async def test_empty_path_is_root(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.origin)
        assert server.last.raw_path == "/"

    def test_request_url_handles_idna_ipv6_and_userinfo(self) -> None:
        assert str(network._request_url("http://BÜCHER.example/x")) == "http://xn--bcher-kva.example/x"
        assert network._request_url("http://[::1]:8080/a/../b", raw_path=True).raw_path == "/a/../b"
        url = network._request_url("http://user:p%40ss@example.com/")
        assert (url.user, url.password, url.host) == ("user", "p@ss", "example.com")

    async def test_invalid_url_is_recorded(self) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com", retries=3)) as client:
            assert await client.fetch("http://exa mple.com:99999/") is None
            assert client.error_counts == {"InvalidURL": 1}


class TestContentType:
    async def test_json_body_infers_json_content_type(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/api"), data=' {"file": "x"}')
        assert server.last.headers["content-type"] == "application/json"

    async def test_json_array_body_infers_json_content_type(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/api"), data="[1]")
        assert server.last.headers["content-type"] == "application/json"

    async def test_user_header_content_type_is_not_overridden(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", headers=["content-type: text/xml"])
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/api"), data="<a/>")
        assert server.last.headers.getall("content-type") == ["text/xml"]

    async def test_per_request_content_type_is_not_overridden(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/api"), data="{}", headers={"CONTENT-TYPE": "text/plain"})
        assert server.last.headers.getall("content-type") == ["text/plain"]

    async def test_get_has_no_content_type(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/api"))
        assert "content-type" not in server.last.headers


class TestClientOptions:
    async def test_default_verify_is_true_and_trust_env_off(self) -> None:
        with patch("panoptic.network.aiohttp.TCPConnector", wraps=aiohttp.TCPConnector) as connector_cls:
            client = NetworkClient(ScanConfig(url="https://example.com"))
            async with client:
                assert client._session is not None
                # trust_env would also read ~/.netrc; env proxies are resolved manually.
                assert client._session.trust_env is False
                assert client._proxy is None
        assert connector_cls.call_args.kwargs["ssl"] is True

    async def test_invalid_ssl_disables_verification(self) -> None:
        with patch("panoptic.network.aiohttp.TCPConnector", wraps=aiohttp.TCPConnector) as connector_cls:
            async with NetworkClient(ScanConfig(url="https://example.com", invalid_ssl=True)):
                pass
        assert connector_cls.call_args.kwargs["ssl"] is False

    async def test_environment_http_proxy_is_used(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HTTP_PROXY", server.origin)
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        async with NetworkClient(ScanConfig(url="http://target.example")) as client:
            assert await client.fetch("http://target.example/a/../x", raw_path=True) is not None
        assert server.last.raw_path == "http://target.example/a/../x"

    async def test_environment_all_proxy_is_used(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("ALL_PROXY", server.origin)
        async with NetworkClient(ScanConfig(url="http://target.example")) as client:
            assert await client.fetch("http://target.example/x") is not None
        assert server.last.raw_path == "http://target.example/x"

    async def test_no_proxy_bypasses_environment_all_proxy(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for name in ("HTTP_PROXY", "http_proxy"):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("ALL_PROXY", "http://127.0.0.1:9")
        monkeypatch.setenv("NO_PROXY", "127.0.0.1")
        async with NetworkClient(ScanConfig(url=server.origin)) as client:
            assert await client.fetch(server.url("/direct")) is not None
        assert server.last.raw_path == "/direct"

    async def test_environment_socks_proxy_uses_its_own_session(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for name in ("HTTP_PROXY", "http_proxy", "NO_PROXY", "no_proxy"):
            monkeypatch.delenv(name, raising=False)
        proxy = f"socks5://127.0.0.1:{_free_port()}"
        monkeypatch.setenv("ALL_PROXY", proxy)
        async with NetworkClient(ScanConfig(url="http://example.com", retries=0)) as client:
            assert await client.fetch("http://example.com/") is None
            assert client.error_counts == {"ProxyConnectionError": 1}
            session, per_request = client._session_for(client._proxy_for(URL("http://example.com/")))
            assert per_request is None
            assert isinstance(session.connector, aiohttp_socks.ProxyConnector)
            assert client._socks_sessions == {proxy: session}
        assert session.closed

    async def test_no_proxy_bypasses_environment_proxy(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
        monkeypatch.setenv("NO_PROXY", "127.0.0.1")
        async with NetworkClient(ScanConfig(url=server.origin)) as client:
            assert await client.fetch(server.url("/direct")) is not None
        assert server.last.raw_path == "/direct"

    async def test_ignore_proxy_disables_environment_proxies(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
        monkeypatch.delenv("NO_PROXY", raising=False)
        monkeypatch.delenv("no_proxy", raising=False)
        async with NetworkClient(ScanConfig(url=server.origin, ignore_proxy=True, retries=0)) as client:
            assert await client.fetch(server.url("/direct")) is not None
        assert server.last.raw_path == "/direct"

    async def test_netrc_credentials_are_never_sent(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        netrc = tmp_path / ".netrc"
        netrc.write_text("machine 127.0.0.1 login admin password s3cret\n")
        netrc.chmod(0o600)
        monkeypatch.setenv("NETRC", str(netrc))
        monkeypatch.setenv("HOME", str(tmp_path))
        async with NetworkClient(ScanConfig(url=server.origin)) as client:
            assert await client.fetch(server.url("/x")) is not None
        assert "authorization" not in server.last.headers

    async def test_pool_limit_matches_concurrency(self) -> None:
        client = NetworkClient(ScanConfig(url="https://example.com", concurrency=7))
        async with client:
            assert client._session is not None
            assert client._session.connector is not None
            assert client._session.connector.limit == 7

    async def test_session_does_not_decompress_or_store_cookies(self) -> None:
        client = NetworkClient(ScanConfig(url="https://example.com"))
        async with client:
            assert client._session is not None
            assert client._session.auto_decompress is False
            assert isinstance(client._session.cookie_jar, aiohttp.DummyCookieJar)

    async def test_http_proxy_is_passed_per_request(self, server: RecordingServer) -> None:
        """The proxy receives the absolute-form request, traversal path intact."""
        config = ScanConfig(url="http://example.com", proxy=server.origin, ignore_proxy=True)
        client = NetworkClient(config)
        async with client:
            assert client._proxy == server.origin
            assert client._session is not None
            assert type(client._session.connector) is aiohttp.TCPConnector
            response = await client.fetch("http://target.example/a/b/../../etc/passwd", raw_path=True)
        assert response is not None
        assert server.last.raw_path == "http://target.example/a/b/../../etc/passwd"
        assert server.last.headers["host"] == "target.example"

    @pytest.mark.parametrize(
        ("proxy", "proxy_type", "rdns"),
        [
            ("socks5h://user:p%40ss@127.0.0.1:9050", aiohttp_socks.ProxyType.SOCKS5, True),
            ("socks5://127.0.0.1:9050", aiohttp_socks.ProxyType.SOCKS5, None),
            ("SOCKS4://127.0.0.1", aiohttp_socks.ProxyType.SOCKS4, None),
        ],
    )
    async def test_socks_proxy_uses_proxy_connector(
        self, proxy: str, proxy_type: aiohttp_socks.ProxyType, rdns: bool | None
    ) -> None:
        client = NetworkClient(ScanConfig(url="https://example.com", proxy=proxy, concurrency=3, invalid_ssl=True))
        async with client:
            assert client._session is not None
            connector = client._session.connector
            assert isinstance(connector, aiohttp_socks.ProxyConnector)
            assert connector.limit == 3
            assert connector._proxy_type == proxy_type
            assert connector._rdns is rdns
            assert connector._ssl is False
            # The SOCKS proxy replaces environment proxies; no per-request proxy.
            assert client._proxy is None
            assert client._proxy_for(URL("http://example.com/")) is None
        if "user" in proxy:
            assert (connector._proxy_username, connector._proxy_password) == ("user", "p@ss")
            assert connector._proxy_port == 9050
        elif proxy.startswith("SOCKS4"):
            assert connector._proxy_port == 1080

    async def test_socks_proxy_failure_is_retried(self) -> None:
        config = ScanConfig(url="http://example.com", proxy=f"socks5://127.0.0.1:{_free_port()}", retries=1)
        async with NetworkClient(config) as client:
            assert await client.fetch("http://example.com/") is None
            assert client.error_counts == {"ProxyConnectionError": 2}

    def test_header_cookie_overrides_cookie_option_with_warning(self, capsys: pytest.CaptureFixture[str]) -> None:
        config = ScanConfig(url="http://example.com", cookie="a=1", headers=["cookie: b=2"])
        headers = NetworkClient(config)._build_headers()
        assert headers.getall("Cookie") == ["b=2"]
        assert "overrides --cookie" in capsys.readouterr().err

    def test_no_cookie_warning_without_conflict(self, capsys: pytest.CaptureFixture[str]) -> None:
        config = ScanConfig(url="http://example.com", cookie="a=1", headers=["X-A: 1"])
        NetworkClient(config)._build_headers()
        assert "overrides --cookie" not in capsys.readouterr().err


class TestCookies:
    async def test_server_cookies_are_not_persisted(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", cookie="sid=user")
        server.add("/a", headers={"Set-Cookie": "tracker=1; Path=/"})
        client = NetworkClient(config)
        async with client:
            await client.fetch(server.url("/a"))
            await client.fetch(server.url("/b"))
            assert client._session is not None
            assert len(client._session.cookie_jar) == 0
        assert server.requests[1].headers.getall("cookie") == ["sid=user"]

    async def test_no_cookie_header_without_user_cookie(self, server: RecordingServer) -> None:
        server.add("/a", headers={"Set-Cookie": "tracker=1; Path=/"})
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/a"))
            await client.fetch(server.url("/b"))
        assert "cookie" not in server.requests[1].headers


class TestRedirects:
    @pytest.fixture
    async def other(self, make_server: ServerFactory) -> RecordingServer:
        """A second server: same host, different port, so a different origin."""
        return await make_server()

    async def test_user_headers_stripped_on_cross_origin_redirect(
        self, server: RecordingServer, other: RecordingServer
    ) -> None:
        config = ScanConfig(
            url="http://example.com",
            follow_redirects=True,
            cookie="sid=secret",
            headers=["X-Api-Key: k3y", "Authorization: Bearer t"],
        )
        server.add("/start", status=302, headers={"Location": other.url("/x")})
        other.add("/x", "elsewhere")
        async with NetworkClient(config) as client:
            resp = await client.fetch(server.url("/start"))
        assert resp is not None
        assert resp.text == "elsewhere"
        assert len(resp.history) == 1
        first, redirected = server.last, other.last
        assert first.headers["x-api-key"] == "k3y"
        for name in ("x-api-key", "cookie", "authorization"):
            assert name not in redirected.headers
        assert redirected.headers["user-agent"] == first.headers["user-agent"]

    async def test_localhost_and_loopback_ip_are_different_origins(self, server: RecordingServer) -> None:
        assert server.server is not None
        config = ScanConfig(url="http://example.com", follow_redirects=True, headers=["X-Api-Key: k3y"])
        server.add("/start", status=302, headers={"Location": f"http://localhost:{server.server.port}/x"})
        async with NetworkClient(config) as client:
            resp = await client.fetch(server.url("/start"))
        assert resp is not None
        assert resp.url == f"http://localhost:{server.server.port}/x"
        assert "x-api-key" not in server.last.headers

    async def test_per_request_headers_stripped_on_cross_origin_redirect(
        self, server: RecordingServer, other: RecordingServer
    ) -> None:
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        server.add("/start", status=302, headers={"Location": other.url("/x")})
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/start"), headers={"X-Api-Key": "secret"})
        assert server.last.headers["x-api-key"] == "secret"
        assert "x-api-key" not in other.last.headers

    async def test_headers_restored_when_redirected_back_to_origin(
        self, server: RecordingServer, other: RecordingServer
    ) -> None:
        config = ScanConfig(url="http://example.com", follow_redirects=True, cookie="sid=secret")
        server.add("/start", status=302, headers={"Location": other.url("/bounce")})
        other.add("/bounce", status=302, headers={"Location": server.url("/final")})
        async with NetworkClient(config) as client:
            resp = await client.fetch(server.url("/start"), headers={"X-Api-Key": "k"})
        assert resp is not None
        assert len(resp.history) == 2
        assert "cookie" not in other.last.headers
        final = server.last
        assert final.path == "/final"
        assert final.headers.getall("cookie") == ["sid=secret"]
        assert final.headers.getall("x-api-key") == ["k"]

    async def test_inferred_content_type_follows_307(self, server: RecordingServer, other: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        server.add("/start", status=307, headers={"Location": other.url("/x")})
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/start"), data="file=x")
        redirected = other.last
        assert redirected.method == "POST"
        assert redirected.body == b"file=x"
        assert redirected.headers["content-type"] == "application/x-www-form-urlencoded"

    async def test_308_keeps_method_body_and_user_content_type(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", follow_redirects=True, headers=["Content-Type: text/xml"])
        server.add("/start", status=308, headers={"Location": "/next"})
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/start"), data="<a/>")
        redirected = server.last
        assert (redirected.method, redirected.path, redirected.body) == ("POST", "/next", b"<a/>")
        assert redirected.headers.getall("content-type") == ["text/xml"]

    async def test_scheme_change_is_cross_origin(self) -> None:
        http_url = network._request_url("http://example.com/start")
        assert network._origin(http_url) != network._origin(network._request_url("https://example.com/start"))
        assert network._origin(http_url) == network._origin(network._request_url("http://EXAMPLE.com:80/other"))

    async def test_https_redirect_strips_user_headers(self, server: RecordingServer) -> None:
        """An http -> https hop is cross-origin, so user headers are dropped before it is sent."""
        assert server.server is not None
        config = ScanConfig(url="http://example.com", follow_redirects=True, headers=["X-Api-Key: k3y"], retries=0)
        server.add("/start", status=301, headers={"Location": f"https://127.0.0.1:{server.server.port}/start"})
        sent: list[Any] = []
        real_send_once = NetworkClient._send_once

        async def spy(self: NetworkClient, request: Any) -> Response:
            sent.append(request)
            return await real_send_once(self, request)

        with patch.object(NetworkClient, "_send_once", spy):
            async with NetworkClient(config) as client:
                # The plain-HTTP test server cannot complete a TLS handshake.
                assert await client.fetch(server.url("/start")) is None
        assert [request.url.scheme for request in sent] == ["http", "https"]
        assert sent[0].headers["x-api-key"] == "k3y"
        assert "x-api-key" not in sent[1].headers

    async def test_user_headers_kept_on_same_origin_redirect(self, server: RecordingServer) -> None:
        config = ScanConfig(
            url="http://example.com",
            follow_redirects=True,
            cookie="sid=secret",
            headers=["X-Api-Key: k3y"],
        )
        server.add("/start", status=302, headers={"Location": "/final"})
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/start"))
        redirected = server.last
        assert redirected.path == "/final"
        assert redirected.headers["x-api-key"] == "k3y"
        assert redirected.headers["cookie"] == "sid=secret"

    @pytest.mark.parametrize("status", [301, 302, 303])
    async def test_post_redirect_becomes_get_without_body_headers(self, server: RecordingServer, status: int) -> None:
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        server.add("/form", status=status, headers={"Location": "/done"})
        async with NetworkClient(config) as client:
            await client.fetch(server.url("/form"), data="a=b")
        redirected = server.last
        assert (redirected.method, redirected.path, redirected.body) == ("GET", "/done", b"")
        assert "content-type" not in redirected.headers

    async def test_relative_location_is_resolved_as_normal_url(self, server: RecordingServer) -> None:
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        server.add("/a/b/start", status=302, headers={"Location": "../c/./d?x=%2F"})
        async with NetworkClient(config) as client:
            resp = await client.fetch(server.url("/a/b/start"))
        assert resp is not None
        assert server.last.raw_path == "/a/c/d?x=%2F"

    async def test_redirects_are_bounded(self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(network, "MAX_REDIRECTS", 2)
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        server.add("/loop", status=302, headers={"Location": "/loop"})
        async with NetworkClient(config) as client:
            resp = await client.fetch(server.url("/loop"))
        assert resp is not None
        assert resp.status_code == 302
        assert len(resp.history) == 2
        assert len(server.requests) == 3

    async def test_redirect_without_location_is_returned(self, server: RecordingServer) -> None:
        server.add("/r", status=302)
        async with NetworkClient(ScanConfig(url="http://example.com", follow_redirects=True)) as client:
            resp = await client.fetch(server.url("/r"))
        assert resp is not None
        assert resp.status_code == 302


def _raw_deflate(data: bytes) -> bytes:
    """Deflate without the zlib wrapper, as some servers send it."""
    compressor = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


class TestLimits:
    async def test_response_body_is_truncated(self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(network, "MAX_RESPONSE_BYTES", 10)
        server.add("/big", b"0123456789ABCDEF")
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            resp = await client.fetch(server.url("/big"))
        assert resp is not None
        assert resp.content == b"0123456789"

    async def test_reading_stops_at_the_cap(self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch) -> None:
        """An endless body is cut off at the cap and its connection dropped."""
        monkeypatch.setattr(network, "MAX_RESPONSE_BYTES", 1024)

        async def endless(request: web.BaseRequest) -> web.StreamResponse:
            response = web.StreamResponse()
            await response.prepare(request)
            try:
                while True:
                    await response.write(b"A" * 4096)
            except (ConnectionError, RuntimeError):
                pass
            return response

        server.add_handler("/endless", endless)
        server.add("/after", "still works")
        async with NetworkClient(ScanConfig(url="http://example.com", timeout=5.0)) as client:
            resp = await client.fetch(server.url("/endless"))
            assert resp is not None
            assert resp.content == b"A" * 1024
            after = await client.fetch(server.url("/after"))
        assert after is not None
        assert after.text == "still works"

    async def test_gzip_bomb_is_bounded_while_decoding(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(network, "MAX_RESPONSE_BYTES", 1024)
        bomb = gzip.compress(b"\0" * (64 * 1024 * 1024))
        server.add("/bomb", bomb, headers={"Content-Encoding": "gzip"})
        # Any unbounded inflate of the 64 MiB body would exceed this decompress budget.
        real_decompressobj = zlib.decompressobj
        outputs: list[int] = []

        def tracking_decompressobj(*args: Any) -> object:
            inner = real_decompressobj(*args)

            class Tracker:
                def decompress(self, data: bytes, max_length: int = 0) -> bytes:
                    out = inner.decompress(data, max_length)
                    outputs.append(len(out))
                    return out

            return Tracker()

        # Patch only panoptic.network's view of zlib.
        fake_zlib = SimpleNamespace(decompressobj=tracking_decompressobj, MAX_WBITS=zlib.MAX_WBITS, error=zlib.error)
        monkeypatch.setattr(network, "zlib", fake_zlib)
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            resp = await client.fetch(server.url("/bomb"))
        assert resp is not None
        assert resp.content == b"\0" * 1024
        assert sum(outputs) == 1024

    @pytest.mark.parametrize(
        ("encoding", "compress"),
        [
            ("gzip", gzip.compress),
            ("x-gzip", gzip.compress),
            ("deflate", zlib.compress),
            ("deflate", _raw_deflate),
        ],
    )
    async def test_compressed_body_is_decoded(
        self, server: RecordingServer, encoding: str, compress: Callable[[bytes], bytes]
    ) -> None:
        body = b"root:x:0:0:root:/root:/bin/bash\n" * 50
        server.add("/c", compress(body), headers={"Content-Encoding": encoding})
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            resp = await client.fetch(server.url("/c"))
        assert resp is not None
        assert resp.content == body

    async def test_invalid_deflate_body_is_a_decoding_error(self, server: RecordingServer) -> None:
        """Neither zlib-wrapped nor raw deflate: reported as DecodingError, not an uncaught zlib.error."""
        server.add("/c", b"\xff\xff not deflate", headers={"Content-Encoding": "deflate"})
        async with NetworkClient(ScanConfig(url="http://example.com", retries=3)) as client:
            assert await client.fetch(server.url("/c")) is None
            assert client.error_counts == {"DecodingError": 1}

    async def test_invalid_compressed_body_is_not_retried(self, server: RecordingServer) -> None:
        server.add("/c", b"not gzip at all", headers={"Content-Encoding": "gzip"})
        async with NetworkClient(ScanConfig(url="http://example.com", retries=3)) as client:
            assert await client.fetch(server.url("/c")) is None
            assert client.error_counts == {"DecodingError": 1}
        assert len(server.requests) == 1

    async def test_unsupported_encoding_is_kept_raw(self, server: RecordingServer) -> None:
        server.add("/br", b"\x8b\x02raw", headers={"Content-Encoding": "br"})
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            resp = await client.fetch(server.url("/br"))
        assert resp is not None
        assert resp.content == b"\x8b\x02raw"

    async def test_requests_only_boundable_encodings(self, server: RecordingServer) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch(server.url("/"))
        assert server.last.headers.getall("accept-encoding") == ["gzip, deflate"]

    async def test_small_body_is_kept_intact(self, server: RecordingServer) -> None:
        server.add("/small", b"root:x:0:0")
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            resp = await client.fetch(server.url("/small"))
        assert resp is not None
        assert resp.text == "root:x:0:0"

    async def test_overall_deadline_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(network, "REQUEST_DEADLINE_FACTOR", 0.01)

        async def stall(self: NetworkClient, request: Any) -> Response:
            await asyncio.sleep(10)
            raise AssertionError("unreachable")

        monkeypatch.setattr(NetworkClient, "_send", stall)
        config = ScanConfig(url="http://example.com", timeout=1.0, retries=1)
        async with NetworkClient(config) as client:
            assert await client.fetch("http://example.com/slow") is None
            assert client.error_counts["_RequestDeadlineExceeded"] == 2

    async def test_slow_drip_body_hits_the_deadline(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Each chunk arrives within the read timeout, but the whole body does not."""
        monkeypatch.setattr(network, "REQUEST_DEADLINE_FACTOR", 2.0)

        async def drip(request: web.BaseRequest) -> web.StreamResponse:
            response = web.StreamResponse()
            await response.prepare(request)
            for _ in range(40):
                await response.write(b"x")
                await asyncio.sleep(0.05)
            return response

        server.add_handler("/drip", drip)
        async with NetworkClient(ScanConfig(url="http://example.com", timeout=0.3, retries=0)) as client:
            assert await client.fetch(server.url("/drip")) is None
            assert client.error_counts == {"_RequestDeadlineExceeded": 1}

    async def test_read_timeout_is_retried(self, server: RecordingServer) -> None:
        async def slow(request: web.BaseRequest) -> web.StreamResponse:
            await asyncio.sleep(2)
            return web.Response(text="late")

        server.add_handler("/slow", slow)
        server.add("/slow", "fast")
        async with NetworkClient(ScanConfig(url="http://example.com", timeout=0.2, retries=1)) as client:
            resp = await client.fetch(server.url("/slow"))
            assert client.error_counts == {"SocketTimeoutError": 1}
        assert resp is not None
        assert resp.text == "fast"


@pytest.fixture
async def flaky_server() -> AsyncIterator[tuple[str, list[int]]]:
    """A raw server that drops the first connection, then answers ``200 ok``."""
    connections: list[int] = []

    async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        connections.append(1)
        await reader.readuntil(b"\r\n\r\n")
        if len(connections) > 1:
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            await writer.drain()
        writer.close()

    tcp_server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = tcp_server.sockets[0].getsockname()[1]
    yield f"http://127.0.0.1:{port}/", connections
    tcp_server.close()
    await tcp_server.wait_closed()


class TestRetries:
    @pytest.mark.parametrize(
        "exc",
        [
            aiohttp.ServerDisconnectedError(),
            aiohttp.ClientPayloadError("truncated"),
            aiohttp.SocketTimeoutError("slow"),
            aiohttp.ConnectionTimeoutError("connect"),
            aiohttp.ClientOSError(104, "reset"),
            aiohttp.ClientConnectionResetError("reset"),
            ConnectionResetError("reset"),
            TimeoutError(),
            aiohttp_socks.ProxyConnectionError("proxy down"),
            aiohttp_socks.ProxyTimeoutError("proxy slow"),
        ],
    )
    async def test_transient_errors_are_retried(
        self, exc: Exception, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        server.add("/r", "ok")
        _fail_first_send(monkeypatch, exc)
        async with NetworkClient(ScanConfig(url="http://example.com", retries=1)) as client:
            resp = await client.fetch(server.url("/r"))
            assert resp is not None
            assert resp.text == "ok"
            assert client.last_error == type(exc).__name__

    async def test_server_disconnect_on_the_wire_is_retried(self, flaky_server: tuple[str, list[int]]) -> None:
        # POST, because aiohttp itself already retries an idempotent request once.
        url, connections = flaky_server
        async with NetworkClient(ScanConfig(url="http://example.com", retries=1)) as client:
            resp = await client.fetch(url, data="file=x")
            assert client.error_counts == {"ServerDisconnectedError": 1}
        assert resp is not None
        assert resp.text == "ok"
        assert len(connections) == 2

    @pytest.mark.parametrize(
        ("exc", "name"),
        [
            (aiohttp_socks.ProxyError("general SOCKS server failure", error_code=1), "ProxyError"),
            (aiohttp.ClientResponseError(SimpleNamespace(real_url="x"), (), status=400), "ClientResponseError"),  # type: ignore[arg-type]
        ],
    )
    async def test_other_client_errors_are_not_retried(
        self, exc: Exception, name: str, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls = _fail_first_send(monkeypatch, exc, exc)
        async with NetworkClient(ScanConfig(url="http://example.com", retries=3)) as client:
            assert await client.fetch(server.url("/r")) is None
            assert client.error_counts == {name: 1}
        assert len(calls) == 1

    async def test_unsupported_scheme_is_not_retried(self) -> None:
        async with NetworkClient(ScanConfig(url="http://example.com", retries=3)) as client:
            assert await client.fetch("ftp://example.com/r") is None
            assert client.error_counts == {"NonHttpUrlClientError": 1}

    async def test_backoff_sleeps_between_retries(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(network, "_backoff_delay", lambda attempt: float(attempt + 1))
        monkeypatch.setattr(network, "_sleep", fake_sleep)
        _fail_first_send(monkeypatch, aiohttp.ClientOSError(111, "a"), aiohttp.ClientOSError(111, "b"))
        async with NetworkClient(ScanConfig(url="http://example.com", retries=2)) as client:
            assert await client.fetch(server.url("/r")) is not None
        assert sleeps == [1.0, 2.0]

    def test_backoff_delay_grows_and_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(network, "RETRY_BACKOFF_BASE", 0.5)
        assert 0.25 <= network._backoff_delay(0) <= 0.5
        assert 1.0 <= network._backoff_delay(2) <= 2.0
        assert network._backoff_delay(50) <= network.RETRY_BACKOFF_MAX

    async def test_429_retry_after_is_respected_and_capped(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(network, "_sleep", fake_sleep)
        server.add("/r", status=429, headers={"Retry-After": "9999"})
        server.add("/r", "ok")
        async with NetworkClient(ScanConfig(url="http://example.com", retries=1)) as client:
            resp = await client.fetch(server.url("/r"))
            assert client.error_counts == {"HTTP 429": 1}
        assert resp is not None
        assert resp.text == "ok"
        assert sleeps == [network.RETRY_AFTER_MAX]

    async def test_429_without_retry_after_uses_backoff(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(network, "_sleep", fake_sleep)
        monkeypatch.setattr(network, "_backoff_delay", lambda attempt: 0.25)
        server.add("/r", status=429)
        server.add("/r", "ok")
        async with NetworkClient(ScanConfig(url="http://example.com", retries=1)) as client:
            resp = await client.fetch(server.url("/r"))
        assert resp is not None
        assert sleeps == [0.25]

    async def test_503_with_retry_after_is_retried(
        self, server: RecordingServer, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(network, "_sleep", fake_sleep)
        server.add("/r", status=503, headers={"Retry-After": "2"})
        server.add("/r", "ok")
        async with NetworkClient(ScanConfig(url="http://example.com", retries=1)) as client:
            resp = await client.fetch(server.url("/r"))
            assert client.error_counts == {"HTTP 503": 1}
        assert resp is not None
        assert resp.status_code == 200
        assert sleeps == [2.0]

    async def test_503_without_retry_after_is_returned(self, server: RecordingServer) -> None:
        server.add("/r", status=503)
        async with NetworkClient(ScanConfig(url="http://example.com", retries=2)) as client:
            resp = await client.fetch(server.url("/r"))
        assert resp is not None
        assert resp.status_code == 503
        assert len(server.requests) == 1

    async def test_throttled_response_returned_when_retries_exhausted(self, server: RecordingServer) -> None:
        server.add("/r", status=429, headers={"Retry-After": "0"})
        async with NetworkClient(ScanConfig(url="http://example.com", retries=0)) as client:
            resp = await client.fetch(server.url("/r"))
        assert resp is not None
        assert resp.status_code == 429

    def test_retry_after_http_date(self) -> None:
        assert network._retry_after_delay(_make_response(503, {"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})) == 0.0
        assert network._retry_after_delay(_make_response(503, {"Retry-After": "Wed, 21 Oct 2015 07:28:00"})) == 0.0
        assert network._retry_after_delay(_make_response(503, {"Retry-After": "junk"})) is None
        assert network._retry_after_delay(_make_response(503)) is None
