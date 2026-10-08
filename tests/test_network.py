"""Tests for panoptic.network — async HTTP client."""

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from panoptic import network
from panoptic.models import ScanConfig
from panoptic.network import NetworkClient


@pytest.fixture(autouse=True)
def _no_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep retry tests fast: no backoff sleeps."""
    monkeypatch.setattr(network, "RETRY_BACKOFF_BASE", 0.0)


class TestNetworkClient:
    @pytest.fixture
    def config(self) -> ScanConfig:
        return ScanConfig(
            url="http://example.com",
            timeout=5.0,
            retries=1,
            concurrency=2,
        )

    async def test_context_manager(self, config: ScanConfig) -> None:
        async with NetworkClient(config) as client:
            assert client._client is not None

    async def test_fetch_get(self, config: ScanConfig, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url="http://example.com/test", text="hello")
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/test")
            assert response is not None
            assert response.text == "hello"
            assert response.status_code == 200

    async def test_fetch_post(self, config: ScanConfig, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url="http://example.com/test", text="posted")
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/test", data="file=test")
            assert response is not None
        request = httpx_mock.get_request()
        assert request is not None
        assert request.method == "POST"
        assert request.content == b"file=test"
        assert request.headers["content-type"] == "application/x-www-form-urlencoded"

    async def test_fetch_timeout_returns_none(self, config: ScanConfig, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.TimeoutException("timed out"))
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/slow")
            assert response is None

    async def test_fetch_connection_error_returns_none(self, config: ScanConfig, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        httpx_mock.add_exception(httpx.ConnectError("refused again"))
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/down")
            assert response is None

    async def test_connect_error_is_retried(self, config: ScanConfig, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("temporary"))
        httpx_mock.add_response(url="http://example.com/retry", text="recovered")
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/retry")
        assert response is not None
        assert response.text == "recovered"

    async def test_ssl_and_environment_proxy_options_reach_httpx(self) -> None:
        config = ScanConfig(
            url="https://example.com",
            invalid_ssl=True,
            ignore_proxy=False,
        )
        mock_client = AsyncMock()
        with patch("panoptic.network.httpx.AsyncClient", return_value=mock_client) as client_cls:
            async with NetworkClient(config):
                pass

        kwargs = client_cls.call_args.kwargs
        assert kwargs["verify"] is False
        assert kwargs["trust_env"] is True
        assert "transport" not in kwargs

    async def test_ignore_proxy_disables_environment_proxies(self) -> None:
        config = ScanConfig(url="https://example.com", ignore_proxy=True)
        mock_client = AsyncMock()
        with patch("panoptic.network.httpx.AsyncClient", return_value=mock_client) as client_cls:
            async with NetworkClient(config):
                pass
        assert client_cls.call_args.kwargs["trust_env"] is False

    async def test_custom_user_agent(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", user_agent="CustomBot/1.0")
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/test")
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["user-agent"] == "CustomBot/1.0"

    async def test_custom_cookie(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", cookie="sid=abc123")
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/test")
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["cookie"] == "sid=abc123"

    async def test_custom_header(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", headers=["X-Custom: value123"])
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/test")
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["x-custom"] == "value123"

    async def test_multiple_custom_headers(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", headers=["X-Custom: val1", "X-Other: val2"])
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/test")
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["x-custom"] == "val1"
        assert request.headers["x-other"] == "val2"

    async def test_no_follow_redirects(self, config: ScanConfig, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(status_code=302, headers={"Location": "/other"})
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/redir")
            assert response is not None
            assert response.status_code == 302  # Should NOT follow

    async def test_follow_redirects_when_enabled(self, httpx_mock: HTTPXMock) -> None:
        """Verify redirect following works by checking final response content."""
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        httpx_mock.add_response(
            url="http://example.com/start",
            status_code=302,
            headers={"Location": "http://example.com/final"},
        )
        httpx_mock.add_response(url="http://example.com/final", text="followed")
        async with NetworkClient(config) as client:
            resp = await client.fetch("http://example.com/start")
            assert resp is not None
            assert resp.text == "followed"
            assert resp.status_code == 200

    async def test_no_follow_redirects_by_default(self, httpx_mock: HTTPXMock) -> None:
        """Default behavior should NOT follow redirects."""
        config = ScanConfig(url="http://example.com")
        httpx_mock.add_response(
            url="http://example.com/start",
            status_code=302,
            headers={"Location": "http://example.com/final"},
        )
        async with NetworkClient(config) as client:
            resp = await client.fetch("http://example.com/start")
            assert resp is not None
            assert resp.status_code == 302


class TestContentType:
    async def test_json_body_infers_json_content_type(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response()
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch("http://example.com/api", data=' {"file": "x"}')
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["content-type"] == "application/json"

    async def test_json_array_body_infers_json_content_type(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response()
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch("http://example.com/api", data="[1]")
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["content-type"] == "application/json"

    async def test_user_header_content_type_is_not_overridden(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", headers=["content-type: text/xml"])
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/api", data="<a/>")
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers.get_list("content-type") == ["text/xml"]

    async def test_per_request_content_type_is_not_overridden(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response()
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch("http://example.com/api", data="{}", headers={"CONTENT-TYPE": "text/plain"})
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers.get_list("content-type") == ["text/plain"]

    async def test_get_has_no_content_type(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response()
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch("http://example.com/api")
        request = httpx_mock.get_request()
        assert request is not None
        assert "content-type" not in request.headers


class TestClientOptions:
    async def test_default_verify_is_true(self) -> None:
        with patch("panoptic.network.httpx.AsyncClient", return_value=AsyncMock()) as client_cls:
            async with NetworkClient(ScanConfig(url="https://example.com")):
                pass
        kwargs = client_cls.call_args.kwargs
        assert kwargs["verify"] is True
        assert kwargs["proxy"] is None

    async def test_proxy_passed_to_httpx(self) -> None:
        config = ScanConfig(url="https://example.com", proxy="http://127.0.0.1:8080")
        with patch("panoptic.network.httpx.AsyncClient", return_value=AsyncMock()) as client_cls:
            async with NetworkClient(config):
                pass
        assert client_cls.call_args.kwargs["proxy"] == "http://127.0.0.1:8080"

    async def test_pool_limits_match_concurrency(self) -> None:
        config = ScanConfig(url="https://example.com", concurrency=7)
        with patch("panoptic.network.httpx.AsyncClient", return_value=AsyncMock()) as client_cls:
            async with NetworkClient(config):
                pass
        limits = client_cls.call_args.kwargs["limits"]
        assert limits.max_connections == 7
        assert limits.max_keepalive_connections == 7

    def test_header_cookie_overrides_cookie_option_with_warning(self, capsys: pytest.CaptureFixture[str]) -> None:
        config = ScanConfig(url="http://example.com", cookie="a=1", headers=["Cookie: b=2"])
        headers = NetworkClient(config)._build_headers()
        assert headers["Cookie"] == "b=2"
        assert "overrides --cookie" in capsys.readouterr().err

    def test_no_cookie_warning_without_conflict(self, capsys: pytest.CaptureFixture[str]) -> None:
        config = ScanConfig(url="http://example.com", cookie="a=1", headers=["X-A: 1"])
        NetworkClient(config)._build_headers()
        assert "overrides --cookie" not in capsys.readouterr().err


class TestCookies:
    async def test_server_cookies_are_not_persisted(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", cookie="sid=user")
        httpx_mock.add_response(url="http://example.com/a", headers={"Set-Cookie": "tracker=1; Path=/"})
        httpx_mock.add_response(url="http://example.com/b")
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/a")
            await client.fetch("http://example.com/b")
            assert client._client is not None
            assert len(client._client.cookies.jar) == 0
        second = httpx_mock.get_requests()[1]
        assert second.headers["cookie"] == "sid=user"

    async def test_no_cookie_header_without_user_cookie(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url="http://example.com/a", headers={"Set-Cookie": "tracker=1; Path=/"})
        httpx_mock.add_response(url="http://example.com/b")
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            await client.fetch("http://example.com/a")
            await client.fetch("http://example.com/b")
        assert "cookie" not in httpx_mock.get_requests()[1].headers


class TestRedirects:
    async def test_user_headers_stripped_on_cross_origin_redirect(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(
            url="http://example.com",
            follow_redirects=True,
            cookie="sid=secret",
            headers=["X-Api-Key: k3y"],
        )
        httpx_mock.add_response(
            url="http://example.com/start", status_code=302, headers={"Location": "http://example.org/x"}
        )
        httpx_mock.add_response(url="http://example.org/x", text="elsewhere")
        async with NetworkClient(config) as client:
            resp = await client.fetch("http://example.com/start")
        assert resp is not None
        assert resp.text == "elsewhere"
        assert len(resp.history) == 1
        redirected = httpx_mock.get_requests()[1]
        assert "x-api-key" not in redirected.headers
        assert "cookie" not in redirected.headers
        assert "user-agent" in redirected.headers

    async def test_scheme_change_is_cross_origin(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", follow_redirects=True, headers=["X-Api-Key: k3y"])
        httpx_mock.add_response(
            url="http://example.com/start", status_code=301, headers={"Location": "https://example.com/start"}
        )
        httpx_mock.add_response(url="https://example.com/start")
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/start")
        assert "x-api-key" not in httpx_mock.get_requests()[1].headers

    async def test_user_headers_kept_on_same_origin_redirect(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(
            url="http://example.com",
            follow_redirects=True,
            cookie="sid=secret",
            headers=["X-Api-Key: k3y"],
        )
        httpx_mock.add_response(url="http://example.com/start", status_code=302, headers={"Location": "/final"})
        httpx_mock.add_response(url="http://example.com/final")
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/start")
        redirected = httpx_mock.get_requests()[1]
        assert redirected.headers["x-api-key"] == "k3y"
        assert redirected.headers["cookie"] == "sid=secret"

    async def test_post_redirect_becomes_get_without_body_headers(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        httpx_mock.add_response(url="http://example.com/form", status_code=302, headers={"Location": "/done"})
        httpx_mock.add_response(url="http://example.com/done")
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/form", data="a=b")
        redirected = httpx_mock.get_requests()[1]
        assert redirected.method == "GET"
        assert "content-type" not in redirected.headers

    async def test_redirects_are_bounded(self, httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(network, "MAX_REDIRECTS", 2)
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        httpx_mock.add_response(
            url="http://example.com/loop", status_code=302, headers={"Location": "/loop"}, is_reusable=True
        )
        async with NetworkClient(config) as client:
            resp = await client.fetch("http://example.com/loop")
        assert resp is not None
        assert resp.status_code == 302
        assert len(httpx_mock.get_requests()) == 3


class TestLimits:
    async def test_response_body_is_truncated(self, httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(network, "MAX_RESPONSE_BYTES", 10)
        httpx_mock.add_response(url="http://example.com/big", content=b"0123456789ABCDEF")
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            resp = await client.fetch("http://example.com/big")
        assert resp is not None
        assert resp.content == b"0123456789"

    async def test_small_body_is_kept_intact(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url="http://example.com/small", content=b"root:x:0:0")
        async with NetworkClient(ScanConfig(url="http://example.com")) as client:
            resp = await client.fetch("http://example.com/small")
        assert resp is not None
        assert resp.text == "root:x:0:0"

    async def test_overall_deadline_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(network, "REQUEST_DEADLINE_FACTOR", 0.01)

        async def stall(self: NetworkClient, request: httpx.Request) -> httpx.Response:
            await asyncio.sleep(10)
            raise AssertionError("unreachable")

        monkeypatch.setattr(NetworkClient, "_send", stall)
        config = ScanConfig(url="http://example.com", timeout=1.0, retries=1)
        async with NetworkClient(config) as client:
            assert await client.fetch("http://example.com/slow") is None
            assert client.error_counts["_RequestDeadlineExceeded"] == 2


class TestRetries:
    @pytest.mark.parametrize(
        "exc",
        [
            httpx.ReadTimeout("slow"),
            httpx.PoolTimeout("pool"),
            httpx.RemoteProtocolError("reset"),
            httpx.ConnectTimeout("connect"),
        ],
    )
    async def test_transient_errors_are_retried(self, exc: Exception, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(exc)
        httpx_mock.add_response(url="http://example.com/r", text="ok")
        async with NetworkClient(ScanConfig(url="http://example.com", retries=1)) as client:
            resp = await client.fetch("http://example.com/r")
            assert resp is not None
            assert resp.text == "ok"
            assert client.last_error == type(exc).__name__

    async def test_non_transient_error_is_not_retried(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.UnsupportedProtocol("nope"))
        async with NetworkClient(ScanConfig(url="http://example.com", retries=3)) as client:
            assert await client.fetch("http://example.com/r") is None
            assert client.error_counts == {"UnsupportedProtocol": 1}
        assert len(httpx_mock.get_requests()) == 1

    async def test_backoff_sleeps_between_retries(self, httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch) -> None:
        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(network, "_backoff_delay", lambda attempt: float(attempt + 1))
        monkeypatch.setattr(network, "_sleep", fake_sleep)
        httpx_mock.add_exception(httpx.ConnectError("a"))
        httpx_mock.add_exception(httpx.ConnectError("b"))
        httpx_mock.add_response(url="http://example.com/r")
        async with NetworkClient(ScanConfig(url="http://example.com", retries=2)) as client:
            assert await client.fetch("http://example.com/r") is not None
        assert sleeps == [1.0, 2.0]

    def test_backoff_delay_grows_and_is_capped(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(network, "RETRY_BACKOFF_BASE", 0.5)
        assert 0.25 <= network._backoff_delay(0) <= 0.5
        assert 1.0 <= network._backoff_delay(2) <= 2.0
        assert network._backoff_delay(50) <= network.RETRY_BACKOFF_MAX

    async def test_429_retry_after_is_respected_and_capped(
        self, httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sleeps: list[float] = []

        async def fake_sleep(delay: float) -> None:
            sleeps.append(delay)

        monkeypatch.setattr(network, "_sleep", fake_sleep)
        httpx_mock.add_response(url="http://example.com/r", status_code=429, headers={"Retry-After": "9999"})
        httpx_mock.add_response(url="http://example.com/r", text="ok")
        async with NetworkClient(ScanConfig(url="http://example.com", retries=1)) as client:
            resp = await client.fetch("http://example.com/r")
        assert resp is not None
        assert resp.text == "ok"
        assert sleeps == [network.RETRY_AFTER_MAX]

    async def test_503_without_retry_after_is_returned(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url="http://example.com/r", status_code=503)
        async with NetworkClient(ScanConfig(url="http://example.com", retries=2)) as client:
            resp = await client.fetch("http://example.com/r")
        assert resp is not None
        assert resp.status_code == 503

    async def test_throttled_response_returned_when_retries_exhausted(self, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url="http://example.com/r", status_code=429, headers={"Retry-After": "0"})
        async with NetworkClient(ScanConfig(url="http://example.com", retries=0)) as client:
            resp = await client.fetch("http://example.com/r")
        assert resp is not None
        assert resp.status_code == 429

    def test_retry_after_http_date(self) -> None:
        resp = httpx.Response(503, headers={"Retry-After": "Wed, 21 Oct 2015 07:28:00 GMT"})
        assert network._retry_after_delay(resp) == 0.0
        assert network._retry_after_delay(httpx.Response(503, headers={"Retry-After": "junk"})) is None
