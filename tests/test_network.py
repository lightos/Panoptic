"""Tests for panoptic.network — async HTTP client."""

import httpx
import pytest
from pytest_httpx import HTTPXMock

from panoptic.models import ScanConfig
from panoptic.network import NetworkClient


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

    async def test_fetch_timeout_returns_none(self, config: ScanConfig, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.TimeoutException("timed out"))
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/slow")
            assert response is None

    async def test_fetch_connection_error_returns_none(self, config: ScanConfig, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/down")
            assert response is None

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
