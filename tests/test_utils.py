"""Tests for panoptic.utils."""

import pytest

from panoptic.utils import (
    get_random_agent,
    load_data_file,
    sanitize_filename,
    validate_header,
    validate_url_scheme,
)


class TestValidateUrlScheme:
    def test_http_valid(self) -> None:
        validate_url_scheme("http://example.com/test.php?file=x")

    def test_https_valid(self) -> None:
        validate_url_scheme("https://example.com/test.php?file=x")

    def test_file_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Only http:// and https://"):
            validate_url_scheme("file:///etc/passwd")

    def test_ftp_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Only http:// and https://"):
            validate_url_scheme("ftp://internal/data")

    def test_no_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Only http:// and https://"):
            validate_url_scheme("example.com/test")


class TestValidateHeader:
    def test_valid_header(self) -> None:
        name, value = validate_header("X-Forwarded-For: 127.0.0.1")
        assert name == "X-Forwarded-For"
        assert value == "127.0.0.1"

    def test_crlf_in_value_rejected(self) -> None:
        with pytest.raises(ValueError, match="CRLF"):
            validate_header("X-Foo: bar\r\nX-Injected: evil")

    def test_crlf_in_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="CRLF"):
            validate_header("X-Foo\r\n: bar")

    def test_no_colon_rejected(self) -> None:
        with pytest.raises(ValueError, match="colon"):
            validate_header("InvalidHeader")

    def test_value_with_equals(self) -> None:
        """Headers with = in value should work (e.g., auth tokens)."""
        name, value = validate_header("Authorization: Bearer abc=def")
        assert name == "Authorization"
        assert value == "Bearer abc=def"


class TestSanitizeFilename:
    def test_slashes_replaced(self) -> None:
        assert "/" not in sanitize_filename("/etc/passwd")

    def test_traversal_neutralized(self) -> None:
        result = sanitize_filename("../../../etc/passwd")
        assert ".." not in result

    def test_colons_replaced(self) -> None:
        assert ":" not in sanitize_filename("C:\\Windows\\system.ini")


class TestLoadDataFile:
    def test_load_agents(self) -> None:
        content = load_data_file("agents.txt")
        assert len(content) > 0
        assert "Mozilla" in content

    def test_load_nonexistent_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_data_file("nonexistent.txt")


class TestGetRandomAgent:
    def test_returns_string(self) -> None:
        agent = get_random_agent()
        assert isinstance(agent, str)
        assert len(agent) > 0

    def test_returns_different_values(self) -> None:
        """Should return different agents with deterministic seed."""
        import random

        random.seed(42)
        agents = {get_random_agent() for _ in range(20)}
        assert len(agents) > 1
