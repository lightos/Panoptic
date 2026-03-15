"""Tests for panoptic.cli — argument parsing and validation."""

from unittest.mock import AsyncMock, patch

import pytest

from panoptic.cli import parse_args, run, validate_args


class TestParseArgs:
    def test_url_required_for_scan(self) -> None:
        args = parse_args(["--url", "http://example.com/test.php?file=x"])
        assert args["url"] == "http://example.com/test.php?file=x"

    def test_url_normalized(self) -> None:
        args = parse_args(["--url", "example.com/test.php?file=x"])
        assert args["url"].startswith("http://")

    def test_short_flags(self) -> None:
        args = parse_args(["-u", "http://example.com", "-v", "-a"])
        assert args["url"] == "http://example.com"
        assert args["verbose"] is True
        assert args["automatic"] is True

    def test_threads_maps_to_concurrency(self) -> None:
        args = parse_args(["-u", "http://example.com", "--threads", "8"])
        assert args["concurrency"] == 8

    def test_new_flags(self) -> None:
        args = parse_args(
            [
                "-u",
                "http://example.com",
                "--timeout",
                "30",
                "--retries",
                "5",
                "--delay",
                "0.5",
                "--output-format",
                "json",
            ]
        )
        assert args["timeout"] == 30.0
        assert args["retries"] == 5
        assert args["delay"] == 0.5
        assert args["output_format"] == "json"

    def test_prefix_multiplier(self) -> None:
        args = parse_args(["-u", "http://example.com", "--prefix", "../", "--multiplier", "3"])
        assert args["prefix"] == "../../../"

    def test_list_command(self) -> None:
        args = parse_args(["--list", "software"])
        assert args["list"] == "software"

    def test_inverted_random_delay_rejected(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["--url", "http://example.com", "--random-delay", "5.0-0.5"])


class TestValidateArgs:
    def test_rejects_file_scheme(self) -> None:
        with pytest.raises(SystemExit):
            validate_args(
                {
                    "url": "file:///etc/passwd",
                    "list": None,
                    "update": False,
                    "list_all_files": False,
                    "path_based": False,
                    "header": None,
                }
            )

    def test_rejects_crlf_header(self) -> None:
        with pytest.raises(SystemExit):
            validate_args(
                {
                    "url": "http://example.com",
                    "list": None,
                    "update": False,
                    "list_all_files": False,
                    "path_based": False,
                    "header": "X-Foo: bar\r\nInjected: yes",
                }
            )

    def test_accepts_valid_args(self) -> None:
        # Should not raise
        validate_args(
            {
                "url": "http://example.com",
                "list": None,
                "update": False,
                "list_all_files": False,
                "path_based": False,
                "header": None,
            }
        )

    def test_rejects_negative_timeout(self) -> None:
        with pytest.raises(SystemExit):
            validate_args(
                {
                    "url": "http://example.com",
                    "list": None,
                    "update": False,
                    "list_all_files": False,
                    "header": None,
                    "timeout": -1.0,
                }
            )

    def test_rejects_negative_delay(self) -> None:
        with pytest.raises(SystemExit):
            validate_args(
                {
                    "url": "http://example.com",
                    "list": None,
                    "update": False,
                    "list_all_files": False,
                    "header": None,
                    "delay": -0.5,
                }
            )


class TestParamAutodetection:
    async def test_base64_param_autodetect(self) -> None:
        """Param detection must handle base64 values with = padding."""
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            mock_scanner = AsyncMock()
            mock_scanner_cls.return_value = mock_scanner
            await run(["--url", "http://example.com/test.php?file=dGVzdC50eHQ=&id=1", "--auto"])
            config = mock_scanner_cls.call_args[0][0]
            assert config.param == "file"
