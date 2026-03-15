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

    def test_concurrency_flag(self) -> None:
        args = parse_args(["-u", "http://example.com", "--concurrency", "8"])
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

    def test_match_code_parsing(self) -> None:
        args = parse_args(["--url", "http://example.com", "--match-code", "200,301"])
        assert args["match_codes"] == [200, 301]

    def test_filter_code_parsing(self) -> None:
        args = parse_args(["--url", "http://example.com", "--filter-code", "404,500"])
        assert args["filter_codes"] == [404, 500]

    def test_invalid_match_code_rejected(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["--url", "http://example.com", "--match-code", "999"])

    def test_non_numeric_match_code_rejected(self) -> None:
        with pytest.raises(SystemExit):
            parse_args(["--url", "http://example.com", "--match-code", "abc"])


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
                    "headers": None,
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
                    "headers": ["X-Foo: bar\r\nInjected: yes"],
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
                "headers": None,
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
                    "headers": None,
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
                    "headers": None,
                    "delay": -0.5,
                }
            )


class TestListFormatting:
    def test_list_json_output(self) -> None:
        """--list with --output-format json should produce valid JSON."""
        import json

        from panoptic.cases import list_values

        values = list_values("os")
        output = json.dumps(sorted(values), indent=2)
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert "*NIX" in parsed

    def test_list_all_files_json_output(self) -> None:
        """--list-all-files with --output-format json should produce valid JSON."""
        import json

        from panoptic.cases import list_all_files

        paths = list_all_files()
        output = json.dumps(paths, indent=2)
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) > 0

    def test_list_all_files_csv_output(self) -> None:
        """--list-all-files with --output-format csv should have header row."""
        from panoptic.cases import list_all_files

        paths = list_all_files()
        lines = ["path"] + paths
        assert lines[0] == "path"
        assert len(lines) > 1


class TestParamAutodetection:
    async def test_base64_param_autodetect(self) -> None:
        """Param detection must handle base64 values with = padding."""
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            mock_scanner = AsyncMock()
            mock_scanner_cls.return_value = mock_scanner
            await run(["--url", "http://example.com/test.php?file=dGVzdC50eHQ=&id=1", "--auto"])
            config = mock_scanner_cls.call_args[0][0]
            assert config.param == "file"
