"""Tests for panoptic.cli — argument parsing and validation."""

import os
from pathlib import Path
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
        assert args["prefix"] == "../"
        assert args["multiplier"] == 3

    def test_boolean_flag_can_override_config_with_false(self) -> None:
        args = parse_args(["-u", "http://example.com", "--no-auto"])
        assert args["automatic"] is False

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

    def test_rejects_url_without_hostname(self) -> None:
        with pytest.raises(SystemExit):
            validate_args(
                {
                    "url": "http:///test.php?file=x",
                    "list": None,
                    "update": False,
                    "list_all_files": False,
                    "headers": None,
                }
            )

    def test_rejects_socks4_proxy(self) -> None:
        """httpx (socksio) only supports SOCKS5, so socks4:// must be rejected up front."""
        with pytest.raises(SystemExit):
            validate_args(
                {
                    "url": "http://example.com/test.php?file=x",
                    "list": None,
                    "update": False,
                    "list_all_files": False,
                    "headers": None,
                    "proxy": "socks4://127.0.0.1:9050",
                }
            )

    def test_accepts_socks5_proxy(self) -> None:
        # Should not raise for supported SOCKS5 variants.
        for scheme in ("socks5://127.0.0.1:9050", "socks5h://127.0.0.1:9050"):
            validate_args(
                {
                    "url": "http://example.com/test.php?file=x",
                    "list": None,
                    "update": False,
                    "list_all_files": False,
                    "headers": None,
                    "proxy": scheme,
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

    async def test_list_csv_quotes_values_with_commas(self, capsys: pytest.CaptureFixture[str]) -> None:
        import csv
        import io

        exit_code = await run(["--list", "os", "--output-format", "csv"])
        rows = list(csv.reader(io.StringIO(capsys.readouterr().out)))
        assert exit_code == 0
        assert all(len(row) == 1 for row in rows)
        assert ["DragonFly BSD"] in rows

    @pytest.mark.skipif(os.name != "posix", reason="requires POSIX file permissions")
    async def test_list_output_file_is_owner_only(self, tmp_path: Path) -> None:
        out_path = tmp_path / "os-list.txt"
        exit_code = await run(["--list", "os", "--output-file", str(out_path)])
        assert exit_code == 0
        assert out_path.exists()
        assert os.stat(out_path).st_mode & 0o777 == 0o600


class TestParamAutodetection:
    async def test_base64_param_autodetect(self) -> None:
        """Param detection must handle base64 values with = padding."""
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            mock_scanner = AsyncMock()
            mock_scanner_cls.return_value = mock_scanner
            await run(["--url", "http://example.com/test.php?file=dGVzdC50eHQ=&id=1", "--auto"])
            config = mock_scanner_cls.call_args[0][0]
            assert config.param == "file"

    async def test_skips_empty_parameter_during_autodetect(self) -> None:
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            mock_scanner = AsyncMock()
            mock_scanner.run.return_value = 0
            mock_scanner_cls.return_value = mock_scanner
            exit_code = await run(["--url", "http://example.com/test.php?empty=&file=test", "--auto"])
            config = mock_scanner_cls.call_args[0][0]
        assert exit_code == 0
        assert config.param == "file"

    async def test_url_can_come_from_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.toml"
        config_file.write_text('[defaults]\nurl = "example.com/test.php?file=x"\nautomatic = true\n')
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            mock_scanner = AsyncMock()
            mock_scanner.run.return_value = 0
            mock_scanner_cls.return_value = mock_scanner
            exit_code = await run(["--config", str(config_file)])
            config = mock_scanner_cls.call_args[0][0]
        assert exit_code == 0
        assert config.url == "http://example.com/test.php?file=x"

    async def test_invalid_config_type_returns_operational_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file = tmp_path / "config.toml"
        config_file.write_text('[defaults]\nurl = "example.com/?file=x"\nos_filter = 123\n')
        exit_code = await run(["--config", str(config_file), "--auto"])
        assert exit_code == 2
        assert "os_filter must be a string" in capsys.readouterr().err

    async def test_explicit_missing_parameter_is_rejected(self, capsys: pytest.CaptureFixture[str]) -> None:
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            exit_code = await run(["--url", "http://example.com/?file=x", "--param", "typo"])
        assert exit_code == 1
        assert "Parameter 'typo' not found" in capsys.readouterr().err
        mock_scanner_cls.assert_not_called()

    async def test_json_post_requires_fuzz_injection_marker(self, capsys: pytest.CaptureFixture[str]) -> None:
        body = '{"file":"old"}'
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            exit_code = await run(["--url", "http://example.com/api", "--data", body, "--param", "file"])
        assert exit_code == 1
        assert "place FUZZ at the injection point" in capsys.readouterr().err
        mock_scanner_cls.assert_not_called()

    async def test_json_post_with_fuzz_is_accepted(self) -> None:
        body = '{"file":"FUZZ"}'
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            mock_scanner = AsyncMock()
            mock_scanner.run.return_value = 0
            mock_scanner_cls.return_value = mock_scanner
            exit_code = await run(["--url", "http://example.com/api", "--data", body])
        assert exit_code == 0
        config = mock_scanner_cls.call_args.args[0]
        assert config.data == body


def _scan_args(**overrides: object) -> dict[str, object]:
    args: dict[str, object] = {
        "url": "http://example.com/?file=x",
        "list": None,
        "update": False,
        "list_all_files": False,
        "path_based": False,
        "headers": None,
    }
    args.update(overrides)
    return args


class TestReviewHardening:
    def test_ftp_url_not_mangled_into_http(self) -> None:
        args = parse_args(["--url", "ftp://127.0.0.1/x"])
        assert args["url"] == "ftp://127.0.0.1/x"
        with pytest.raises(SystemExit):
            validate_args(args)

    def test_log_file_cannot_overwrite_load_list(self, tmp_path: Path) -> None:
        list_file = tmp_path / "list.txt"
        with pytest.raises(SystemExit):
            validate_args(_scan_args(list_file=str(list_file), log_file=str(tmp_path / "." / "list.txt")))

    def test_output_file_cannot_overwrite_config(self, tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
        config_file = tmp_path / "config.toml"
        with pytest.raises(SystemExit):
            validate_args(_scan_args(output_file=str(config_file)), str(config_file))
        assert "--config" in capsys.readouterr().err

    async def test_run_rejects_output_over_config_file(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.toml"
        original = "[defaults]\nautomatic = true\n"
        config_file.write_text(original)
        with patch("panoptic.core.Scanner") as mock_scanner_cls, pytest.raises(SystemExit):
            await run(
                ["--url", "http://example.com/?file=x", "--config", str(config_file), "--log-file", str(config_file)]
            )
        mock_scanner_cls.assert_not_called()
        assert config_file.read_text() == original

    @pytest.mark.parametrize(
        "overrides",
        [{"timeout": float("nan")}, {"timeout": float("inf")}, {"delay": float("inf")}, {"delay": float("nan")}],
    )
    def test_non_finite_numbers_rejected(self, overrides: dict[str, object]) -> None:
        with pytest.raises(SystemExit):
            validate_args(_scan_args(**overrides))

    @pytest.mark.parametrize("value", ["0.5-2.0-9", "0.5-inf", "nan-1", "1"])
    def test_random_delay_requires_two_finite_parts(self, value: str) -> None:
        with pytest.raises(SystemExit):
            parse_args(["-u", "http://example.com", "--random-delay", value])

    async def test_config_random_delay_int_is_clean_error(
        self, tmp_path: Path, capsys: pytest.CaptureFixture[str]
    ) -> None:
        config_file = tmp_path / "config.toml"
        config_file.write_text("[defaults]\nrandom_delay = 5\nmatch_codes = 200\n")
        exit_code = await run(["--url", "http://example.com/?file=x", "--config", str(config_file)])
        assert exit_code == 2
        assert "Invalid configuration" in capsys.readouterr().err

    @pytest.mark.parametrize("codes", [200, [200.5], "200"])
    def test_validate_args_rejects_non_list_codes(self, codes: object) -> None:
        with pytest.raises(SystemExit):
            validate_args(_scan_args(match_codes=codes))

    @pytest.mark.parametrize(
        ("overrides", "message"),
        [
            ({"path_based": True, "data": "file=x"}, "--path-based cannot be combined with --data"),
            ({"path_based": True, "param": "file"}, "--path-based cannot be combined with --param"),
            ({"path_based": True, "ext_param": "ext"}, "--path-based cannot be combined with --ext-param"),
            ({"param": "file", "ext_param": "file"}, "different parameter"),
            ({"ext_param": "ext", "data": '{"f":"FUZZ"}'}, "FUZZ"),
            ({"ext_param": "ext", "url": "http://example.com/FUZZ?ext=php"}, "FUZZ"),
        ],
    )
    def test_conflicting_flags_rejected(
        self, overrides: dict[str, object], message: str, capsys: pytest.CaptureFixture[str]
    ) -> None:
        with pytest.raises(SystemExit):
            validate_args(_scan_args(**overrides))
        assert message in capsys.readouterr().err

    async def test_list_mode_validates_merged_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.toml"
        # Only validate_args (not ScanConfig) rejects SOCKS4 proxies.
        config_file.write_text('[proxy]\nurl = "socks4://127.0.0.1:9050"\n')
        with pytest.raises(SystemExit):
            await run(["--list", "os", "--config", str(config_file)])

    async def test_list_all_files_validates_merged_config(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.toml"
        config_file.write_text("[defaults]\nquiet = true\nverbose = true\n")
        with pytest.raises(SystemExit):
            await run(["--list-all-files", "--config", str(config_file)])

    async def test_output_dir_option_reaches_scan_config(self) -> None:
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            mock_scanner = AsyncMock()
            mock_scanner.run.return_value = 0
            mock_scanner_cls.return_value = mock_scanner
            exit_code = await run(["--url", "http://example.com/?file=x", "-w", "--output-dir", "loot"])
        assert exit_code == 0
        assert mock_scanner_cls.call_args.args[0].output_dir == "loot"
