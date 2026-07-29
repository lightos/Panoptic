"""Tests for panoptic.config — TOML config loading and merge."""

from pathlib import Path

import pytest

from panoptic.config import load_config, merge_config
from panoptic.core import build_payload
from panoptic.models import OutputFormat


class TestLoadConfig:
    def test_returns_dict(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.toml"
        config_file.write_text("[defaults]\nconcurrency = 16\ntimeout = 30.0\n")
        result = load_config(str(config_file))
        assert result["defaults"]["concurrency"] == 16

    def test_missing_file_returns_empty(self, capsys: pytest.CaptureFixture[str]) -> None:
        result = load_config("/nonexistent/config.toml")
        assert result == {}
        assert "does not exist" in capsys.readouterr().err

    def test_invalid_toml_returns_empty(self, tmp_path: Path) -> None:
        config_file = tmp_path / "bad.toml"
        config_file.write_text("this is [not valid toml")
        result = load_config(str(config_file))
        assert result == {}


class TestMergeConfig:
    def test_cli_overrides_config_file(self) -> None:
        file_config = {"defaults": {"concurrency": 16, "timeout": 30.0}}
        cli_args = {"url": "http://example.com", "concurrency": 8}
        config = merge_config(cli_args, file_config)
        assert config.concurrency == 8  # CLI wins
        assert config.timeout == 30.0  # File value kept

    def test_cli_overrides_defaults(self) -> None:
        cli_args = {"url": "http://example.com", "timeout": 5.0}
        config = merge_config(cli_args, {})
        assert config.timeout == 5.0

    def test_file_overrides_defaults(self) -> None:
        file_config = {"defaults": {"concurrency": 32}}
        cli_args = {"url": "http://example.com"}
        config = merge_config(cli_args, file_config)
        assert config.concurrency == 32

    def test_proxy_from_file(self) -> None:
        file_config = {"proxy": {"url": "socks5://127.0.0.1:9050"}}
        cli_args = {"url": "http://example.com"}
        config = merge_config(cli_args, file_config)
        assert config.proxy == "socks5://127.0.0.1:9050"

    def test_headers_from_file(self) -> None:
        file_config = {"headers": {"user_agent": "CustomBot/1.0"}}
        cli_args = {"url": "http://example.com"}
        config = merge_config(cli_args, file_config)
        assert config.user_agent == "CustomBot/1.0"

    def test_cli_headers_extend_config_headers(self) -> None:
        config = merge_config(
            {"url": "http://example.com", "headers": ["X-CLI: cli"]},
            {"headers": {"values": ["X-Config: config"]}},
        )
        assert config.headers == ["X-Config: config", "X-CLI: cli"]

    def test_output_format_enum(self) -> None:
        cli_args = {"url": "http://example.com", "output_format": "json"}
        config = merge_config(cli_args, {})
        assert config.output_format == OutputFormat.JSON

    def test_cli_false_overrides_true_boolean(self) -> None:
        config = merge_config(
            {"url": "http://example.com", "automatic": False},
            {"defaults": {"automatic": True}},
        )
        assert config.automatic is False

    def test_config_multiplier_applies_to_payload(self) -> None:
        config = merge_config(
            {"url": "http://example.com/?file=x"},
            {"defaults": {"param": "file", "prefix": "../", "multiplier": 3}},
        )
        assert "../../../etc/passwd" in build_payload(config, "/etc/passwd", "file=x")

    def test_config_url_is_normalized(self) -> None:
        config = merge_config({}, {"defaults": {"url": "example.com/?file=x"}})
        assert config.url == "http://example.com/?file=x"

    def test_invalid_output_format_raises(self) -> None:
        with pytest.raises(ValueError, match="output_format"):
            merge_config({"url": "http://example.com"}, {"defaults": {"output_format": "xml"}})

    def test_unknown_option_warns(self, capsys: pytest.CaptureFixture[str]) -> None:
        merge_config({"url": "http://example.com"}, {"defaults": {"concurreny": 8}})
        assert "concurreny" in capsys.readouterr().err

    @pytest.mark.parametrize(
        ("file_config", "message"),
        [
            ({"proxy": {"url": 123}}, "proxy must be a string"),
            ({"headers": {"cookie": 123}}, "cookie must be a string"),
            ({"defaults": {"os_filter": 123}}, "os_filter must be a string"),
            ({"defaults": {"automatic": "yes"}}, "automatic must be a boolean"),
            ({"defaults": {"concurrency": 4.5}}, "concurrency must be an integer"),
        ],
    )
    def test_invalid_config_types_raise(self, file_config: dict[str, object], message: str) -> None:
        with pytest.raises(ValueError, match=message):
            merge_config({"url": "http://example.com"}, file_config)
