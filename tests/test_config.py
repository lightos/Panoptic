"""Tests for panoptic.config — TOML config loading and merge."""

from pathlib import Path

from panoptic.config import load_config, merge_config
from panoptic.models import OutputFormat


class TestLoadConfig:
    def test_returns_dict(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.toml"
        config_file.write_text("[defaults]\nconcurrency = 16\ntimeout = 30.0\n")
        result = load_config(str(config_file))
        assert result["defaults"]["concurrency"] == 16

    def test_missing_file_returns_empty(self) -> None:
        result = load_config("/nonexistent/config.toml")
        assert result == {}

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

    def test_output_format_enum(self) -> None:
        cli_args = {"url": "http://example.com", "output_format": "json"}
        config = merge_config(cli_args, {})
        assert config.output_format == OutputFormat.JSON
