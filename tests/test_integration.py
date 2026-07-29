"""Integration tests — end-to-end scan against mocked HTTP server."""

from panoptic.cli import parse_args, validate_args
from panoptic.config import merge_config
from panoptic.core import build_payload
from panoptic.models import ScanConfig


class TestEndToEnd:
    def test_cli_to_config_pipeline(self) -> None:
        """Verify the full CLI -> config -> ScanConfig pipeline."""
        args = parse_args(
            [
                "--url",
                "http://target.test/vuln.php?file=test.txt",
                "--param",
                "file",
                "--prefix",
                "../",
                "--multiplier",
                "3",
                "--timeout",
                "5",
                "--concurrency",
                "2",
                "--output-format",
                "json",
                "--auto",
            ]
        )
        validate_args(args)
        config = merge_config(args, {})

        assert config.url == "http://target.test/vuln.php?file=test.txt"
        assert config.param == "file"
        assert config.prefix == "../"
        assert config.multiplier == 3
        assert "../../../etc/passwd" in build_payload(config, "/etc/passwd", "file=test.txt")
        assert config.timeout == 5.0
        assert config.concurrency == 2
        assert config.automatic is True

    def test_list_command_runs(self) -> None:
        """Verify --list software works end-to-end."""
        from panoptic.cases import list_values

        values = list_values("software")
        assert len(values) > 0
        assert any("PHP" in v for v in values)

    def test_list_all_files_runs(self) -> None:
        """Verify --list-all-files works end-to-end."""
        from panoptic.cases import list_all_files

        files = list_all_files()
        assert len(files) > 100  # Should have many file paths
        assert any("/etc/passwd" in f for f in files)

    def test_cases_load_with_filters(self) -> None:
        """Verify case filtering works end-to-end."""
        from panoptic.cases import parse_cases

        config = ScanConfig(
            url="http://target.test/vuln.php?file=test.txt",
            os_filter="*NIX",
            type_filter="conf",
        )
        cases = parse_cases(config)
        assert len(cases) > 0
        for case in cases:
            if case.os:
                # *NIX filter keeps the Unix family (FreeBSD, OS X, ...) but excludes Windows.
                assert case.os != "Windows"
            if case.file_type:
                assert case.file_type.value == "conf"
