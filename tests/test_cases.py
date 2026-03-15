"""Tests for panoptic.cases — XML case parsing and filtering."""

import pytest

from panoptic.cases import load_custom_list, load_versions, parse_cases
from panoptic.models import Case, FileType, ScanConfig


class TestParseCases:
    def test_returns_list_of_cases(self) -> None:
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        assert isinstance(cases, list)
        assert len(cases) > 0
        assert all(isinstance(c, Case) for c in cases)

    def test_cases_are_frozen(self) -> None:
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        with pytest.raises(AttributeError):
            cases[0].location = "modified"  # type: ignore[misc]

    def test_filter_by_os(self) -> None:
        config = ScanConfig(url="http://example.com", os_filter="*NIX")
        cases = parse_cases(config)
        assert all(c.os == "*NIX" for c in cases if c.os is not None)

    def test_filter_by_software(self) -> None:
        config = ScanConfig(url="http://example.com", software_filter="PHP")
        cases = parse_cases(config)
        assert all(c.software == "PHP" for c in cases if c.software is not None)

    def test_filter_by_type(self) -> None:
        config = ScanConfig(url="http://example.com", type_filter="conf")
        cases = parse_cases(config)
        assert all(c.file_type == FileType.CONF for c in cases if c.file_type is not None)

    def test_host_placeholder_expansion(self) -> None:
        """Verifies {HOST} in case locations is replaced with target netloc."""
        config = ScanConfig(url="http://target.example.com/test.php?f=x")
        cases = parse_cases(config)
        for case in cases:
            assert "{HOST}" not in case.location


class TestLoadVersions:
    def test_returns_dict(self) -> None:
        versions = load_versions()
        assert isinstance(versions, dict)
        assert "JBOSS" in versions
        assert isinstance(versions["JBOSS"], list)
        assert len(versions["JBOSS"]) > 0


def test_file_type_has_mix() -> None:
    assert FileType.MIX.value == "mix"


class TestLoadCustomList:
    def test_load_from_file(self, tmp_path: pytest.TempPathFactory) -> None:
        listfile = tmp_path / "custom.txt"  # type: ignore[operator]
        listfile.write_text("/etc/passwd\n/etc/shadow\n/var/log/syslog\n")
        cases = load_custom_list(str(listfile))
        assert len(cases) == 3
        assert cases[0].location == "/etc/passwd"

    def test_skips_empty_lines(self, tmp_path: pytest.TempPathFactory) -> None:
        listfile = tmp_path / "custom.txt"  # type: ignore[operator]
        listfile.write_text("/etc/passwd\n\n/etc/shadow\n\n")
        cases = load_custom_list(str(listfile))
        assert len(cases) == 2

    def test_nonexistent_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_custom_list("/nonexistent/path/list.txt")

    def test_directory_raises(self, tmp_path: pytest.TempPathFactory) -> None:
        with pytest.raises(ValueError, match="regular file"):
            load_custom_list(str(tmp_path))
