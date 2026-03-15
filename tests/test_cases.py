"""Tests for panoptic.cases — CSV case parsing, validation, and filtering."""

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


class TestCsvValidation:
    def test_parse_cases_returns_expected_count(self) -> None:
        """CSV parser returns expected number of cases."""
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        assert len(cases) == 1024

    def test_all_cases_have_metadata(self) -> None:
        """Every case from CSV has all metadata fields populated."""
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        for case in cases:
            assert case.os is not None, f"Missing os: {case.location}"
            assert case.software is not None, f"Missing software: {case.location}"
            assert case.category is not None, f"Missing category: {case.location}"
            assert case.file_type is not None, f"Missing file_type: {case.location}"

    def test_bash_entries_are_typed_other(self) -> None:
        """Bash entries (formerly 'mix') are classified as 'other'."""
        config = ScanConfig(url="http://example.com", software_filter="Bash")
        cases = parse_cases(config)
        assert len(cases) > 0
        assert all(c.file_type == FileType.OTHER for c in cases)


class TestListFunctions:
    def test_list_values_os(self) -> None:
        from panoptic.cases import list_values

        values = list_values("os")
        assert "*NIX" in values
        assert "Windows" in values

    def test_list_values_software(self) -> None:
        from panoptic.cases import list_values

        values = list_values("software")
        assert "PHP" in values
        assert "nginx" in values

    def test_list_values_unknown_group(self) -> None:
        from panoptic.cases import list_values

        values = list_values("nonexistent")
        assert values == set()

    def test_list_all_files(self) -> None:
        from panoptic.cases import list_all_files

        files = list_all_files()
        assert len(files) > 0
        assert all(isinstance(f, str) for f in files)


class TestCsvValidationErrors:
    """Negative-path tests for CSV validation."""

    def test_missing_column_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panoptic.cases import _load_csv

        monkeypatch.setattr(
            "panoptic.cases.load_data_file",
            lambda _: "path,os,software\n/etc/passwd,*NIX,PHP\n",
        )
        with pytest.raises(ValueError, match="missing required columns"):
            _load_csv()

    def test_empty_field_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panoptic.cases import _load_csv

        monkeypatch.setattr(
            "panoptic.cases.load_data_file",
            lambda _: "path,os,software,category,type\n/etc/passwd,,PHP,Programming,conf\n",
        )
        with pytest.raises(ValueError, match="empty 'os' field"):
            _load_csv()

    def test_invalid_type_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panoptic.cases import _load_csv

        monkeypatch.setattr(
            "panoptic.cases.load_data_file",
            lambda _: "path,os,software,category,type\n/etc/passwd,*NIX,PHP,Programming,bogus\n",
        )
        with pytest.raises(ValueError, match="unknown type 'bogus'"):
            _load_csv()

    def test_empty_csv_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from panoptic.cases import _load_csv

        monkeypatch.setattr("panoptic.cases.load_data_file", lambda _: "")
        with pytest.raises(ValueError, match="missing required columns"):
            _load_csv()
