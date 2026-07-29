"""Tests for panoptic.cases — CSV case parsing, validation, and filtering."""

from pathlib import Path

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

    def test_filter_by_os_nix_includes_unix_family(self) -> None:
        """A *NIX filter excludes Windows but keeps the whole Unix family."""
        config = ScanConfig(url="http://example.com", os_filter="*NIX")
        cases = parse_cases(config)
        os_values = {c.os for c in cases if c.os is not None}
        assert "Windows" not in os_values
        assert "*NIX" in os_values
        assert "FreeBSD" in os_values  # specific Unix OS retained under *NIX

    def test_filter_by_specific_unix_includes_generic_nix(self) -> None:
        """A specific Unix filter still includes the generic *NIX cases (matches runtime)."""
        config = ScanConfig(url="http://example.com", os_filter="FreeBSD")
        cases = parse_cases(config)
        os_values = {c.os for c in cases if c.os is not None}
        assert "FreeBSD" in os_values
        assert "*NIX" in os_values
        assert "Windows" not in os_values

    def test_filter_by_lowercase_os_alias_keeps_os_x_cases(self) -> None:
        config = ScanConfig(url="http://example.com", os_filter="osx")
        cases = parse_cases(config)
        os_values = {case.os for case in cases}
        assert "OS X" in os_values
        assert "*NIX" in os_values
        assert "Windows" not in os_values
        assert any(case.location == "/usr/local/mysql/data/mysql.log" for case in cases)

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

    def test_domain_placeholder_expansion(self) -> None:
        config = ScanConfig(url="http://target.example.com:8080/test.php?f=x")
        cases = parse_cases(config)
        domain_cases = [case for case in cases if "/var/log/lighttpd/target.example.com/" in case.location]
        assert len(domain_cases) == 2
        assert all("{" not in case.location for case in cases)

    def test_version_templates_are_skipped_unless_requested(self) -> None:
        default_cases = parse_cases(ScanConfig(url="http://example.com"))
        versioned_cases = parse_cases(ScanConfig(url="http://example.com", all_versions=True))
        assert all("[" not in case.location for case in default_cases)
        assert len(versioned_cases) > len(default_cases)
        assert any("JBoss-6.0.0.Final" in case.location for case in versioned_cases)

    def test_unknown_version_template_fails_fast(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            "panoptic.cases._load_csv",
            lambda: [
                {
                    "path": "/opt/[UNKNOWN]/config",
                    "os": "*NIX",
                    "software": "Example",
                    "category": "Other",
                    "type": "conf",
                }
            ],
        )
        monkeypatch.setattr("panoptic.cases.load_versions", lambda: {"KNOWN": ["1.0"]})
        with pytest.raises(ValueError, match="unknown version section 'UNKNOWN'"):
            parse_cases(ScanConfig(url="http://example.com", all_versions=True))


class TestLoadVersions:
    def test_returns_dict(self) -> None:
        versions = load_versions()
        assert isinstance(versions, dict)
        assert "JBOSS" in versions
        assert isinstance(versions["JBOSS"], list)
        assert len(versions["JBOSS"]) > 0


class TestLoadCustomList:
    def test_load_from_file(self, tmp_path: Path) -> None:
        listfile = tmp_path / "custom.txt"
        listfile.write_text("/etc/passwd\n/etc/shadow\n/var/log/syslog\n")
        cases = load_custom_list(str(listfile))
        assert len(cases) == 3
        assert cases[0].location == "/etc/passwd"

    def test_skips_empty_lines(self, tmp_path: Path) -> None:
        listfile = tmp_path / "custom.txt"
        listfile.write_text("/etc/passwd\n\n/etc/shadow\n\n")
        cases = load_custom_list(str(listfile))
        assert len(cases) == 2

    def test_nonexistent_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_custom_list("/nonexistent/path/list.txt")

    def test_directory_raises(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="regular file"):
            load_custom_list(str(tmp_path))


class TestCsvValidation:
    def test_parse_cases_returns_expected_count(self) -> None:
        """CSV parser returns expected number of cases."""
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        assert len(cases) == 958

    def test_composite_os_rows_emit_one_case_per_location(self) -> None:
        cases = parse_cases(ScanConfig(url="http://example.com"))
        locations = {
            "/usr/ports/ftp/pure-ftpd/pure-ftpd.conf",
            "/usr/ports/ftp/pure-ftpd/pureftpd.passwd",
            "/usr/ports/ftp/pure-ftpd/pureftpd.pdb",
        }
        composite_cases = [case for case in cases if case.location in locations]
        assert len(composite_cases) == len(locations)
        assert {case.location for case in composite_cases} == locations
        assert all(case.os == "DragonFly BSD, FreeBSD" for case in composite_cases)

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
        assert "OS X" in values
        assert "OSX" not in values
        assert "DragonFly BSD" in values
        assert "DragonflyBSD, FreeBSD" not in values

        filtered_values = list_values("os", ScanConfig(url="http://example.com"))
        assert "DragonFly BSD" in filtered_values
        assert "FreeBSD" in filtered_values
        assert "DragonFly BSD, FreeBSD" not in filtered_values

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
