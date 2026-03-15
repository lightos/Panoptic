"""Tests for panoptic.models."""

import pytest

from panoptic.models import Case, FileType, OutputFormat, ScanConfig, ScanResult


class TestCase:
    def test_immutable(self) -> None:
        case = Case(location="/etc/passwd", os="*NIX")
        with pytest.raises(AttributeError):
            case.location = "/etc/shadow"  # type: ignore[misc]

    def test_hashable(self) -> None:
        case = Case(location="/etc/passwd", os="*NIX")
        hash(case)  # Should not raise

    def test_case_id_deterministic(self) -> None:
        """case_id must be stable across calls (not Python hash)."""
        case = Case(location="/etc/passwd", os="*NIX", category="OS", software="Linux")
        id1 = case.case_id
        id2 = case.case_id
        assert id1 == id2
        assert len(id1) == 16  # truncated SHA-256

    def test_case_id_different_for_different_cases(self) -> None:
        c1 = Case(location="/etc/passwd")
        c2 = Case(location="/etc/shadow")
        assert c1.case_id != c2.case_id

    def test_equality(self) -> None:
        c1 = Case(location="/etc/passwd", os="*NIX")
        c2 = Case(location="/etc/passwd", os="*NIX")
        assert c1 == c2


class TestScanResult:
    def test_timestamp_auto_set(self) -> None:
        case = Case(location="/etc/passwd")
        result = ScanResult(case=case, found=True, url="http://example.com")
        assert result.timestamp != ""

    def test_fields(self) -> None:
        case = Case(location="/etc/passwd")
        result = ScanResult(
            case=case,
            found=True,
            url="http://example.com",
            status_code=200,
            content="root:x:0:0",
            content_length=100,
        )
        assert result.found is True
        assert result.status_code == 200


class TestScanConfig:
    def test_defaults(self) -> None:
        config = ScanConfig(url="http://example.com")
        assert config.concurrency == 4
        assert config.timeout == 10.0
        assert config.retries == 3
        assert config.output_format == OutputFormat.TEXT
        assert config.heuristic_ratio == 0.9

    def test_prefix_not_mutated(self) -> None:
        """ScanConfig.prefix should never be mutated after creation."""
        config = ScanConfig(url="http://example.com", prefix="../")
        original = config.prefix
        _ = config.prefix + "/etc/passwd"
        assert config.prefix == original


class TestEnums:
    def test_file_type_values(self) -> None:
        assert FileType.CONF.value == "conf"
        assert FileType.LOG.value == "log"
        assert FileType.OTHER.value == "other"

    def test_output_format_values(self) -> None:
        assert OutputFormat.TEXT.value == "text"
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.CSV.value == "csv"
