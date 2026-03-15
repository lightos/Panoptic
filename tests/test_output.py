"""Tests for panoptic.output — text, JSON, CSV formatters."""

import csv
import io
import json

import pytest

from panoptic.models import Case, FileType, ScanResult
from panoptic.output import CsvFormatter, JsonFormatter, TextFormatter


@pytest.fixture
def sample_results() -> list[ScanResult]:
    return [
        ScanResult(
            case=Case(location="/etc/passwd", os="*NIX", category="OS", software="Linux", file_type=FileType.CONF),
            found=True,
            url="http://example.com/?file=/etc/passwd",
            status_code=200,
            content_length=1234,
            timestamp="2026-03-14T10:00:00",
        ),
        ScanResult(
            case=Case(location="/var/log/syslog", os="*NIX", category="OS", software="Linux", file_type=FileType.LOG),
            found=True,
            url="http://example.com/?file=/var/log/syslog",
            status_code=200,
            content_length=5678,
            timestamp="2026-03-14T10:00:01",
        ),
    ]


class TestJsonFormatter:
    def test_output_is_valid_json(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = JsonFormatter(buf)
        formatter.write_results(sample_results)
        buf.seek(0)
        data = json.loads(buf.read())
        assert isinstance(data, list)
        assert len(data) == 2

    def test_fields_present(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = JsonFormatter(buf)
        formatter.write_results(sample_results)
        buf.seek(0)
        data = json.loads(buf.read())
        entry = data[0]
        assert entry["location"] == "/etc/passwd"
        assert entry["os"] == "*NIX"
        assert entry["found"] is True
        assert entry["status_code"] == 200

    def test_empty_results(self) -> None:
        buf = io.StringIO()
        formatter = JsonFormatter(buf)
        formatter.write_results([])
        buf.seek(0)
        assert json.loads(buf.read()) == []


class TestCsvFormatter:
    def test_output_is_valid_csv(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = CsvFormatter(buf)
        formatter.write_results(sample_results)
        buf.seek(0)
        reader = csv.DictReader(buf)
        rows = list(reader)
        assert len(rows) == 2

    def test_header_present(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = CsvFormatter(buf)
        formatter.write_results(sample_results)
        buf.seek(0)
        header = buf.readline()
        assert "location" in header
        assert "timestamp" in header

    def test_empty_results_has_header(self) -> None:
        buf = io.StringIO()
        formatter = CsvFormatter(buf)
        formatter.write_results([])
        buf.seek(0)
        content = buf.read()
        assert "location" in content  # Header still present


class TestUrlRedaction:
    def test_json_output_redacts_url(self) -> None:
        """JSON output must not leak raw query param values."""
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="http://example.com/test.php?file=/etc/passwd&token=secret123",
            status_code=200,
        )
        buf = io.StringIO()
        JsonFormatter(buf).write_results([result])
        buf.seek(0)
        data = json.loads(buf.read())
        assert "secret123" not in data[0]["url"]
        assert "token=***" in data[0]["url"]

    def test_csv_output_redacts_url(self) -> None:
        """CSV output must not leak raw query param values."""
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="http://example.com/test.php?file=/etc/passwd&token=secret123",
            status_code=200,
        )
        buf = io.StringIO()
        CsvFormatter(buf).write_results([result])
        buf.seek(0)
        content = buf.read()
        assert "secret123" not in content


class TestTextFormatter:
    def test_found_message(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf)
        formatter.write_found(sample_results[0])
        buf.seek(0)
        output = buf.read()
        assert "/etc/passwd" in output

    def test_summary(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf)
        formatter.write_summary(sample_results, total_cases=100)
        buf.seek(0)
        output = buf.read()
        assert "2" in output  # 2 found
