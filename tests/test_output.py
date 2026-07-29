"""Tests for panoptic.output — text, JSON, CSV formatters."""

import csv
import io
import json

import pytest

from panoptic.models import Case, FileType, ScanConfig, ScanResult
from panoptic.output import CsvFormatter, JsonFormatter, TextFormatter, _scan_mode_label


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

    def test_json_array_body_is_redacted(self) -> None:
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url='[{"file":"/etc/passwd","token":"supersecret"}]',
            status_code=200,
        )
        buf = io.StringIO()
        JsonFormatter(buf).write_results([result])
        data = json.loads(buf.getvalue())
        assert "supersecret" not in data[0]["url"]
        assert "***" in data[0]["url"]

    def test_json_numeric_and_bool_scalars_are_redacted(self) -> None:
        """Non-string JSON leaves (a numeric PIN, a boolean flag) must not leak."""
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url='{"file":"/etc/passwd","pin":90210,"admin":true}',
            status_code=200,
        )
        buf = io.StringIO()
        JsonFormatter(buf).write_results([result])
        redacted = json.loads(buf.getvalue())[0]["url"]
        assert "90210" not in redacted
        assert "true" not in redacted
        # Keys are preserved for context, values are not.
        assert '"pin"' in redacted and '"admin"' in redacted

    def test_top_level_scalar_json_body_is_redacted(self) -> None:
        """A bare scalar body (e.g. --data '31337') must not be echoed verbatim."""
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="31337",
            status_code=200,
        )
        buf = io.StringIO()
        JsonFormatter(buf).write_results([result])
        assert json.loads(buf.getvalue())[0]["url"] == "***"

    def test_opaque_body_without_structure_is_fully_redacted(self) -> None:
        """A non-URL, non-JSON, non-form body (a raw token) is redacted entirely."""
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="raw-session-token-abc123",
            status_code=200,
        )
        buf = io.StringIO()
        JsonFormatter(buf).write_results([result])
        assert json.loads(buf.getvalue())[0]["url"] == "***"

    def test_form_body_keeps_keys_redacts_values(self) -> None:
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="file=/etc/passwd&token=secret123",
            status_code=200,
        )
        buf = io.StringIO()
        JsonFormatter(buf).write_results([result])
        redacted = json.loads(buf.getvalue())[0]["url"]
        assert "secret123" not in redacted
        assert redacted == "file=***&token=***"

    def test_uppercase_url_scheme_is_still_redacted(self) -> None:
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="HTTPS://user:secret@example.com/path?token=secret123",
            status_code=200,
        )
        buf = io.StringIO()
        JsonFormatter(buf).write_results([result])
        redacted = json.loads(buf.getvalue())[0]["url"]
        assert "secret" not in redacted
        assert redacted == "https://example.com/path?token=***" or redacted == "HTTPS://example.com/path?token=***"

    def test_bare_form_segment_is_redacted(self) -> None:
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="file=/etc/passwd&bare-secret-token",
            status_code=200,
        )
        buf = io.StringIO()
        JsonFormatter(buf).write_results([result])
        assert json.loads(buf.getvalue())[0]["url"] == "file=***&***"


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

    def test_file_results_include_discovered_paths(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf)
        formatter.write_results(sample_results, total_cases=100)
        output = buf.getvalue()
        assert "/etc/passwd" in output
        assert "/var/log/syslog" in output

    def test_file_results_do_not_hard_wrap_long_paths(self) -> None:
        location = f"/var/lib/{'very-long-directory/' * 8}configuration.conf"
        result = ScanResult(
            case=Case(location=location),
            found=True,
            url=f"http://example.com/?file={location}",
            status_code=200,
            content_length=123,
        )
        buf = io.StringIO()
        TextFormatter(buf).write_results([result], total_cases=1)
        assert location in buf.getvalue()

    def test_fuzz_in_header_name_is_not_reported_as_injection_mode(self) -> None:
        config = ScanConfig(
            url="http://example.com/?file=x",
            headers=["X-FUZZ-Label: fixed"],
        )
        assert _scan_mode_label(config) == "GET"

    def test_fuzz_in_header_value_is_reported_as_injection_mode(self) -> None:
        config = ScanConfig(
            url="http://example.com/",
            headers=["X-File: FUZZ"],
        )
        assert _scan_mode_label(config) == "FUZZ"


class TestQuietMode:
    def test_quiet_suppresses_banner(self) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        formatter.write_banner("1.0", "http://example.com")
        buf.seek(0)
        assert buf.read() == ""

    def test_quiet_suppresses_info(self) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        formatter.write_info("Starting scan")
        buf.seek(0)
        assert buf.read() == ""

    def test_quiet_suppresses_summary(self) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        formatter.write_summary([], 100)
        buf.seek(0)
        assert buf.read() == ""

    def test_quiet_shows_found(self) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="http://example.com/test.php?file=/etc/passwd",
            status_code=200,
        )
        formatter.write_found(result)
        buf.seek(0)
        assert "/etc/passwd" in buf.read()

    def test_quiet_shows_warning(self) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        formatter.write_warning("SSL disabled")
        buf.seek(0)
        assert "SSL disabled" in buf.read()


class TestMarkupEscaping:
    """Untrusted content (URLs, case locations, config values) must not inject Rich markup."""

    def test_warning_escapes_markup(self) -> None:
        buf = io.StringIO()
        TextFormatter(buf).write_warning("Case '/etc/[red]passwd[/red]' failed")
        assert "[red]passwd[/red]" in buf.getvalue()

    def test_info_escapes_markup(self) -> None:
        buf = io.StringIO()
        TextFormatter(buf).write_info("Using random User-Agent: [bold]evil[/bold]")
        assert "[bold]evil[/bold]" in buf.getvalue()

    def test_verbose_escapes_markup(self) -> None:
        buf = io.StringIO()
        TextFormatter(buf).write_verbose("Trying '[green]/etc/passwd[/green]'")
        assert "[green]/etc/passwd[/green]" in buf.getvalue()

    def test_banner_escapes_markup_in_url(self) -> None:
        buf = io.StringIO()
        # An injected style tag in the (redacted) URL must render literally, not
        # be interpreted — an unescaped invalid tag would also raise at print time.
        TextFormatter(buf).write_banner("1.0", "http://host/[red]x[/red]")
        assert "[red]x[/red]" in buf.getvalue()
