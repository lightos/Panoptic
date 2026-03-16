"""Output formatters for Panoptic scan results.

Supports text (rich), JSON, and CSV output formats.
"""

from __future__ import annotations

import csv
import json
import sys
from typing import TextIO

from rich.console import Console
from rich.markup import escape as rich_escape

from panoptic.models import ScanConfig, ScanResult
from panoptic.utils import _PARAM_VALUE_RE, redact_url


class TeeWriter:
    """Write to two streams simultaneously (e.g., stderr + log file)."""

    def __init__(self, primary: TextIO, secondary: TextIO) -> None:
        self.primary = primary
        self.secondary = secondary

    def write(self, data: str) -> int:
        self.primary.write(data)
        return self.secondary.write(data)

    def flush(self) -> None:
        self.primary.flush()
        self.secondary.flush()

    def fileno(self) -> int:
        return self.primary.fileno()


def _redact_json_values(obj: object) -> object:
    """Recursively replace all string values in a JSON structure with '***'."""
    if isinstance(obj, dict):
        return {k: _redact_json_values(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_json_values(v) for v in obj]
    if isinstance(obj, str):
        return "***"
    return obj


def _redact_field(url: str) -> str:
    """Redact a URL or POST body for safe serialization."""
    if url.startswith(("http://", "https://")):
        return redact_url(url)
    # JSON body: redact all string values by parsing then recursively replacing
    if url.lstrip().startswith("{"):
        try:
            obj = json.loads(url)
            return json.dumps(_redact_json_values(obj))
        except (json.JSONDecodeError, ValueError):
            pass
    # POST body: redact form-encoded values (key=VALUE → key=***)
    return _PARAM_VALUE_RE.sub("***", url)


def _result_to_dict(r: ScanResult) -> dict[str, object]:
    """Convert a ScanResult to a flat dict for serialization."""
    return {
        "timestamp": r.timestamp,
        "url": _redact_field(r.url),
        "location": r.case.location,
        "os": r.case.os,
        "category": r.case.category,
        "software": r.case.software,
        "type": r.case.file_type.value if r.case.file_type else None,
        "found": r.found,
        "status_code": r.status_code,
        "content_length": r.content_length,
    }


_FUZZ_MARKER = "FUZZ"


def _has_fuzz(config: ScanConfig) -> bool:
    """Check if FUZZ marker is present in data or headers."""
    if config.data and _FUZZ_MARKER in config.data:
        return True
    if config.headers:
        return any(_FUZZ_MARKER in h for h in config.headers)
    return False


def _scan_mode_pupil(config: ScanConfig | None) -> str:
    """Return a contextual eye pupil based on scan mode."""
    if config is None:
        return "()"
    if _has_fuzz(config):
        return "><"
    if config.path_based:
        return "//"
    if config.base64_encode:
        return "=="
    if config.data:
        return "{}"
    return "()"


def _scan_mode_label(config: ScanConfig | None) -> str:
    """Return a short label describing the scan mode."""
    if config is None:
        return ""
    if _has_fuzz(config):
        return "FUZZ"
    if config.path_based:
        return "path-based"
    if config.base64_encode:
        return "base64"
    if config.data:
        return "POST"
    return "GET"


class TextFormatter:
    """Rich-powered text output for terminal display."""

    def __init__(
        self,
        stream: TextIO | None = None,
        console: Console | None = None,
        quiet: bool = False,
    ) -> None:
        self._console = console or Console(file=stream or sys.stderr, highlight=False)
        self._quiet = quiet

    def write_banner(
        self,
        version: str,
        url: str,
        config: ScanConfig | None = None,
    ) -> None:
        if self._quiet:
            return
        pupil = _scan_mode_pupil(config) if config else "()"
        mode = _scan_mode_label(config) if config else ""
        mode_str = f" [dim]·[/dim] [cyan]{mode}[/cyan]" if mode else ""
        self._console.print(
            f"[bold cyan] .-',--.`-.[/]   [bold]Panoptic[/] {version}\n"
            f"[bold cyan]<_ | {pupil} | _>[/]   [dim]{url}[/dim]\n"
            f"[bold cyan]  `-`=='-'[/]  {mode_str}\n"
        )

    def write_info(self, message: str) -> None:
        if self._quiet:
            return
        self._console.print(f"[blue][i][/blue] {message}")

    def write_warning(self, message: str) -> None:
        self._console.print(f"[red][!][/red] {message}")

    def write_found(self, result: ScanResult) -> None:
        case = result.case
        file_type_str = case.file_type.value if case.file_type else None
        parts = [p for p in (case.os, case.category, case.software, file_type_str) if p]
        context = f" ({'/'.join(parts)})" if parts else ""
        self._console.print(f"[bold green][+][/bold green] Found '{rich_escape(case.location)}'{rich_escape(context)}")

    def write_verbose(self, message: str) -> None:
        if self._quiet:
            return
        self._console.print(f"[dim][*] {message}[/dim]")

    def write_summary(self, found: list[ScanResult], total_cases: int) -> None:
        if self._quiet:
            return
        self._console.print("\n[bold]Scan Complete[/bold]")
        self._console.print(f"  Cases tested: {total_cases}")
        self._console.print(f"  Files found:  [green]{len(found)}[/green]")


class JsonFormatter:
    """JSON output for pipeline integration."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout

    def write_results(self, results: list[ScanResult]) -> None:
        data = [_result_to_dict(r) for r in results]
        json.dump(data, self._stream, indent=2)
        self._stream.write("\n")


class CsvFormatter:
    """CSV output for spreadsheet/report workflows."""

    FIELDS = [
        "timestamp",
        "url",
        "location",
        "os",
        "category",
        "software",
        "type",
        "found",
        "status_code",
        "content_length",
    ]

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout

    @staticmethod
    def _sanitize_csv_value(value: object) -> object:
        """Neutralize spreadsheet formula injection in CSV cells.

        Values starting with =, +, -, or @ are prefixed with a single quote
        to prevent Excel/Sheets from interpreting them as formulas.
        """
        if isinstance(value, str) and value and value[0] in ("=", "+", "-", "@"):
            return f"'{value}"
        return value

    def write_results(self, results: list[ScanResult]) -> None:
        writer = csv.DictWriter(self._stream, fieldnames=self.FIELDS)
        writer.writeheader()
        for r in results:
            row = {k: self._sanitize_csv_value(v) for k, v in _result_to_dict(r).items()}
            writer.writerow(row)
