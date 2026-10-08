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
from panoptic.utils import escape_control_chars, redact_parameter_values, redact_url, validate_header


def _safe_text(value: object) -> str:
    """Neutralize terminal control sequences and Rich markup in untrusted text.

    Server- or user-controlled strings (target URLs, discovered paths, error
    messages) may embed ESC/CSI/OSC or other C0/C1 control characters that
    would drive the terminal or forge log lines. Control characters are shown
    as visible escapes (``\\x1b``); trailing newlines added by callers for
    spacing are preserved.
    """
    text = str(value)
    body = text.rstrip("\n")
    trailing = text[len(body) :]
    return rich_escape(escape_control_chars(body)) + trailing


class TeeWriter:
    """Write to two streams simultaneously (e.g., stderr + log file).

    Control characters other than newline and tab are escaped before reaching
    the secondary (log file) stream so a log viewed with ``cat``/``less -R``
    cannot replay terminal escape sequences.
    """

    def __init__(self, primary: TextIO, secondary: TextIO) -> None:
        self.primary = primary
        self.secondary = secondary

    def write(self, data: str) -> int:
        self.primary.write(data)
        self.secondary.write(escape_control_chars(data, keep="\n\t"))
        return len(data)

    def flush(self) -> None:
        self.primary.flush()
        self.secondary.flush()

    def fileno(self) -> int:
        return self.primary.fileno()


def _redact_json_values(obj: object) -> object:
    """Recursively redact every scalar leaf in a JSON structure.

    Strings, numbers, and booleans are all replaced with '***' — a credential
    can be a numeric PIN or a bare token just as easily as a string, so redacting
    only strings would leak scalar secrets. ``null`` is preserved because it
    carries no value and keeps the structure faithful.
    """
    if isinstance(obj, dict):
        return {k: _redact_json_values(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_json_values(v) for v in obj]
    if obj is None:
        return None
    return "***"


def _redact_field(url: str) -> str:
    """Redact a URL or POST body for safe serialization."""
    if url.lower().startswith(("http://", "https://")):
        return redact_url(url)
    # JSON body: redact every leaf value, preserving container structure and keys.
    try:
        obj = json.loads(url)
    except (json.JSONDecodeError, ValueError):
        pass
    else:
        if isinstance(obj, (dict, list)):
            return json.dumps(_redact_json_values(obj))
        # Bare JSON scalar (number, quoted string, bool, null): nothing structural
        # to keep, so redact the whole field.
        return "***"
    # Form-encoded body: redact values while keeping keys for context (key=VALUE → key=***).
    if "=" in url:
        return redact_parameter_values(url)
    # Opaque body with no recognizable structure (e.g. a raw token): redact entirely.
    return "***" if url else url


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
        for header in config.headers:
            try:
                _name, value = validate_header(header, warn_deprecated=False)
            except ValueError:
                continue
            if _FUZZ_MARKER in value:
                return True
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


def _format_size(size: int) -> str:
    """Format a byte count for display (e.g. 812 B, 1.2 KB, 3.4 MB)."""
    if size < 1024:
        return f"{size} B"
    if size < 1024 * 1024:
        return f"{size / 1024:.1f} KB"
    return f"{size / (1024 * 1024):.1f} MB"


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
        # The URL is attacker-influenced (target, redacted userinfo, IPv6 brackets)
        # and must be escaped so it cannot inject or break Rich markup.
        self._console.print(
            f"[bold cyan] .-',--.`-.[/]   [bold]Panoptic[/] {_safe_text(version)}\n"
            f"[bold cyan]<_ | {pupil} | _>[/]   [dim]{_safe_text(url)}[/dim]\n"
            f"[bold cyan]  `-`=='-'[/]  {mode_str}\n"
        )

    def write_info(self, message: str) -> None:
        if self._quiet:
            return
        self._console.print(f"[blue][i][/blue] {_safe_text(message)}")

    def write_warning(self, message: str) -> None:
        self._console.print(f"[red][!][/red] {_safe_text(message)}")

    def write_found(self, result: ScanResult) -> None:
        case = result.case
        file_type_str = case.file_type.value if case.file_type else None
        parts = [p for p in (case.os, case.category, case.software, file_type_str) if p]
        context = f" ({'/'.join(parts)})" if parts else ""
        details = [str(result.status_code)] if result.status_code is not None else []
        if result.content_length is not None:
            details.append(_format_size(result.content_length))
        response = f" [dim]\\[{', '.join(details)}][/dim]" if details else ""
        self._console.print(
            f"[bold green][+][/bold green] Found '{_safe_text(case.location)}'{response}{_safe_text(context)}"
        )

    def write_verbose(self, message: str) -> None:
        if self._quiet:
            return
        self._console.print(f"[dim][*] {_safe_text(message)}[/dim]")

    def write_summary(self, found: list[ScanResult], total_cases: int) -> None:
        if self._quiet:
            return
        self._console.print("\n[bold]Scan Complete[/bold]")
        self._console.print(f"  Cases tested: {total_cases}")
        self._console.print(f"  Files found:  [green]{len(found)}[/green]")

    def write_results(self, found: list[ScanResult], total_cases: int) -> None:
        """Write complete plain-text results for files and redirected output."""
        if self._quiet:
            return
        if found:
            self._console.print("[bold]Findings[/bold]")
            for result in found:
                status = result.status_code if result.status_code is not None else "-"
                length = result.content_length if result.content_length is not None else "-"
                self._console.print(
                    f"  {_safe_text(result.case.location)}  [dim](status={status}, length={length})[/dim]",
                    soft_wrap=True,
                )
        else:
            self._console.print("No files found.")
        self.write_summary(found, total_cases)


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

    _FORMULA_CHARS = frozenset("=+-@")
    _DANGEROUS_LEADING_CHARS = frozenset("=+-@\t\r\n|%")

    @classmethod
    def _sanitize_csv_value(cls, value: object) -> object:
        """Neutralize spreadsheet formula injection in CSV cells.

        Values starting with ``= + - @``, a tab/CR/LF, ``|`` (DDE) or ``%``,
        or with leading whitespace followed by a formula character, are
        prefixed with a single quote so Excel/Sheets/LibreOffice treat them
        as text instead of formulas.
        """
        if not isinstance(value, str) or not value:
            return value
        stripped = value.lstrip()
        if value[0] in cls._DANGEROUS_LEADING_CHARS or (stripped and stripped[0] in cls._FORMULA_CHARS):
            return f"'{value}"
        return value

    def write_results(self, results: list[ScanResult]) -> None:
        writer = csv.DictWriter(self._stream, fieldnames=self.FIELDS)
        writer.writeheader()
        for r in results:
            row = {k: self._sanitize_csv_value(v) for k, v in _result_to_dict(r).items()}
            writer.writerow(row)
