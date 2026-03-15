"""Output formatters for Panoptic scan results.

Supports text (rich), JSON, and CSV output formats.
"""

from __future__ import annotations

import csv
import json
import sys
from typing import TextIO

from rich.console import Console

from panoptic.models import ScanResult
from panoptic.utils import redact_url


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


def _result_to_dict(r: ScanResult) -> dict[str, object]:
    """Convert a ScanResult to a flat dict for serialization."""
    return {
        "timestamp": r.timestamp,
        "url": redact_url(r.url) if r.url.startswith(("http://", "https://")) else r.url,
        "location": r.case.location,
        "os": r.case.os,
        "category": r.case.category,
        "software": r.case.software,
        "type": r.case.file_type.value if r.case.file_type else None,
        "found": r.found,
        "status_code": r.status_code,
        "content_length": r.content_length,
    }


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

    def write_banner(self, version: str, url: str) -> None:
        if self._quiet:
            return
        self._console.print(
            f"[bold cyan] .-',--.`-.[/]\n"
            f"[bold cyan]<_ | () | _>[/]\n"
            f"[bold cyan]  `-`=='-'[/]\n"
            f"\n[bold]Panoptic {version}[/] ({url})\n"
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
        self._console.print(f"[bold green][+][/bold green] Found '{case.location}'{context}")

    def write_verbose(self, message: str) -> None:
        if self._quiet:
            return
        self._console.print(f"[dim][*] {message}[/dim]")

    def write_summary(self, results: list[ScanResult], total_cases: int) -> None:
        if self._quiet:
            return
        found = [r for r in results if r.found]
        self._console.print("\n[bold]Scan Complete[/bold]")
        self._console.print(f"  Cases tested: {total_cases}")
        self._console.print(f"  Files found:  [green]{len(found)}[/green]")
        if found:
            self._console.print("\n[bold]Found files:[/bold]")
            for r in found:
                self.write_found(r)


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

    def write_results(self, results: list[ScanResult]) -> None:
        writer = csv.DictWriter(self._stream, fieldnames=self.FIELDS)
        writer.writeheader()
        for r in results:
            writer.writerow(_result_to_dict(r))
