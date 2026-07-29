"""CSV case parsing, filtering, version expansion, and custom list loading."""

from __future__ import annotations

import csv
import os
import re
from urllib.parse import urlsplit

from panoptic.models import Case, FileType, ScanConfig
from panoptic.utils import load_data_file, normalize_os_name, normalize_os_names, os_matches_restriction

REQUIRED_COLUMNS = frozenset({"path", "os", "software", "category", "type"})
VALID_TYPES = frozenset(t.value for t in FileType)


def _expand_os_values(raw: str) -> tuple[str, ...]:
    """Expand comma-separated OS metadata and normalize known aliases."""
    return normalize_os_names(raw)


def _validate_csv(rows: list[dict[str, str]]) -> None:
    """Validate CSV data on first load. Raises ValueError on bad data."""
    for i, row in enumerate(rows, start=2):  # line 1 is header
        for col in REQUIRED_COLUMNS:
            if not row.get(col):
                raise ValueError(f"cases.csv line {i}: empty '{col}' field")
        if row["type"] not in VALID_TYPES:
            raise ValueError(f"cases.csv line {i}: unknown type '{row['type']}', expected one of {sorted(VALID_TYPES)}")


def _load_csv() -> list[dict[str, str]]:
    """Load and validate cases.csv. Returns list of row dicts."""
    content = load_data_file("cases.csv")
    reader = csv.DictReader(content.splitlines())
    if reader.fieldnames is None or not REQUIRED_COLUMNS.issubset(set(reader.fieldnames)):
        raise ValueError(f"cases.csv: missing required columns {sorted(REQUIRED_COLUMNS)}, got {reader.fieldnames}")
    rows = list(reader)
    _validate_csv(rows)
    return rows


def load_versions() -> dict[str, list[str]]:
    """Load version strings from versions.ini data file.

    Returns a dict mapping section names to lists of version strings.
    """
    content = load_data_file("versions.ini")
    versions: dict[str, list[str]] = {}
    section: str | None = None

    for line in content.splitlines():
        line = line.strip()
        if re.match(r"\[.+\]", line):
            section = line[1:-1]
        elif line and section is not None:
            versions.setdefault(section, []).append(line)

    return versions


def parse_cases(config: ScanConfig) -> list[Case]:
    """Parse cases.csv and return test cases filtered by config.

    Validates CSV structure on load. Applies OS/software/category/type filters.
    Expands {HOST} placeholders and [SECTION] version patterns.
    """
    rows = _load_csv()

    # Build replacements dict for placeholder expansion
    replacements: dict[str, str] = {}
    if config.url:
        hostname = urlsplit(config.url).hostname or ""
        replacements["HOST"] = hostname
        replacements["DOMAIN"] = hostname

    # Load versions for expansion
    versions = load_versions() if config.all_versions else {}

    cases: list[Case] = []

    for row in rows:
        os_values = _expand_os_values(row["os"])
        software_val = row["software"]
        category_val = row["category"]
        file_type = FileType(row["type"])
        location = row["path"]

        # Apply filters. The OS prefilter uses the same Unix-family hierarchy as
        # the runtime restriction (os_matches_restriction) so a "*NIX" filter
        # keeps FreeBSD/OS X/... cases and a specific Unix filter still keeps the
        # generic "*NIX" cases — otherwise the list would silently drop cases the
        # scan would actually test.
        normalized_filter = normalize_os_name(config.os_filter)
        if normalized_filter and not any(os_matches_restriction(os_val, normalized_filter) for os_val in os_values):
            continue
        if config.software_filter and software_val.lower() != config.software_filter.lower():
            continue
        if config.category_filter and category_val.lower() != config.category_filter.lower():
            continue
        if config.type_filter and file_type.value.lower() != config.type_filter.lower():
            continue

        # Placeholder expansion ({HOST}, etc.)
        for variable in re.findall(r"\{[^}]+\}", location):
            key = variable[1:-1]
            if key in replacements:
                location = location.replace(variable, replacements[key])

        # Version expansion ([SECTION] patterns)
        match = re.search(r"\[([^\]]+)\]", location)
        if match and config.all_versions:
            if match.group(1) not in versions:
                raise ValueError(f"cases.csv references unknown version section '{match.group(1)}'")
            locations = [location.replace(match.group(0), v) for v in versions[match.group(1)]]
        elif match:
            # Version templates are meaningful only when explicitly expanded.
            # Sending the raw "[SECTION]" path can never find a real file.
            continue
        else:
            locations = [location]
        # A comma-separated OS field describes one case compatible with any of
        # those systems; it must not fan out into duplicate requests.
        case_os = ", ".join(os_values)
        for loc in locations:
            cases.append(
                Case(location=loc, os=case_os, category=category_val, software=software_val, file_type=file_type)
            )

    return cases


def load_custom_list(filepath: str) -> list[Case]:
    """Load a custom file list from a user-provided path.

    Validates the file exists and is a regular file.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"List file not found: {filepath}")
    if not os.path.isfile(filepath):
        raise ValueError(f"Path is not a regular file: {filepath}")
    with open(filepath, encoding="utf-8") as f:
        return [Case(location=stripped) for line in f if (stripped := line.strip())]


def list_values(group: str, config: ScanConfig | None = None) -> set[str]:
    """List unique values for a given group (os, software, category).

    When config is provided, respects active filters (matching original behavior).
    Used by --list command.
    """
    if group not in {"os", "software", "category"}:
        return set()

    if config is not None:
        cases = parse_cases(config)
        if group == "os":
            return {os_value for case in cases for os_value in normalize_os_names(case.os)}
        return {getattr(c, group) for c in cases if getattr(c, group)}

    rows = _load_csv()
    if group == "os":
        return {os_val for row in rows for os_val in _expand_os_values(row[group])}
    return {row[group] for row in rows if row.get(group)}


def list_all_files() -> list[str]:
    """List all file paths in cases.csv.

    Used by --list-all-files command.
    """
    rows = _load_csv()
    return [row["path"] for row in rows]
