"""XML case parsing, filtering, version expansion, and custom list loading."""

from __future__ import annotations

import os
import re
from typing import Any
from urllib.parse import urlsplit
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

from panoptic.models import Case, FileType, ScanConfig
from panoptic.utils import load_data_file


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
            section = line.strip("[]")
        elif line and section is not None:
            versions.setdefault(section, []).append(line)

    return versions


def parse_cases(config: ScanConfig) -> list[Case]:
    """Parse cases.xml and return test cases filtered by config.

    Uses defusedxml for XML bomb protection.
    Builds a filtered list instead of mutating the tree in-place.
    """
    xml_content = load_data_file("cases.xml")
    root = ET.fromstring(xml_content)

    # Build parent map for ancestor lookups
    parent_map: dict[Any, Any] = {}
    for parent in root.iter():
        for child in parent:
            parent_map[child] = parent

    # Build replacements dict for placeholder expansion
    replacements: dict[str, str] = {}
    if config.url:
        replacements["HOST"] = urlsplit(config.url).netloc

    # Load versions for expansion
    versions = load_versions() if config.all_versions else {}

    cases: list[Case] = []

    for file_elem in root.iter("file"):
        location = file_elem.get("value", "")
        if not location:
            continue

        # Walk ancestors to find os, software, category, type
        os_val = _find_ancestor_attr(file_elem, "os", parent_map)
        software_val = _find_ancestor_attr(file_elem, "software", parent_map)
        category_val = _find_ancestor_attr(file_elem, "category", parent_map)
        file_type = _determine_file_type(file_elem, parent_map)

        # Apply filters
        if config.os_filter and os_val and os_val.lower() != config.os_filter.lower():
            continue
        if config.software_filter and software_val and software_val.lower() != config.software_filter.lower():
            continue
        if config.category_filter and category_val and category_val.lower() != config.category_filter.lower():
            continue
        if config.type_filter and file_type and file_type.value != config.type_filter.lower():
            continue

        # Placeholder expansion ({HOST}, etc.)
        for variable in re.findall(r"\{[^}]+\}", location):
            key = variable.strip("{}")
            if key in replacements:
                location = location.replace(variable, replacements[key])

        # Version expansion ([SECTION] patterns)
        match = re.search(r"\[([^\]]+)\]", location)
        if match and config.all_versions and match.group(1) in versions:
            for version in versions[match.group(1)]:
                expanded = location.replace(match.group(0), version)
                cases.append(
                    Case(
                        location=expanded,
                        os=os_val,
                        category=category_val,
                        software=software_val,
                        file_type=file_type,
                    )
                )
        else:
            cases.append(
                Case(
                    location=location,
                    os=os_val,
                    category=category_val,
                    software=software_val,
                    file_type=file_type,
                )
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
    if config is not None:
        # Parse cases with current filters applied, then extract unique values
        cases = parse_cases(config)
        values: set[str] = set()
        for case in cases:
            val = getattr(case, group, None)
            if val:
                values.add(val)
        return values

    # No config — return all values globally
    xml_content = load_data_file("cases.xml")
    root = ET.fromstring(xml_content)

    all_values: set[str] = set()
    for elem in root.iter(group):
        val_attr = elem.get("value")
        if val_attr:
            all_values.add(val_attr)

    return all_values


def list_all_files() -> list[str]:
    """List all file paths in cases.xml.

    Used by --list-all-files command.
    """
    xml_content = load_data_file("cases.xml")
    root = ET.fromstring(xml_content)

    return [elem.get("value", "") for elem in root.iter("file") if elem.get("value")]


def _find_ancestor_attr(
    element: Element,
    tag: str,
    parent_map: dict[Any, Any],
) -> str | None:
    """Walk up the parent chain to find the nearest ancestor with the given tag."""
    current = element
    while current in parent_map:
        parent = parent_map[current]
        if parent.tag == tag:
            result: str | None = parent.get("value")
            return result
        current = parent
    return None


def _determine_file_type(
    element: Element,
    parent_map: dict[Any, Any],
) -> FileType | None:
    """Determine the file type (conf/log/other) from ancestor tags."""
    current = element
    while current in parent_map:
        parent = parent_map[current]
        match parent.tag:
            case "conf":
                return FileType.CONF
            case "log":
                return FileType.LOG
            case "other":
                return FileType.OTHER
        current = parent
    return None
