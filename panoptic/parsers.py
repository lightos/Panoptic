"""Post-discovery content parsers for Panoptic.

Extracts additional scan targets from discovered files
(e.g., users from /etc/passwd, binlog files from mysql-bin.index).
"""

from __future__ import annotations

import re

from panoptic.models import Case, FileType
from panoptic.utils import load_data_file


def extract_home_file_cases(
    passwd_content: str,
    parent_case: Case,
) -> list[Case]:
    """Extract home directory file cases from /etc/passwd content.

    Parses passwd entries to find user home directories, then generates
    cases for common dotfiles in each home directory.
    """
    if not passwd_content:
        return []

    home_files = _load_home_files()
    cases: list[Case] = []

    pattern = re.compile(
        r"(?P<username>[^:\n]+):"
        r"(?P<password>[^:]*):"
        r"(?P<uid>\d+):"
        r"(?P<gid>\d*):"
        r"(?P<info>[^:]*):"
        r"(?P<home>[^:]+):"
        r"[/a-z]*"
    )

    for match in pattern.finditer(passwd_content):
        home = match.group("home")

        # Skip users with root (/) as home — would scan entire filesystem
        if home == "/":
            continue

        for dotfile in home_files:
            cases.append(
                Case(
                    location=f"{home}/{dotfile}",
                    os=parent_case.os,
                    category="*NIX User File",
                    software="*NIX",
                    file_type=FileType.CONF,
                )
            )

    return cases


def extract_binlog_cases(
    index_content: str,
    parent_case: Case,
) -> list[Case]:
    """Extract MySQL binary log file cases from mysql-bin.index content.

    Parses the index file to find individual binlog filenames and generates
    cases using the same directory as the index file.

    Entries in the index file have the form '.\\mysql-bin.000001' where
    '.\\' is a dot-backslash prefix.
    """
    if not index_content:
        return []

    # Match entries like '.\mysql-bin.000001' (dot then backslash prefix).
    # Using a non-raw string so '\\\\' represents a literal backslash in the regex,
    # matching the single backslash in the index file content.
    binlogs = re.findall("\\.\\\\(?P<binlog>mysql-bin\\.\\d{1,6})", index_content)

    # Extract directory from parent case location
    last_slash = parent_case.location.rfind("/")
    directory = parent_case.location[: last_slash + 1] if last_slash >= 0 else ""

    return [
        Case(
            location=f"{directory}{binlog}",
            os=parent_case.os,
            category="Databases",
            software="MySQL",
            file_type=FileType.LOG,
        )
        for binlog in binlogs
    ]


def _load_home_files() -> list[str]:
    """Load common home directory files from bundled data."""
    content = load_data_file("home.txt")
    return [line.strip() for line in content.splitlines() if line.strip()]
