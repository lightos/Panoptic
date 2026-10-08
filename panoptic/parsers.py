"""Post-discovery content parsers for Panoptic.

Extracts additional scan targets from discovered files
(e.g., users from /etc/passwd, binlog files from mysql-bin.index).
"""

from __future__ import annotations

import functools
import re

from panoptic.models import Case, FileType
from panoptic.utils import CONTROL_CHARS_RE, load_data_file


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
    seen_homes: set[str] = set()

    for home in _iter_passwd_homes(passwd_content):
        if home in seen_homes:
            continue
        seen_homes.add(home)

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


_PASSWD_LINE_RE = re.compile(
    r"^(?P<username>[^:\r\n]+):"
    r"(?P<password>[^:\r\n]*):"
    r"(?P<uid>\d+):"
    r"(?P<gid>\d*):"
    r"(?P<info>[^:\r\n]*):"
    r"(?P<home>[^:\r\n]+):"
    r"(?P<shell>[^:\r\n]*)$"
)


def _iter_passwd_homes(passwd_content: str) -> list[str]:
    """Return validated absolute home directories, one passwd entry per line.

    Entries never span lines; homes must be absolute, free of control
    characters and ``..`` segments, and not the filesystem root.
    """
    homes: list[str] = []
    for line in passwd_content.splitlines():
        match = _PASSWD_LINE_RE.match(line)
        if not match:
            continue
        home = match.group("home")
        if not home.startswith("/") or CONTROL_CHARS_RE.search(home):
            continue
        if ".." in home.split("/"):
            continue
        home = home.rstrip("/")
        # Skip users with root (/) as home — would scan entire filesystem
        if not home:
            continue
        homes.append(home)
    return homes


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

    # Support Windows and Unix relative entries plus the modern MySQL 8
    # default "binlog" basename.
    binlogs = re.findall(
        r"(?:^|[\r\n])(?:\.[\\/])?(?P<binlog>(?:mysql-bin|binlog)\.\d{1,9})(?:\r?$)",
        index_content,
        flags=re.MULTILINE,
    )

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


@functools.cache
def _load_home_files() -> tuple[str, ...]:
    """Load common home directory files from bundled data (cached)."""
    content = load_data_file("home.txt")
    return tuple(line.strip() for line in content.splitlines() if line.strip())
