"""Lint checks for the bundled data files (cases.csv, versions.ini, agents.txt)."""

import csv
from collections import Counter

import pytest

from panoptic.cases import _expand_os_values, load_versions, parse_cases
from panoptic.models import ScanConfig
from panoptic.utils import load_data_file

ALLOWED_CATEGORIES = frozenset(
    {
        "API Gateway",
        "Antivirus",
        "Authentication",
        "Backup Systems",
        "CDN",
        "CI/CD",
        "Cloud Infrastructure",
        "Containerization",
        "Databases",
        "Desktop applications",
        "Development",
        "Email",
        "FTP",
        "Firewalls",
        "Infrastructure as Code",
        "IoT",
        "LDAP",
        "Logging",
        "Message Brokers",
        "Monitoring",
        "Network",
        "Packaged Web Dev",
        "Printing",
        "Programming",
        "Secret Management",
        "Service Mesh",
        "System Files",
        "VPN",
        "Versioning",
        "Virtualization",
        "Web Hosting Administration",
        "Web Servers",
        "Win NT",
    }
)

ALLOWED_OS = frozenset(
    {
        "*NIX",
        "AIX",
        "Crux Linux",
        "DragonFly BSD",
        "FreeBSD",
        "NetBSD",
        "OS X",
        "OpenBSD",
        "Slackware",
        "SunOS",
        "Windows",
    }
)


@pytest.fixture(scope="module")
def rows() -> list[dict[str, str]]:
    return list(csv.DictReader(load_data_file("cases.csv").splitlines()))


def _duplicates(values: list[str]) -> list[str]:
    return sorted(value for value, count in Counter(values).items() if count > 1)


class TestCasesCsv:
    def test_no_duplicate_paths(self, rows: list[dict[str, str]]) -> None:
        assert _duplicates([row["path"] for row in rows]) == []

    def test_no_directory_paths(self, rows: list[dict[str, str]]) -> None:
        assert [row["path"] for row in rows if row["path"].endswith(("/", "\\"))] == []

    def test_windows_rows_do_not_use_unix_paths(self, rows: list[dict[str, str]]) -> None:
        offenders = [
            row["path"]
            for row in rows
            if _expand_os_values(row["os"]) == ("Windows",) and row["path"].lower().startswith("/etc/")
        ]
        assert offenders == []

    def test_categories_are_controlled(self, rows: list[dict[str, str]]) -> None:
        assert {row["category"] for row in rows} - ALLOWED_CATEGORIES == set()

    def test_os_values_are_controlled(self, rows: list[dict[str, str]]) -> None:
        os_values = {os_value for row in rows for os_value in _expand_os_values(row["os"])}
        assert os_values - ALLOWED_OS == set()

    def test_no_duplicate_case_ids_with_all_versions(self) -> None:
        cases = parse_cases(ScanConfig(url="http://example.com", all_versions=True))
        assert _duplicates([case.case_id for case in cases]) == []
        assert _duplicates([case.location for case in cases]) == []


class TestVersionsIni:
    def test_no_duplicate_versions(self) -> None:
        for section, versions in load_versions().items():
            assert _duplicates(versions) == [], f"duplicate versions in [{section}]"

    def test_no_duplicate_sections(self) -> None:
        sections = [line.strip() for line in load_data_file("versions.ini").splitlines() if line.startswith("[")]
        assert _duplicates(sections) == []


class TestAgentsTxt:
    def test_no_duplicates_or_blank_lines(self) -> None:
        lines = load_data_file("agents.txt").splitlines()
        assert lines
        assert [line for line in lines if not line.strip()] == []
        assert _duplicates(lines) == []
