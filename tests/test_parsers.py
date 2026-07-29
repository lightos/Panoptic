"""Tests for panoptic.parsers — passwd and binlog extraction."""

from panoptic.models import Case
from panoptic.parsers import extract_binlog_cases, extract_home_file_cases


class TestExtractHomeFileCases:
    def test_extracts_users_with_home_dirs(self, sample_passwd: str) -> None:
        parent_case = Case(location="/etc/passwd", os="*NIX")
        cases = extract_home_file_cases(sample_passwd, parent_case)
        assert len(cases) > 0

        # Should find entries for user with /home/user
        home_locations = [c.location for c in cases]
        assert any("/home/user/" in loc for loc in home_locations)

    def test_skips_root_home(self, sample_passwd: str) -> None:
        """Users with home=/ should be skipped (would scan entire filesystem)."""
        passwd = "nobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n"
        parent_case = Case(location="/etc/passwd", os="*NIX")
        cases = extract_home_file_cases(passwd, parent_case)
        assert not any(c.location.startswith("//") for c in cases)

    def test_includes_common_dotfiles(self, sample_passwd: str) -> None:
        parent_case = Case(location="/etc/passwd", os="*NIX")
        cases = extract_home_file_cases(sample_passwd, parent_case)
        locations = [c.location for c in cases]
        assert any(".bashrc" in loc for loc in locations)
        assert any(".ssh/" in loc for loc in locations)

    def test_inherits_os_from_parent(self, sample_passwd: str) -> None:
        parent_case = Case(location="/etc/passwd", os="*NIX")
        cases = extract_home_file_cases(sample_passwd, parent_case)
        assert all(c.os == "*NIX" for c in cases)

    def test_empty_passwd_returns_empty(self) -> None:
        parent_case = Case(location="/etc/passwd", os="*NIX")
        assert extract_home_file_cases("", parent_case) == []


class TestExtractBinlogCases:
    def test_extracts_binlog_files(self) -> None:
        content = ".\\mysql-bin.000001\n.\\mysql-bin.000002\n.\\mysql-bin.000003\n"
        parent_case = Case(
            location="/var/lib/mysql/mysql-bin.index",
            os="*NIX",
            software="MySQL",
        )
        cases = extract_binlog_cases(content, parent_case)
        assert len(cases) == 3
        assert cases[0].location.endswith("mysql-bin.000001")

    def test_preserves_directory(self) -> None:
        content = ".\\mysql-bin.000001\n"
        parent_case = Case(
            location="/var/lib/mysql/mysql-bin.index",
            os="*NIX",
            software="MySQL",
        )
        cases = extract_binlog_cases(content, parent_case)
        assert cases[0].location.startswith("/var/lib/mysql/")

    def test_extracts_unix_and_modern_binlog_entries(self) -> None:
        content = "./mysql-bin.000001\n./binlog.000002\n/absolute/binlog.000003\n"
        parent_case = Case(location="/var/lib/mysql/mysql-bin.index", os="*NIX")
        cases = extract_binlog_cases(content, parent_case)
        assert [case.location for case in cases] == [
            "/var/lib/mysql/mysql-bin.000001",
            "/var/lib/mysql/binlog.000002",
        ]

    def test_empty_content_returns_empty(self) -> None:
        parent_case = Case(location="/var/lib/mysql/mysql-bin.index")
        assert extract_binlog_cases("", parent_case) == []
