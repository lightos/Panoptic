"""Tests for panoptic.utils."""

import os
from pathlib import Path

import pytest

from panoptic.utils import (
    get_random_agent,
    load_data_file,
    normalize_os_name,
    open_secure_write,
    redact_url,
    sanitize_filename,
    validate_header,
    validate_url_scheme,
)

posix_only = pytest.mark.skipif(os.name != "posix", reason="requires POSIX file permissions/symlinks")


class TestValidateUrlScheme:
    def test_http_valid(self) -> None:
        validate_url_scheme("http://example.com/test.php?file=x")

    def test_https_valid(self) -> None:
        validate_url_scheme("https://example.com/test.php?file=x")

    def test_file_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Only http:// and https://"):
            validate_url_scheme("file:///etc/passwd")

    def test_ftp_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Only http:// and https://"):
            validate_url_scheme("ftp://internal/data")

    def test_no_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Only http:// and https://"):
            validate_url_scheme("example.com/test")

    def test_missing_hostname_rejected(self) -> None:
        with pytest.raises(ValueError, match="hostname"):
            validate_url_scheme("http:///path")


class TestNormalizeOsName:
    @pytest.mark.parametrize("value", ["OSX", "osx", "OsX", "OS X", "os x"])
    def test_os_x_aliases_are_case_insensitive(self, value: str) -> None:
        assert normalize_os_name(value) == "OS X"

    def test_unknown_os_preserves_display_name(self) -> None:
        assert normalize_os_name("  FreeBSD  ") == "FreeBSD"


class TestValidateHeader:
    def test_valid_header(self) -> None:
        name, value = validate_header("X-Forwarded-For: 127.0.0.1")
        assert name == "X-Forwarded-For"
        assert value == "127.0.0.1"

    def test_crlf_in_value_rejected(self) -> None:
        with pytest.raises(ValueError, match="CRLF"):
            validate_header("X-Foo: bar\r\nX-Injected: evil")

    def test_crlf_in_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="CRLF"):
            validate_header("X-Foo\r\n: bar")

    def test_no_colon_rejected(self) -> None:
        with pytest.raises(ValueError, match="colon"):
            validate_header("InvalidHeader")

    def test_value_with_equals(self) -> None:
        """Headers with = in value should work (e.g., auth tokens)."""
        name, value = validate_header("Authorization: Bearer abc=def")
        assert name == "Authorization"
        assert value == "Bearer abc=def"

    def test_invalid_header_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="header name"):
            validate_header("Bad Header: value")

    def test_nul_rejected(self) -> None:
        with pytest.raises(ValueError, match="NUL"):
            validate_header("X-Test: value\x00injected")

    def test_ipv6_redaction_preserves_brackets(self) -> None:
        assert redact_url("http://user:pass@[::1]:8080/path?token=x") == "http://[::1]:8080/path?token=***"


class TestSanitizeFilename:
    def test_slashes_replaced(self) -> None:
        assert "/" not in sanitize_filename("/etc/passwd")

    def test_traversal_neutralized(self) -> None:
        result = sanitize_filename("../../../etc/passwd")
        assert ".." not in result

    def test_colons_replaced(self) -> None:
        assert ":" not in sanitize_filename("C:\\Windows\\system.ini")


class TestLoadDataFile:
    def test_load_agents(self) -> None:
        content = load_data_file("agents.txt")
        assert len(content) > 0
        assert "Mozilla" in content

    def test_load_nonexistent_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_data_file("nonexistent.txt")


class TestGetRandomAgent:
    def test_returns_string(self) -> None:
        agent = get_random_agent()
        assert isinstance(agent, str)
        assert len(agent) > 0

    def test_returns_different_values(self) -> None:
        """Should return different agents with deterministic seed."""
        import random

        random.seed(42)
        agents = {get_random_agent() for _ in range(20)}
        assert len(agents) > 1


class TestOpenSecureWrite:
    def test_creates_file_with_content(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        with open_secure_write(str(target)) as fh:
            fh.write("hello")
        assert target.read_text(encoding="utf-8") == "hello"

    @posix_only
    def test_new_file_is_owner_only(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        with open_secure_write(str(target)) as fh:
            fh.write("x")
        assert os.stat(target).st_mode & 0o777 == 0o600

    @posix_only
    def test_tightens_permissions_on_existing_file(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        target.write_text("old", encoding="utf-8")
        os.chmod(target, 0o644)
        with open_secure_write(str(target)) as fh:
            fh.write("new")
        assert os.stat(target).st_mode & 0o777 == 0o600
        assert target.read_text(encoding="utf-8") == "new"

    def test_truncates_existing_content(self, tmp_path: Path) -> None:
        target = tmp_path / "out.txt"
        target.write_text("a very long previous value", encoding="utf-8")
        with open_secure_write(str(target)) as fh:
            fh.write("short")
        assert target.read_text(encoding="utf-8") == "short"

    def test_newline_is_not_translated(self, tmp_path: Path) -> None:
        target = tmp_path / "out.csv"
        with open_secure_write(str(target), newline="") as fh:
            fh.write("a,b\r\n")
        assert target.read_bytes() == b"a,b\r\n"

    @posix_only
    def test_refuses_to_follow_symlink(self, tmp_path: Path) -> None:
        """A pre-planted symlink at the target must not be written through."""
        secret = tmp_path / "secret.txt"
        secret.write_text("do-not-clobber", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(secret)
        with pytest.raises(OSError):
            open_secure_write(str(link))
        # The symlink target must be untouched.
        assert secret.read_text(encoding="utf-8") == "do-not-clobber"

    @posix_only
    def test_fallback_rejects_existing_symlink_without_nofollow(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Platforms lacking O_NOFOLLOW still reject an already-present symlink."""
        secret = tmp_path / "secret.txt"
        secret.write_text("do-not-clobber", encoding="utf-8")
        link = tmp_path / "link.txt"
        link.symlink_to(secret)
        monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
        with pytest.raises(OSError):
            open_secure_write(str(link))
        assert secret.read_text(encoding="utf-8") == "do-not-clobber"

    @posix_only
    def test_fchmod_failure_fails_closed_without_truncating(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """If permissions can't be enforced, fail closed and preserve prior content."""
        target = tmp_path / "out.txt"
        target.write_text("original content", encoding="utf-8")

        def boom(fd: int, mode: int) -> None:
            raise PermissionError("cannot chmod")

        monkeypatch.setattr(os, "fchmod", boom)
        with pytest.raises(OSError):
            open_secure_write(str(target))
        # The pre-existing content must not have been truncated.
        assert target.read_text(encoding="utf-8") == "original content"
