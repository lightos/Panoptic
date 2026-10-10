"""Tests for panoptic.update — git self-update."""

import shlex
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from panoptic import update
from panoptic.update import (
    GIT_UPSTREAM_REF,
    _normalise_git_url,
    _reinstall_commands,
    _uses_secure_git_transport,
    do_update,
    get_revision,
)

HEAD_A = b"abc1234567890abcdef1234567890abcdef123456\n"
HEAD_B = b"def4567890abcdef1234567890abcdef12345678\n"
TRUSTED_REMOTE = b"git@github.com:lightos/Panoptic.git\n"


def _ok(stdout: bytes = b"") -> MagicMock:
    return MagicMock(returncode=0, stdout=stdout, stderr=b"")


class TestDoUpdate:
    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_git_checkout_runs_git_pull(self, mock_exists: Any, mock_run: Any) -> None:
        mock_run.side_effect = [
            _ok(TRUSTED_REMOTE),
            _ok(b"main\n"),
            _ok(HEAD_A),
            _ok(b"Already up to date.\n"),
            _ok(HEAD_A),
        ]
        assert do_update() == 0
        assert mock_run.call_count == 5
        # Should use list args, not shell=True
        pull_args = mock_run.call_args_list[3]
        assert pull_args[0][0] == ["git", "pull", "--ff-only", "origin", GIT_UPSTREAM_REF]

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_git_runs_with_c_locale_and_clean_git_env(
        self, mock_exists: Any, mock_run: Any, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("GIT_DIR", "/tmp/elsewhere/.git")
        monkeypatch.setenv("GIT_WORK_TREE", "/tmp/elsewhere")
        monkeypatch.setenv("LANG", "de_DE.UTF-8")
        mock_run.side_effect = [_ok(TRUSTED_REMOTE), _ok(b"main\n"), _ok(HEAD_A), _ok(), _ok(HEAD_A)]
        assert do_update() == 0
        for call in mock_run.call_args_list:
            env = call.kwargs["env"]
            assert env["LC_ALL"] == "C"
            assert "GIT_DIR" not in env
            assert "GIT_WORK_TREE" not in env
            assert call.kwargs.get("shell") is not True

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_already_up_to_date_uses_head_comparison(
        self, mock_exists: Any, mock_run: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        # Localized output without the word "Already" must still be detected.
        mock_run.side_effect = [
            _ok(TRUSTED_REMOTE),
            _ok(b"main\n"),
            _ok(HEAD_A),
            _ok(b"Bereits aktuell.\n"),
            _ok(HEAD_A),
        ]
        assert do_update() == 0
        out = capsys.readouterr().out
        assert "Already at the latest revision 'abc1234'" in out

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_updated_reports_new_revision(
        self, mock_exists: Any, mock_run: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_run.side_effect = [
            _ok(TRUSTED_REMOTE),
            _ok(b"main\n"),
            _ok(HEAD_A),
            _ok(b"Already something\n"),
            _ok(HEAD_B),
            _ok(),  # git diff --quiet: pyproject.toml unchanged
        ]
        assert do_update() == 0
        out = capsys.readouterr().out
        assert "Updated to revision 'def4567'" in out
        assert "Reinstall" not in out
        assert mock_run.call_args_list[5][0][0] == [
            "git",
            "diff",
            "--quiet",
            HEAD_A.decode().strip(),
            HEAD_B.decode().strip(),
            "--",
            "pyproject.toml",
        ]

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_update_with_changed_dependencies_prints_reinstall_command(
        self, mock_exists: Any, mock_run: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_run.side_effect = [
            _ok(TRUSTED_REMOTE),
            _ok(b"main\n"),
            _ok(HEAD_A),
            _ok(),
            _ok(HEAD_B),
            MagicMock(returncode=1, stdout=b"", stderr=b""),  # pyproject.toml changed
        ]
        assert do_update() == 0
        out = capsys.readouterr().out
        assert "Reinstall them with:" in out
        assert f"{shlex.quote(sys.executable)} -m pip install -e " in out

    def test_reinstall_command_quoting_per_shell(self) -> None:
        python = r"C:\Tools\R&D\O'Neil\.venv\Scripts\python.exe"
        checkout = r"C:\Tools\R&D\O'Neil"
        assert _reinstall_commands(python, checkout, windows=True) == [
            "& 'C:\\Tools\\R&D\\O''Neil\\.venv\\Scripts\\python.exe' -m pip install -e "
            "'C:\\Tools\\R&D\\O''Neil'   # PowerShell"
        ]
        assert _reinstall_commands("/home/a b/R&D/.venv/bin/python", "/home/a b/R&D", windows=False) == [
            "'/home/a b/R&D/.venv/bin/python' -m pip install -e '/home/a b/R&D'"
        ]

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_pull_failure_shows_git_stderr(
        self, mock_exists: Any, mock_run: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stderr = b"error: Your local changes to the following files would be overwritten by merge:\n\tREADME.md\n"
        mock_run.side_effect = [
            _ok(TRUSTED_REMOTE),
            _ok(b"main\n"),
            _ok(HEAD_A),
            MagicMock(returncode=1, stdout=b"", stderr=stderr),
        ]
        assert do_update() == 2
        out = capsys.readouterr().out
        assert "would be overwritten by merge" in out
        assert "uncommitted changes" in out
        assert "make sure 'git' is installed" not in out

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_pull_failure_redacts_credentials_in_stderr(
        self, mock_exists: Any, mock_run: Any, capsys: pytest.CaptureFixture[str]
    ) -> None:
        stderr = b"fatal: unable to access 'https://user:s3cret@github.com/lightos/Panoptic.git/': denied\n"
        mock_run.side_effect = [
            _ok(TRUSTED_REMOTE),
            _ok(b"main\n"),
            _ok(HEAD_A),
            MagicMock(returncode=1, stdout=b"", stderr=stderr),
        ]
        assert do_update() == 2
        out = capsys.readouterr().out
        assert "s3cret" not in out
        assert "unable to access" in out

    @pytest.mark.parametrize(
        "remote",
        [
            b"https://github.com/attacker/Panoptic.git\n",
            b"http://github.com/lightos/Panoptic.git\n",
            b"/some/local/mirror\n",
        ],
    )
    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_untrusted_remote_is_rejected(
        self, mock_exists: Any, mock_run: Any, remote: bytes, capsys: pytest.CaptureFixture[str]
    ) -> None:
        mock_run.side_effect = [_ok(remote)]
        assert do_update() == 2
        assert mock_run.call_count == 1  # never reaches git pull
        assert "not a trusted upstream URL" in capsys.readouterr().out

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_remote_lookup_failure(self, mock_exists: Any, mock_run: Any) -> None:
        mock_run.side_effect = [MagicMock(returncode=2, stdout=b"", stderr=b"error: No such remote 'origin'")]
        assert do_update() == 2

    @patch("panoptic.update.subprocess.run", side_effect=FileNotFoundError("git"))
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_git_missing(self, mock_exists: Any, mock_run: Any, capsys: pytest.CaptureFixture[str]) -> None:
        assert do_update() == 2
        assert "'git' is not installed" in capsys.readouterr().out

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_remote_check_timeout(self, mock_exists: Any, mock_run: Any) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="git", timeout=30)
        assert do_update() == 2

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_pull_timeout(self, mock_exists: Any, mock_run: Any, capsys: pytest.CaptureFixture[str]) -> None:
        mock_run.side_effect = [
            _ok(TRUSTED_REMOTE),
            _ok(b"main\n"),
            _ok(HEAD_A),
            subprocess.TimeoutExpired(cmd="git", timeout=300),
        ]
        assert do_update() == 2
        assert "timed out" in capsys.readouterr().out

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_git_checkout_rejects_non_main_branch(self, mock_exists: Any, mock_run: Any) -> None:
        mock_run.side_effect = [_ok(TRUSTED_REMOTE), _ok(b"feature\n")]
        assert do_update() == 2
        assert mock_run.call_count == 2

    @pytest.mark.parametrize(
        ("marker", "installer", "command"),
        [
            ("pipx_metadata.json", "pipx", "pipx upgrade panoptic"),
            ("uv-receipt.toml", "uv", "uv tool upgrade panoptic"),
        ],
    )
    def test_tool_installs_print_their_upgrade_command(
        self,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
        capsys: pytest.CaptureFixture[str],
        marker: str,
        installer: str,
        command: str,
    ) -> None:
        (tmp_path / marker).write_text("")
        monkeypatch.setattr(update, "_PROJECT_ROOT", str(tmp_path / "site-packages"))
        monkeypatch.setattr(sys, "prefix", str(tmp_path))
        assert do_update() == 0
        out = capsys.readouterr().out
        assert f"installed with {installer}" in out
        assert f"To update, run: {command}" in out

    @patch("panoptic.update.os.path.exists", return_value=False)
    def test_pip_installed_prints_guidance(self, mock_exists: Any, capsys: pytest.CaptureFixture[str]) -> None:
        assert do_update() == 0
        captured = capsys.readouterr()
        assert "installed with pip" in captured.out
        assert (
            "python -m pip install --upgrade https://github.com/lightos/Panoptic/archive/refs/heads/main.zip"
        ) in captured.out
        assert "pip install -U panoptic" not in captured.out

    def test_ssh_and_https_remotes_are_equivalent(self) -> None:
        assert _normalise_git_url("git@github.com:lightos/Panoptic.git") == _normalise_git_url(
            "https://github.com/lightos/Panoptic.git"
        )

    @pytest.mark.parametrize(
        "url",
        [
            "http://github.com/lightos/Panoptic.git",
            "git://github.com/lightos/Panoptic.git",
            "file://github.com/lightos/Panoptic.git",
        ],
    )
    def test_insecure_remote_transports_are_rejected(self, url: str) -> None:
        assert _uses_secure_git_transport(url) is False


class TestGetRevision:
    @patch("panoptic.update.subprocess.run")
    def test_returns_short_hash(self, mock_run: Any) -> None:
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"abc1234567890abcdef1234567890abcdef123456\n",
        )
        rev = get_revision()
        assert rev is not None
        assert len(rev) == 7

    @patch("panoptic.update.subprocess.run")
    def test_returns_none_on_failure(self, mock_run: Any) -> None:
        mock_run.return_value = MagicMock(returncode=1, stdout=b"")
        rev = get_revision()
        assert rev is None

    @patch("panoptic.update.subprocess.run", side_effect=FileNotFoundError("git"))
    def test_returns_none_when_git_missing(self, mock_run: Any) -> None:
        assert get_revision() is None
