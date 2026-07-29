"""Tests for panoptic.update — git self-update."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from panoptic.update import (
    GIT_UPSTREAM_REF,
    _normalise_git_url,
    _uses_secure_git_transport,
    do_update,
    get_revision,
)


class TestDoUpdate:
    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_git_checkout_runs_git_pull(self, mock_exists: Any, mock_run: Any) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=b"git@github.com:lightos/Panoptic.git\n"),
            MagicMock(returncode=0, stdout=b"main\n"),
            MagicMock(returncode=0, stdout=b"Already up to date.\n"),
            MagicMock(returncode=0, stdout=b"abc1234567890abcdef1234567890abcdef123456\n"),
        ]
        assert do_update() == 0
        assert mock_run.call_count == 4
        # Should use list args, not shell=True
        pull_args = mock_run.call_args_list[2]
        assert pull_args[0][0] == ["git", "pull", "--ff-only", "origin", GIT_UPSTREAM_REF]

    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_git_checkout_rejects_non_main_branch(self, mock_exists: Any, mock_run: Any) -> None:
        mock_run.side_effect = [
            MagicMock(returncode=0, stdout=b"git@github.com:lightos/Panoptic.git\n"),
            MagicMock(returncode=0, stdout=b"feature\n"),
        ]
        assert do_update() == 2
        assert mock_run.call_count == 2

    @patch("panoptic.update.os.path.exists", return_value=False)
    def test_pip_installed_prints_guidance(self, mock_exists: Any, capsys: pytest.CaptureFixture[str]) -> None:
        assert do_update() == 0
        captured = capsys.readouterr()
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
