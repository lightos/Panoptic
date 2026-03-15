"""Tests for panoptic.update — git self-update."""

from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from panoptic.update import do_update, get_revision


class TestDoUpdate:
    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_git_checkout_runs_git_pull(self, mock_exists: Any, mock_run: Any) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout=b"Already up to date.\n")
        do_update()
        mock_run.assert_called()
        # Should use list args, not shell=True
        args = mock_run.call_args
        assert isinstance(args[0][0], list)

    @patch("panoptic.update.os.path.exists", return_value=False)
    def test_pip_installed_prints_guidance(self, mock_exists: Any, capsys: pytest.CaptureFixture[str]) -> None:
        do_update()
        captured = capsys.readouterr()
        assert "pip" in captured.out.lower()


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
