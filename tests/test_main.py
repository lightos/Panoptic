"""Tests for panoptic.__main__ — the command entry point."""

import builtins
from typing import Any

import pytest

from panoptic import __main__ as entry


def _fail_import(monkeypatch: pytest.MonkeyPatch, missing: str) -> None:
    real_import = builtins.__import__

    def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
        if name == "panoptic.cli":
            raise ModuleNotFoundError(f"No module named '{missing}'", name=missing)
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)


class TestMissingDependencies:
    @pytest.mark.parametrize("missing", ["rich_argparse", "aiohttp", "aiohttp_socks.proxy"])
    def test_missing_dependency_prints_install_steps(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str], missing: str
    ) -> None:
        _fail_import(monkeypatch, missing)
        with pytest.raises(SystemExit) as exc_info:
            entry.main()
        assert exc_info.value.code == 1
        err = capsys.readouterr().err
        assert f"missing module '{missing.partition('.')[0]}'" in err
        assert "pipx install git+https://github.com/lightos/Panoptic.git" in err
        assert ".venv/bin/python -m pip install -e ." in err
        assert "source" not in err  # every indented line is a runnable command

    def test_other_missing_modules_are_not_hidden(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _fail_import(monkeypatch, "panoptic.nonexistent")
        with pytest.raises(ModuleNotFoundError):
            entry.main()
