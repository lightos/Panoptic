"""Entry point for `python -m panoptic`."""

import asyncio
import sys

# Top-level modules of the runtime dependencies in pyproject.toml.
_DEPENDENCY_MODULES = frozenset({"aiohttp", "aiohttp_socks", "multidict", "yarl", "rich", "rich_argparse"})

_MISSING_DEPENDENCY_HELP = """\
[!] Panoptic's dependencies are not installed for this Python:
    {python} (missing module '{module}')

Install Panoptic with pipx, which manages them for you:

    pipx install git+https://github.com/lightos/Panoptic.git

then run 'panoptic' from any terminal. To run it from this checkout
instead, install it into a virtual environment and activate that
environment in each new terminal (or run .venv/bin/panoptic directly):

    python3 -m venv .venv
    source .venv/bin/activate        (Windows: .venv\\Scripts\\activate)
    python -m pip install -e .
"""


def main() -> None:
    """Main entry point."""
    try:
        from panoptic.cli import run
    except ModuleNotFoundError as exc:
        module = (exc.name or "").partition(".")[0]
        if module not in _DEPENDENCY_MODULES:
            raise
        sys.stderr.write(_MISSING_DEPENDENCY_HELP.format(python=sys.executable, module=module))
        sys.exit(1)

    try:
        sys.exit(asyncio.run(run()))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
