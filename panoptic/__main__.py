"""Entry point for `python -m panoptic`."""

import asyncio
import sys

# Top-level modules of the runtime dependencies in pyproject.toml.
_DEPENDENCY_MODULES = frozenset({"aiohttp", "aiohttp_socks", "multidict", "yarl", "rich", "rich_argparse"})

_MISSING_DEPENDENCY_HELP = """\
[!] Panoptic's dependencies are not installed for this Python:
    {python} (missing module '{module}')

Install Panoptic with pipx, which manages them for you (the README's
Installation section shows how to install pipx itself):

    pipx install git+https://github.com/lightos/Panoptic.git

Then open a new terminal and run 'panoptic'.

To run it from this checkout instead, install it into a virtual environment
there (on Debian and Ubuntu, run 'sudo apt install python3-venv' first):

    python3 -m venv .venv
    .venv/bin/python -m pip install -e .
    .venv/bin/panoptic --version

On Windows, use .venv\\Scripts\\python and .venv\\Scripts\\panoptic instead.
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
