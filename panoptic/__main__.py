"""Entry point for `python -m panoptic`."""

import asyncio
import sys


def main() -> None:
    """Main entry point."""
    from panoptic.cli import run

    try:
        sys.exit(asyncio.run(run()))
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
