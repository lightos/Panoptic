"""Print pip constraints pinning every dependency to its declared lower bound.

The "minimum-versions" CI job installs Panoptic against these pins to prove it
works with the oldest releases it claims to support. Deriving them from
pyproject.toml means a raised floor (e.g. from Dependabot) needs no second edit.
Every runtime and dev requirement must declare a ">=" lower bound.
"""

import re
import sys
import tomllib
from pathlib import Path

PYPROJECT = Path(__file__).resolve().parents[2] / "pyproject.toml"
FLOOR = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*[^;]*?>=\s*([^,;\s]+)")


def main() -> int:
    project = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))["project"]
    requirements = list(project["dependencies"])
    for extra in project.get("optional-dependencies", {}).values():
        requirements.extend(extra)

    pins: dict[str, str] = {}
    for requirement in requirements:
        match = FLOOR.match(requirement)
        if not match:
            print(f"error: {requirement!r} has no '>=' lower bound", file=sys.stderr)
            return 1
        pins[match.group(1)] = match.group(2)

    for name, version in pins.items():
        print(f"{name}=={version}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
