"""Git-based self-update for Panoptic.

Detects whether running from git checkout or pip install and
acts appropriately.
"""

from __future__ import annotations

import os
import re
import subprocess

GIT_REPOSITORY_URL = "https://github.com/lightos/Panoptic.git"

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_PACKAGE_DIR)


def _normalise_git_url(url: str) -> str:
    """Normalise a git remote URL for comparison (strip trailing .git and slash)."""
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    return url.lower()


def do_update() -> None:
    """Perform self-update from git or print pip guidance."""
    git_dir = os.path.join(_PROJECT_ROOT, ".git")

    if not os.path.exists(git_dir):
        print("[i] Panoptic appears to be installed via pip.")
        print("[i] To update, run: pip install -U panoptic")
        return

    print("[i] Checking for updates...")

    # Verify that the configured remote points to the expected upstream repository
    # to prevent supply-chain attacks via tampered local git configuration.
    try:
        remote_check = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            cwd=_PROJECT_ROOT,
        )
    except FileNotFoundError:
        print("[!] 'git' is not installed or not in PATH.")
        print("[i] Please install git or update via: pip install -U panoptic")
        return
    if remote_check.returncode != 0:
        print("[!] Cannot determine remote URL. Please verify your git configuration.")
        return

    remote_url = remote_check.stdout.decode("utf-8", errors="replace").strip()

    if _normalise_git_url(remote_url) != _normalise_git_url(GIT_REPOSITORY_URL):
        print(f"[!] Remote 'origin' ({remote_url}) does not match expected upstream.")
        print(f"[i] Expected: {GIT_REPOSITORY_URL}")
        print("[i] Aborting update for safety. Please verify your git remotes.")
        return

    try:
        result = subprocess.run(
            ["git", "pull", "--ff-only", "origin"],
            capture_output=True,
            cwd=_PROJECT_ROOT,
        )
    except FileNotFoundError:
        print("[!] 'git' is not installed or not in PATH.")
        return

    if result.returncode == 0:
        stdout = result.stdout.decode("utf-8", errors="replace")
        updated = "Already" not in stdout
        revision = get_revision() or "unknown"
        if updated:
            print(f"[i] Updated to revision '{revision}'.")
        else:
            print(f"[i] Already at the latest revision '{revision}'.")
    else:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        print(f"[!] Update failed: {stderr}")
        print("[i] Please make sure 'git' is installed and accessible.")


def get_revision() -> str | None:
    """Get the short git revision hash."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            cwd=_PROJECT_ROOT,
        )
        if result.returncode == 0:
            stdout = result.stdout.decode("utf-8", errors="replace").strip()
            if re.match(r"[0-9a-f]{40}", stdout, re.I):
                return stdout[:7]
    except FileNotFoundError:
        pass
    return None
