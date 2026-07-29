"""Git-based self-update for Panoptic.

Detects whether running from git checkout or pip install and
acts appropriately.
"""

from __future__ import annotations

import os
import re
import subprocess
from urllib.parse import urlsplit

GIT_REPOSITORY_URL = "https://github.com/lightos/Panoptic.git"
GIT_UPSTREAM_BRANCH = "main"
GIT_UPSTREAM_REF = f"refs/heads/{GIT_UPSTREAM_BRANCH}"
PIP_UPDATE_URL = f"https://github.com/lightos/Panoptic/archive/refs/heads/{GIT_UPSTREAM_BRANCH}.zip"
PIP_UPDATE_COMMAND = f"python -m pip install --upgrade {PIP_UPDATE_URL}"

_PACKAGE_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_ROOT = os.path.dirname(_PACKAGE_DIR)


def _normalise_git_url(url: str) -> str:
    """Normalize HTTPS, SSH URL, and scp-style git remotes for comparison."""
    url = url.strip().rstrip("/")
    if "://" not in url:
        scp_match = re.fullmatch(r"(?:[^@]+@)?(?P<host>[^:]+):(?P<path>.+)", url)
        if scp_match:
            host = scp_match.group("host")
            path = scp_match.group("path")
        else:
            return url.removesuffix(".git").lower()
    else:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        path = parsed.path.lstrip("/")
    return f"{host}/{path.removesuffix('.git')}".lower()


def _uses_secure_git_transport(url: str) -> bool:
    """Return whether a remote uses authenticated HTTPS or SSH transport."""
    stripped = url.strip()
    if "://" not in stripped:
        # Git's scp-like syntax (git@github.com:owner/repo.git) uses SSH.
        return re.fullmatch(r"(?:[^@]+@)?[^:]+:.+", stripped) is not None
    return urlsplit(stripped).scheme.lower() in {"https", "ssh"}


def do_update() -> int:
    """Perform self-update from git or print pip guidance."""
    git_dir = os.path.join(_PROJECT_ROOT, ".git")

    if not os.path.exists(git_dir):
        print("[i] Panoptic appears to be installed via pip.")
        print(f"[i] To update, run: {PIP_UPDATE_COMMAND}")
        return 0

    print("[i] Checking for updates...")

    # Verify that the configured remote points to the expected upstream repository
    # to prevent supply-chain attacks via tampered local git configuration.
    try:
        remote_check = subprocess.run(
            ["git", "remote", "get-url", "origin"],
            capture_output=True,
            cwd=_PROJECT_ROOT,
            timeout=30,
        )
    except FileNotFoundError:
        print("[!] 'git' is not installed or not in PATH.")
        print(f"[i] Please install git or update via: {PIP_UPDATE_COMMAND}")
        return 2
    except subprocess.TimeoutExpired:
        print("[!] Timed out while checking the git remote.")
        return 2
    if remote_check.returncode != 0:
        print("[!] Cannot determine remote URL. Please verify your git configuration.")
        return 2

    remote_url = remote_check.stdout.decode("utf-8", errors="replace").strip()

    if not _uses_secure_git_transport(remote_url) or _normalise_git_url(remote_url) != _normalise_git_url(
        GIT_REPOSITORY_URL
    ):
        print(f"[!] Remote 'origin' ({remote_url}) is not a trusted upstream URL.")
        print(f"[i] Expected: {GIT_REPOSITORY_URL}")
        print("[i] HTTPS and SSH remotes for the official repository are accepted.")
        print("[i] Aborting update for safety. Please verify your git remotes.")
        return 2

    try:
        branch_check = subprocess.run(
            ["git", "symbolic-ref", "--quiet", "--short", "HEAD"],
            capture_output=True,
            cwd=_PROJECT_ROOT,
            timeout=30,
        )
        current_branch = branch_check.stdout.decode("utf-8", errors="replace").strip()
        if branch_check.returncode != 0 or current_branch != GIT_UPSTREAM_BRANCH:
            print(f"[!] Self-update requires the '{GIT_UPSTREAM_BRANCH}' branch to be checked out.")
            return 2

        result = subprocess.run(
            ["git", "pull", "--ff-only", "origin", GIT_UPSTREAM_REF],
            capture_output=True,
            cwd=_PROJECT_ROOT,
            timeout=300,
        )
    except FileNotFoundError:
        print("[!] 'git' is not installed or not in PATH.")
        return 2
    except subprocess.TimeoutExpired:
        print("[!] Update timed out.")
        return 2

    if result.returncode == 0:
        stdout = result.stdout.decode("utf-8", errors="replace")
        updated = "Already" not in stdout
        revision = get_revision() or "unknown"
        if updated:
            print(f"[i] Updated to revision '{revision}'.")
        else:
            print(f"[i] Already at the latest revision '{revision}'.")
        return 0
    else:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        print(f"[!] Update failed: {stderr}")
        print("[i] Please make sure 'git' is installed and accessible.")
        return 2


def get_revision() -> str | None:
    """Get the short git revision hash."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            capture_output=True,
            cwd=_PROJECT_ROOT,
            timeout=30,
        )
        if result.returncode == 0:
            stdout = result.stdout.decode("utf-8", errors="replace").strip()
            if re.match(r"[0-9a-f]{40}", stdout):
                return stdout[:7]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None
