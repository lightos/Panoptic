"""Git-based self-update for Panoptic.

Detects whether running from git checkout or pip install and
acts appropriately.
"""

from __future__ import annotations

import os
import re
import subprocess
from urllib.parse import urlsplit

from panoptic.utils import redact_urls_in_text

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


def _git_env() -> dict[str, str]:
    """Environment for git subprocesses.

    Clears inherited GIT_* variables (GIT_DIR, GIT_WORK_TREE, ...) so git
    operates on Panoptic's own checkout, and forces the C locale so output
    is not translated.
    """
    env = {key: value for key, value in os.environ.items() if not key.startswith("GIT_")}
    env["LC_ALL"] = "C"
    env["LANGUAGE"] = "C"
    # Never block waiting for credentials on a terminal prompt.
    env["GIT_TERMINAL_PROMPT"] = "0"
    return env


def _run_git(args: list[str], timeout: int) -> subprocess.CompletedProcess[bytes]:
    """Run a git command in the project root with a sanitized environment."""
    return subprocess.run(
        ["git", *args],
        capture_output=True,
        cwd=_PROJECT_ROOT,
        env=_git_env(),
        timeout=timeout,
    )


def _head_commit() -> str | None:
    """Return the full HEAD commit hash, or None if it cannot be determined."""
    result = _run_git(["rev-parse", "--verify", "HEAD"], timeout=30)
    if result.returncode != 0:
        return None
    stdout = result.stdout.decode("utf-8", errors="replace").strip()
    return stdout if re.fullmatch(r"[0-9a-f]{40,64}", stdout) else None


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
        remote_check = _run_git(["remote", "get-url", "origin"], timeout=30)
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
        branch_check = _run_git(["symbolic-ref", "--quiet", "--short", "HEAD"], timeout=30)
        current_branch = branch_check.stdout.decode("utf-8", errors="replace").strip()
        if branch_check.returncode != 0 or current_branch != GIT_UPSTREAM_BRANCH:
            print(f"[!] Self-update requires the '{GIT_UPSTREAM_BRANCH}' branch to be checked out.")
            return 2

        before = _head_commit()
        result = _run_git(["pull", "--ff-only", "origin", GIT_UPSTREAM_REF], timeout=300)
        after = _head_commit() if result.returncode == 0 else None
    except FileNotFoundError:
        print("[!] 'git' is not installed or not in PATH.")
        return 2
    except subprocess.TimeoutExpired:
        print("[!] Update timed out.")
        return 2

    if result.returncode == 0:
        revision = after[:7] if after else "unknown"
        if before is not None and before == after:
            print(f"[i] Already at the latest revision '{revision}'.")
        else:
            print(f"[i] Updated to revision '{revision}'.")
        return 0

    stderr = result.stderr.decode("utf-8", errors="replace").strip()
    print(f"[!] Update failed (git exit code {result.returncode}):")
    if stderr:
        # Credential helpers can echo repository URLs with embedded credentials.
        for line in redact_urls_in_text(stderr).splitlines():
            print(f"    {line}")
    print(
        "[i] Make sure the working tree has no uncommitted changes (see 'git status') "
        "and that the local branch has not diverged from upstream, then try again."
    )
    return 2


def get_revision() -> str | None:
    """Get the short git revision hash."""
    try:
        commit = _head_commit()
        if commit is not None:
            return commit[:7]
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None
