"""Utility functions for Panoptic."""

from __future__ import annotations

import errno
import os
import random
import re
import secrets
import stat
import sys
from importlib.resources import files
from typing import Any, TextIO
from urllib.parse import unquote_plus, urlsplit

_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_OS_ALIASES = {
    "osx": "OS X",
    "os x": "OS X",
    "dragonflybsd": "DragonFly BSD",
    "dragonfly bsd": "DragonFly BSD",
}


def normalize_os_name(value: str | None) -> str | None:
    """Normalize known OS aliases case-insensitively, preserving unknown names."""
    if value is None:
        return None
    stripped = value.strip()
    return _OS_ALIASES.get(stripped.casefold(), stripped)


def normalize_os_names(value: str | None) -> tuple[str, ...]:
    """Split and normalize comma-separated OS metadata."""
    if not value:
        return ()
    return tuple(normalized for part in value.split(",") if (normalized := normalize_os_name(part)))


def _single_os_matches(case_os: str, restriction: str) -> bool:
    """Compare two already-normalized, non-empty OS labels."""
    case_folded = case_os.casefold()
    restriction_folded = restriction.casefold()
    if restriction_folded == "*nix":
        return case_folded != "windows"
    if case_folded == "*nix":
        return restriction_folded != "windows"
    return case_folded == restriction_folded


def os_matches_restriction(case_os: str | None, restriction: str | None) -> bool:
    """Return True if a case's OS is compatible with an OS restriction/filter.

    Applies a hierarchical Unix-family rule so the case-list prefilter
    (``parse_cases``) and the runtime scan restriction stay in lockstep:

      * an empty case OS or empty restriction always matches;
      * a ``*NIX`` restriction includes every non-Windows OS (FreeBSD, OS X, ...);
      * a specific Unix restriction (e.g. FreeBSD) still includes the generic
        ``*NIX`` cases;
      * otherwise the comparison is exact (case-insensitive).
    """
    if not case_os or not restriction:
        return True
    case_values = normalize_os_names(case_os)
    restriction_values = normalize_os_names(restriction)
    if not case_values or not restriction_values:
        return True
    return any(
        _single_os_matches(case_value, restriction_value)
        for case_value in case_values
        for restriction_value in restriction_values
    )


def validate_url_scheme(url: str) -> None:
    """Validate that a URL uses http:// or https:// scheme.

    Raises ValueError if the scheme is invalid (prevents SSRF via file://, ftp://, etc.).
    """
    parsed = urlsplit(url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Only http:// and https:// URLs are supported, got '{parsed.scheme}://'")
    if not parsed.hostname:
        raise ValueError("URL must include a hostname")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid URL port: {exc}") from exc
    del port


def validate_header(header: str, *, warn_deprecated: bool = True) -> tuple[str, str]:
    """Parse and validate a custom HTTP header string.

    Expected format: 'Name: Value' (standard HTTP header format).
    Rejects headers containing CRLF characters (header injection prevention).

    Returns (name, value) tuple.
    """
    if ":" not in header:
        # Backward compatibility: original used Name=Value format
        if "=" in header:
            if warn_deprecated:
                print(
                    "[!] Warning: header format 'Name=Value' is deprecated, use 'Name: Value'",
                    file=sys.stderr,
                )
            name, _, value = header.partition("=")
        else:
            raise ValueError("Header must contain a colon separator (format: 'Name: Value')")
    else:
        name, _, value = header.partition(":")

    # Check for CRLF BEFORE stripping — strip() would silently remove injection chars
    if any(c in name + value for c in "\r\n\x00"):
        raise ValueError("Header contains CRLF/NUL characters (possible header injection)")

    name = name.strip()
    value = value.strip()

    if not name:
        raise ValueError("Header name cannot be empty")
    if not _HEADER_NAME_RE.fullmatch(name):
        raise ValueError(f"Invalid HTTP header name: {name!r}")

    return name, value


def has_parameter(parameters: str, expected_name: str) -> bool:
    """Return whether form/query syntax contains a decoded or raw parameter name."""
    for segment in parameters.split("&"):
        raw_name, separator, _value = segment.partition("=")
        if separator and (raw_name == expected_name or unquote_plus(raw_name) == expected_name):
            return True
    return False


def replace_parameter_value(parameters: str, expected_name: str, value: str) -> str:
    """Replace matching form/query values while preserving each raw parameter name."""
    replaced: list[str] = []
    for segment in parameters.split("&"):
        raw_name, separator, _old_value = segment.partition("=")
        if separator and (raw_name == expected_name or unquote_plus(raw_name) == expected_name):
            replaced.append(f"{raw_name}={value}")
        else:
            replaced.append(segment)
    return "&".join(replaced)


def sanitize_filename(path: str) -> str:
    """Sanitize a file path for use as a local output filename.

    Replaces directory separators and dangerous characters to prevent
    path traversal in output file writes.
    """
    # Replace path separators and colons first (prevents traversal bypasses)
    sanitized = path.replace("/", "_").replace("\\", "_").replace(":", "_")
    # Remove traversal sequences (loop until stable to prevent bypass via "....//")
    while ".." in sanitized:
        sanitized = sanitized.replace("..", "")
    # Remove leading dots and underscores
    sanitized = sanitized.lstrip("._")
    return sanitized or "unnamed"


def open_secure_write(path: str, *, newline: str | None = None) -> TextIO:
    """Open a file for writing with platform-appropriate hardening.

    Sensitive scan artifacts (log files, result/list output, discovered file
    content) may echo target paths, redacted URLs, or retrieved file bodies.
    On POSIX, the file is forced to owner-only mode 0o600 before truncation.
    Symlink protection depends on the primitives exposed by the platform:

      * With ``O_NOFOLLOW``, ``os.open`` atomically refuses a symlink at the final
        path component.
      * Without ``O_NOFOLLOW``, an ``lstat`` check rejects an already-present
        symlink (and Windows junction where detectable), but cannot eliminate a
        check/open race.

    The file is opened *without* ``O_TRUNC`` and only truncated after
    permissions are confirmed, so a permission-hardening failure fails closed
    on POSIX instead of destroying a pre-existing file's contents. Windows mode
    bits do not configure NTFS ACLs, so owner-only access is not guaranteed there.
    Raises OSError on failure.
    """
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    if not nofollow:
        try:
            target_stat = os.lstat(path)
        except FileNotFoundError:
            pass
        else:
            is_junction = getattr(os.path, "isjunction", lambda _path: False)
            if stat.S_ISLNK(target_stat.st_mode) or is_junction(path):
                raise OSError(errno.ELOOP, "refusing to follow symlink or junction", path)

    flags = os.O_WRONLY | os.O_CREAT | nofollow | getattr(os, "O_BINARY", 0)
    fd = os.open(path, flags, 0o600)
    try:
        # Tighten permissions BEFORE truncating. If we cannot guarantee 0600 we
        # must fail closed rather than proceed — and because we have not yet
        # truncated, a pre-existing file's contents are left intact.
        if hasattr(os, "fchmod"):
            os.fchmod(fd, 0o600)
        elif os.name == "posix":
            raise OSError(errno.ENOTSUP, "fchmod is unavailable; cannot enforce mode 0o600")
        os.ftruncate(fd, 0)
        return os.fdopen(fd, "w", encoding="utf-8", newline=newline)
    except BaseException:
        os.close(fd)
        raise


def load_data_file(filename: str) -> str:
    """Load a data file from the panoptic.data package.

    Uses importlib.resources for compatibility with installed packages
    (zip archives, wheels).
    """
    data_files = files("panoptic.data")
    resource = data_files.joinpath(filename)
    return resource.read_text(encoding="utf-8")


def get_random_agent() -> str:
    """Return a random User-Agent string from the bundled agents list."""
    content = load_data_file("agents.txt")
    agents = [line.strip() for line in content.splitlines() if line.strip()]
    return random.choice(agents)


def generate_invalid_filename() -> str:
    """Generate a cryptographically random filename for baseline comparison.

    Uses secrets module instead of random for unpredictability.
    """
    return secrets.token_hex(8)


def redact_parameter_values(value: str) -> str:
    """Redact values in query/form syntax, including bare non-key segments."""
    redacted: list[str] = []
    for segment in value.split("&"):
        if "=" in segment:
            key, _, _parameter_value = segment.partition("=")
            redacted.append(f"{key}=***")
        elif segment:
            redacted.append("***")
        else:
            redacted.append("")
    return "&".join(redacted)


def redact_url(url: str) -> str:
    """Redact sensitive parts of a URL for safe display.

    Strips userinfo (user:pass@) and replaces query/fragment values
    to prevent credential leakage in banners and log files.
    """
    parsed = urlsplit(url)
    # Rebuild netloc without userinfo
    host = parsed.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    try:
        port = parsed.port
    except ValueError:
        port = None
    if port:
        host = f"{host}:{port}"
    # Redact query parameter values but keep keys for context
    if parsed.query:
        redacted_query = redact_parameter_values(parsed.query)
        return f"{parsed.scheme}://{host}{parsed.path}?{redacted_query}"
    return f"{parsed.scheme}://{host}{parsed.path}"


def normalize_url(url: str) -> str:
    """Normalize a URL, adding http:// scheme if missing."""
    if not url.lower().startswith(("http://", "https://")):
        url = f"http://{url}"
    return url


def parse_status_codes(raw: str | list[Any]) -> list[int]:
    """Parse and validate a comma-separated string or list of HTTP status codes.

    Raises ValueError on invalid codes or codes outside 100-599.
    """
    codes = [int(c.strip()) for c in raw.split(",")] if isinstance(raw, str) else [int(c) for c in raw]
    for code in codes:
        if not 100 <= code <= 599:
            raise ValueError(f"HTTP status code out of range: {code}")
    return codes
