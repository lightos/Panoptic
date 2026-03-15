"""Utility functions for Panoptic."""

from __future__ import annotations

import random
import re
import secrets
import sys
from importlib.resources import files
from typing import Any
from urllib.parse import urlsplit

# Regex to redact values in key=value&... encoded strings (query params, form bodies)
_PARAM_VALUE_RE = re.compile(r"(?<==)[^&]*")


def validate_url_scheme(url: str) -> None:
    """Validate that a URL uses http:// or https:// scheme.

    Raises ValueError if the scheme is invalid (prevents SSRF via file://, ftp://, etc.).
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http:// and https:// URLs are supported, got '{parsed.scheme}://'")


def validate_header(header: str) -> tuple[str, str]:
    """Parse and validate a custom HTTP header string.

    Expected format: 'Name: Value' (standard HTTP header format).
    Rejects headers containing CRLF characters (header injection prevention).

    Returns (name, value) tuple.
    """
    if ":" not in header:
        # Backward compatibility: original used Name=Value format
        if "=" in header:
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
    if any(c in name + value for c in "\r\n"):
        raise ValueError("Header contains CRLF characters (possible header injection)")

    name = name.strip()
    value = value.strip()

    if not name:
        raise ValueError("Header name cannot be empty")

    return name, value


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


def redact_url(url: str) -> str:
    """Redact sensitive parts of a URL for safe display.

    Strips userinfo (user:pass@) and replaces query/fragment values
    to prevent credential leakage in banners and log files.
    """
    parsed = urlsplit(url)
    # Rebuild netloc without userinfo
    host = parsed.hostname or ""
    if parsed.port:
        host = f"{host}:{parsed.port}"
    # Redact query parameter values but keep keys for context
    if parsed.query:
        redacted_query = _PARAM_VALUE_RE.sub("***", parsed.query)
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
