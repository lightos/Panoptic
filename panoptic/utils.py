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
from typing import TextIO
from urllib.parse import unquote_plus, urlsplit

_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_OS_ALIASES = {
    "osx": "OS X",
    "os x": "OS X",
    "dragonflybsd": "DragonFly BSD",
    "dragonfly bsd": "DragonFly BSD",
}


# C0 controls, DEL, and C1 controls (ESC/CSI/OSC/etc. can drive terminals).
CONTROL_CHARS_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def escape_control_chars(text: str, keep: str = "") -> str:
    """Replace control characters with visible escapes (e.g. ESC -> ``\\x1b``).

    Characters listed in ``keep`` (such as ``"\\n"``) are left untouched.
    """

    def _escape(match: re.Match[str]) -> str:
        char = match.group(0)
        return char if char in keep else f"\\x{ord(char):02x}"

    return CONTROL_CHARS_RE.sub(_escape, text)


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


_UNSAFE_FILENAME_CHARS_RE = re.compile(r"[^A-Za-z0-9._-]")
_WINDOWS_RESERVED_NAMES = frozenset(
    {"CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$"} | {f"COM{i}" for i in range(10)} | {f"LPT{i}" for i in range(10)}
)
MAX_FILENAME_BYTES = 200


def _truncate_utf8(value: str, max_bytes: int) -> str:
    """Truncate ``value`` so its UTF-8 encoding fits ``max_bytes`` without splitting a character."""
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def sanitize_filename(path: str, max_bytes: int = MAX_FILENAME_BYTES) -> str:
    """Sanitize a file path for use as a local output filename.

    Every character outside ``[A-Za-z0-9._-]`` (directory separators, colons,
    control characters, non-ASCII) is replaced with ``_``, traversal sequences
    are removed, Windows reserved device names are neutralized, and the result
    is capped at ``max_bytes`` UTF-8 bytes.
    """
    sanitized = _UNSAFE_FILENAME_CHARS_RE.sub("_", path)
    # Remove traversal sequences (loop until stable to prevent bypass via "....//")
    while ".." in sanitized:
        sanitized = sanitized.replace("..", "")
    # Remove leading dots/underscores and trailing dots (invalid on Windows)
    sanitized = _truncate_utf8(sanitized.lstrip("._"), max_bytes).rstrip(".")
    if not sanitized:
        return "unnamed"
    # Windows reserves device names regardless of extension (e.g. "CON.txt").
    if sanitized.split(".", 1)[0].upper() in _WINDOWS_RESERVED_NAMES:
        sanitized = _truncate_utf8(f"_{sanitized}", max_bytes).rstrip(".")
    return sanitized


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


def _redact_path_parameters(path: str) -> str:
    """Redact matrix/path parameters (``/a;jsessionid=SECRET/b``) in a URL path."""
    if ";" not in path:
        return path
    segments: list[str] = []
    for segment in path.split("/"):
        name, separator, params = segment.partition(";")
        if not separator:
            segments.append(segment)
            continue
        redacted: list[str] = []
        for param in params.split(";"):
            if "=" in param:
                key, _, _value = param.partition("=")
                redacted.append(f"{key}=***")
            else:
                redacted.append("***" if param else "")
        segments.append(";".join([name, *redacted]))
    return "/".join(segments)


def redact_url(url: str) -> str:
    """Redact sensitive parts of a URL for safe display.

    Strips userinfo (user:pass@) and fragments, and replaces query and path
    (``;key=value``) parameter values to prevent credential leakage in
    banners and log files.
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
    path = _redact_path_parameters(parsed.path)
    # Redact query parameter values but keep keys for context
    if parsed.query:
        redacted_query = redact_parameter_values(parsed.query)
        return f"{parsed.scheme}://{host}{path}?{redacted_query}"
    return f"{parsed.scheme}://{host}{path}"


# A leading "scheme:" that is not "host:port" (a digit right after the colon).
_URL_SCHEME_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:(?!\d)")


def normalize_url(url: str) -> str:
    """Normalize a URL, adding an http:// scheme only when none is present.

    Inputs that already carry a scheme (e.g. ``ftp://host/x``) are returned
    unchanged so :func:`validate_url_scheme` rejects non-HTTP(S) schemes,
    instead of being mangled into ``http://ftp://host/x`` (host ``ftp``).
    """
    if url.startswith("//"):
        return f"http:{url}"
    if _URL_SCHEME_RE.match(url):
        return url
    return f"http://{url}"


def parse_status_codes(raw: object) -> list[int]:
    """Parse and validate a comma-separated string or list of HTTP status codes.

    Lists must contain integers only (floats, booleans and strings are
    rejected rather than coerced) and string entries must be plain decimal
    digits. Raises ValueError on invalid input or codes outside 100-599.
    """
    codes: list[int] = []
    if isinstance(raw, str):
        for part in raw.split(","):
            stripped = part.strip()
            if not (stripped.isascii() and stripped.isdigit()):
                raise ValueError(f"invalid HTTP status code: {stripped!r}")
            codes.append(int(stripped))
    elif isinstance(raw, list):
        for item in raw:
            if not isinstance(item, int) or isinstance(item, bool):
                raise ValueError(f"HTTP status codes must be integers, got {item!r}")
            codes.append(item)
    else:
        raise ValueError(f"expected a comma-separated string or a list of integers, got {type(raw).__name__} {raw!r}")
    for code in codes:
        if not 100 <= code <= 599:
            raise ValueError(f"HTTP status code out of range: {code}")
    return codes


_URL_IN_TEXT = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://[^\s'\"<>]+")


def redact_urls_in_text(message: str) -> str:
    """Redact credentials and query values from any URLs embedded in a message."""

    def _redact(match: re.Match[str]) -> str:
        try:
            return redact_url(match.group(0))
        except ValueError:
            return "<redacted-url>"

    return _URL_IN_TEXT.sub(_redact, message)
