"""Configuration loading and merging for Panoptic.

Supports TOML config files with CLI argument overrides.
Merge priority: CLI args > config file > built-in defaults.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from panoptic.models import OutputFormat, ScanConfig
from panoptic.utils import normalize_url, parse_status_codes

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore[assignment,unused-ignore]


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "panoptic" / "config.toml"

_STRING_FIELDS = {
    "url",
    "param",
    "data",
    "prefix",
    "postfix",
    "ext_param",
    "bad_string",
    "match_string",
    "replace_slash",
    "output_file",
    "log_file",
    "proxy",
    "user_agent",
    "cookie",
    "os_filter",
    "software_filter",
    "category_filter",
    "type_filter",
    "list_file",
    "resume_file",
}
_BOOLEAN_FIELDS = {
    "path_based",
    "base64_encode",
    "write_files",
    "skip_parsing",
    "automatic",
    "invalid_ssl",
    "all_versions",
    "follow_redirects",
    "verbose",
    "quiet",
    "ignore_proxy",
    "random_agent",
}
_INTEGER_FIELDS = {"concurrency", "retries", "multiplier"}
_NUMBER_FIELDS = {"timeout", "delay", "heuristic_ratio"}


def _validate_merged_types(merged: dict[str, Any]) -> None:
    """Reject TOML values that would otherwise fail later with raw type errors."""
    for field in sorted(_STRING_FIELDS):
        value = merged.get(field)
        if value is not None and not isinstance(value, str):
            raise ValueError(f"{field} must be a string")
    for field in sorted(_BOOLEAN_FIELDS):
        value = merged.get(field)
        if value is not None and not isinstance(value, bool):
            raise ValueError(f"{field} must be a boolean")
    for field in sorted(_INTEGER_FIELDS):
        value = merged.get(field)
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            raise ValueError(f"{field} must be an integer")
    for field in sorted(_NUMBER_FIELDS):
        value = merged.get(field)
        if value is not None and (not isinstance(value, int | float) or isinstance(value, bool)):
            raise ValueError(f"{field} must be a number")


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load a TOML config file.

    Returns an empty dict if the file doesn't exist or is invalid.
    """
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        if path is not None:
            print(f"[!] Warning: config file '{config_path}' does not exist", file=sys.stderr)
        return {}

    if tomllib is None:
        return {}

    try:
        with open(config_path, "rb") as f:
            return dict(tomllib.load(f))
    except (OSError, ValueError):
        print(f"[!] Warning: config file '{config_path}' exists but could not be parsed", file=sys.stderr)
        return {}


def merge_config(cli_args: dict[str, Any], file_config: dict[str, Any]) -> ScanConfig:
    """Merge CLI arguments with file config into a ScanConfig.

    Priority: CLI args > file config > ScanConfig defaults.
    """
    valid_fields = set(ScanConfig.__dataclass_fields__)
    known_sections = {"defaults", "proxy", "headers"}
    for section in sorted(set(file_config) - known_sections):
        print(f"[!] Warning: unknown config section '{section}'", file=sys.stderr)

    defaults = file_config.get("defaults", {})
    if not isinstance(defaults, dict):
        raise ValueError("[defaults] must be a TOML table")
    for key in sorted(set(defaults) - valid_fields - {"header"}):
        print(f"[!] Warning: unknown config option 'defaults.{key}'", file=sys.stderr)

    # Start with file config defaults
    merged: dict[str, Any] = {key: value for key, value in defaults.items() if key in valid_fields or key == "header"}

    # Backward compatibility: normalize singular "header" before merging the
    # dedicated [headers] table and CLI repetitions.
    if "header" in merged:
        legacy_headers = merged.pop("header")
        if isinstance(legacy_headers, str):
            merged["headers"] = [legacy_headers]
        elif isinstance(legacy_headers, list):
            merged["headers"] = legacy_headers
        else:
            raise ValueError("defaults.header must be a string or a list of strings")

    # Map proxy and header sections to flat ScanConfig fields
    proxy_section = file_config.get("proxy", {})
    if not isinstance(proxy_section, dict):
        raise ValueError("[proxy] must be a TOML table")
    for key in sorted(set(proxy_section) - {"url"}):
        print(f"[!] Warning: unknown config option 'proxy.{key}'", file=sys.stderr)
    proxy_url = proxy_section.get("url")
    if proxy_url:
        merged["proxy"] = proxy_url

    headers_section = file_config.get("headers", {})
    if not isinstance(headers_section, dict):
        raise ValueError("[headers] must be a TOML table")
    for key in sorted(set(headers_section) - {"user_agent", "cookie", "values"}):
        print(f"[!] Warning: unknown config option 'headers.{key}'", file=sys.stderr)
    header_ua = headers_section.get("user_agent")
    if header_ua:
        merged["user_agent"] = header_ua
    header_cookie = headers_section.get("cookie")
    if header_cookie:
        merged["cookie"] = header_cookie
    header_values = headers_section.get("values")
    if header_values:
        if not isinstance(header_values, list) or not all(isinstance(header, str) for header in header_values):
            raise ValueError("headers.values must be a list of strings")
        merged["headers"] = [*(merged.get("headers") or []), *header_values]

    # Scalar CLI arguments override file values. Repeatable headers are
    # additive, with CLI values last so duplicate header names retain CLI
    # precedence when the request header mapping is built.
    for key, value in cli_args.items():
        if value is not None:
            if key == "headers":
                if not isinstance(value, list):
                    raise ValueError("headers must be a list of strings")
                merged[key] = [*(merged.get(key) or []), *value]
            else:
                merged[key] = value

    # Handle output_format enum conversion
    if "output_format" in merged and not isinstance(merged["output_format"], OutputFormat):
        if not isinstance(merged["output_format"], str):
            raise ValueError("output_format must be a string")
        try:
            merged["output_format"] = OutputFormat(merged["output_format"])
        except ValueError as e:
            raise ValueError(f"invalid output_format: {e}") from e

    # Normalize match_codes / filter_codes from TOML (may be string or list)
    for code_key in ("match_codes", "filter_codes"):
        val = merged.get(code_key)
        if isinstance(val, str | list) and val:
            try:
                merged[code_key] = parse_status_codes(val)
            except (ValueError, TypeError) as e:
                raise ValueError(f"invalid {code_key}: {e}") from e

    random_delay = merged.get("random_delay")
    if isinstance(random_delay, str):
        parts = random_delay.split("-")
        if len(parts) != 2:
            raise ValueError("random_delay must use MIN-MAX format")
        try:
            merged["random_delay"] = (float(parts[0]), float(parts[1]))
        except ValueError as exc:
            raise ValueError("random_delay must contain numeric MIN-MAX values") from exc
    elif isinstance(random_delay, list):
        if len(random_delay) != 2:
            raise ValueError("random_delay must contain exactly two values")
        merged["random_delay"] = (float(random_delay[0]), float(random_delay[1]))

    headers = merged.get("headers")
    if headers is not None and (
        not isinstance(headers, list) or not all(isinstance(header, str) for header in headers)
    ):
        raise ValueError("headers must be a list of strings")

    _validate_merged_types(merged)

    # Ensure url is present
    url = merged.pop("url", "")
    if url and not url.lower().startswith(("http://", "https://")):
        url = normalize_url(url)

    return ScanConfig(url=url, **{k: v for k, v in merged.items() if k in valid_fields})
