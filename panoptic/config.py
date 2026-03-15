"""Configuration loading and merging for Panoptic.

Supports TOML config files with CLI argument overrides.
Merge priority: CLI args > config file > built-in defaults.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from panoptic.models import OutputFormat, ScanConfig

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "panoptic" / "config.toml"


def load_config(path: str | None = None) -> dict[str, Any]:
    """Load a TOML config file.

    Returns an empty dict if the file doesn't exist or is invalid.
    """
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
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
    # Start with file config defaults
    merged: dict[str, Any] = dict(file_config.get("defaults", {}))

    # Map proxy and header sections to flat ScanConfig fields
    proxy_url = file_config.get("proxy", {}).get("url")
    if proxy_url:
        merged["proxy"] = proxy_url

    headers_section = file_config.get("headers", {})
    if isinstance(headers_section, dict):
        header_ua = headers_section.get("user_agent")
        if header_ua:
            merged["user_agent"] = header_ua

    # Apply CLI args (override file config)
    for key, value in cli_args.items():
        if value is not None:
            merged[key] = value

    # Handle output_format enum conversion
    if "output_format" in merged and isinstance(merged["output_format"], str):
        merged["output_format"] = OutputFormat(merged["output_format"])

    # Normalize match_codes / filter_codes from TOML (may be string or list of strings)
    for code_key in ("match_codes", "filter_codes"):
        val = merged.get(code_key)
        if isinstance(val, str):
            try:
                codes = [int(c.strip()) for c in val.split(",")]
                for c in codes:
                    if not 100 <= c <= 599:
                        raise ValueError(f"HTTP status code out of range: {c}")
                merged[code_key] = codes
            except ValueError as e:
                flag = "match_codes" if code_key == "match_codes" else "filter_codes"
                print(f"[!] Invalid {flag} in config: {e}", file=sys.stderr)
                merged.pop(code_key)
        elif isinstance(val, list) and val:
            try:
                codes = [int(c) for c in val]
                for c in codes:
                    if not 100 <= c <= 599:
                        raise ValueError(f"HTTP status code out of range: {c}")
                merged[code_key] = codes
            except (ValueError, TypeError) as e:
                flag = "match_codes" if code_key == "match_codes" else "filter_codes"
                print(f"[!] Invalid {flag} in config: {e}", file=sys.stderr)
                merged.pop(code_key)

    # Backward compatibility: normalize singular "header" to plural "headers"
    if "header" in merged and "headers" not in merged:
        val = merged.pop("header")
        if isinstance(val, str):
            merged["headers"] = [val]
        elif isinstance(val, list):
            merged["headers"] = val
    elif "header" in merged:
        merged.pop("header")

    # Ensure url is present
    url = merged.pop("url", "")

    return ScanConfig(url=url, **{k: v for k, v in merged.items() if k in ScanConfig.__dataclass_fields__})
