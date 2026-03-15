"""Command-line interface for Panoptic.

Handles argument parsing, validation, and dispatch to scan/list/update modes.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from rich_argparse import RawDescriptionRichHelpFormatter

from panoptic.utils import normalize_url, validate_header, validate_url_scheme

EXAMPLES = """
Examples:
  panoptic --url "http://localhost/include.php?file=test.txt"
  panoptic --url "http://localhost/include.php?file=test.txt&id=1" --param file
  panoptic --url "http://localhost/include.php" --data "file=test.txt&id=1" --param file
  panoptic --url "http://localhost/files/view/test.txt" --path-based --prefix "..%%252f"
  panoptic --url "http://localhost/include.php?file=test.txt" --auto --all-versions
  panoptic --list software
"""


def parse_args(argv: list[str] | None = None) -> dict[str, Any]:
    """Parse command-line arguments and return as a dict."""
    parser = argparse.ArgumentParser(
        prog="panoptic",
        description="Panoptic -- probe a URL for local files via path traversal vulnerability",
        epilog=EXAMPLES,
        formatter_class=RawDescriptionRichHelpFormatter,
    )

    # Connection / Proxy
    conn = parser.add_argument_group("Connection / Proxy")
    conn.add_argument("-u", "--url", help="Target URL vulnerable to path traversal")
    conn.add_argument("--proxy", help="Route requests through proxy (e.g. 'socks5://127.0.0.1:9050')")
    conn.add_argument("--ignore-proxy", action="store_true", help="Bypass system proxy settings")
    conn.add_argument("--random-agent", action="store_true", dest="random_agent", help="Choose random User-Agent")
    conn.add_argument(
        "--header",
        dest="headers",
        action="append",
        help="Add custom HTTP header (e.g. 'X-Forwarded-For: 127.0.0.1'); repeatable",
    )
    conn.add_argument("--cookie", help="Add HTTP Cookie header (e.g. 'sid=foobar; auth=1')")
    conn.add_argument("--user-agent", dest="user_agent", help="Set specific User-Agent string")
    conn.add_argument("--timeout", type=float, default=None, help="HTTP request timeout in seconds (default: 10)")
    conn.add_argument("--retries", type=int, default=None, help="Number of retries per request (default: 3)")
    conn.add_argument(
        "--follow-redirects",
        dest="follow_redirects",
        action="store_true",
        help="Follow HTTP redirects (default: don't follow)",
    )

    # Filtering
    filt = parser.add_argument_group("Filtering / Listing")
    filt.add_argument(
        "-l",
        "--list",
        metavar="GROUP",
        choices=["software", "category", "os"],
        help="Show available values for specified group",
    )
    filt.add_argument("-o", "--os", dest="os_filter", help="Only test files for specific OS")
    filt.add_argument("-s", "--software", dest="software_filter", help="Only test files for specific software")
    filt.add_argument("-c", "--category", dest="category_filter", help="Only test files for specific category")

    # Scan options
    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("-p", "--param", help="Name of vulnerable parameter to test")
    scan.add_argument(
        "-P",
        "--path-based",
        dest="path_based",
        action="store_true",
        help="Target file paths directly instead of query parameters",
    )
    scan.add_argument("-d", "--data", help="Send parameters via POST instead of GET")
    scan.add_argument("-t", "--type", dest="type_filter", help="Filter by type ('conf', 'log', 'other')")
    scan.add_argument("--prefix", default="", help="Add prefix to file paths (e.g. '../')")
    scan.add_argument("--postfix", default="", help="Add suffix to file paths (e.g. '%%00')")
    scan.add_argument("--multiplier", type=int, default=1, help="Repeat prefix N times (default: 1)")
    scan.add_argument("--bad-string", dest="bad_string", help="Skip paths if this string appears in response")
    scan.add_argument(
        "--match-string", dest="match_string", help="Only report findings containing this string in response"
    )
    scan.add_argument(
        "--match-code",
        dest="match_codes",
        help="Only report findings with these HTTP status codes (comma-separated, e.g. '200,301')",
    )
    scan.add_argument(
        "--filter-code",
        dest="filter_codes",
        help="Exclude findings with these HTTP status codes (comma-separated, e.g. '404,500')",
    )
    scan.add_argument("--replace-slash", dest="replace_slash", help="Use alternative character(s) for '/'")
    scan.add_argument(
        "--base64",
        dest="base64_encode",
        action="store_true",
        help="Base64-encode file paths before injection (for endpoints that decode)",
    )
    scan.add_argument("--ext-param", dest="ext_param", help="Name of parameter containing file extension")
    scan.add_argument("--all-versions", dest="all_versions", action="store_true", help="Test all versioned file paths")

    # Performance
    perf = parser.add_argument_group("Performance")
    perf.add_argument("--concurrency", type=int, default=None, help="Number of concurrent requests (default: 4)")
    perf.add_argument("--delay", type=float, default=None, help="Delay between requests in seconds")
    perf.add_argument(
        "--random-delay",
        type=str,
        default=None,
        dest="random_delay",
        metavar="MIN-MAX",
        help="Random delay range in seconds (e.g. '0.5-2.0')",
    )

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    out.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress banner, info, and progress — only show findings and warnings",
    )
    out.add_argument(
        "-w",
        "--write-files",
        dest="write_files",
        action="store_true",
        help="Save discovered files to local output directory",
    )
    out.add_argument(
        "-x", "--skip-parsing", dest="skip_parsing", action="store_true", help="Don't extract users from passwd files"
    )
    out.add_argument(
        "-i", "--invalid-ssl", dest="invalid_ssl", action="store_true", help="Ignore SSL certificate validation errors"
    )
    out.add_argument(
        "-a", "--auto", dest="automatic", action="store_true", help="Avoid user interaction by using default options"
    )
    out.add_argument(
        "--output-format",
        dest="output_format",
        choices=["text", "json", "csv"],
        default=None,
        help="Output format (default: text)",
    )
    out.add_argument("--output-file", dest="output_file", help="Write results to file")
    out.add_argument("--log-file", dest="log_file", help="Save console output to file")
    out.add_argument("--resume-file", dest="resume_file", help="Resume file for checkpoint/restart")

    # Other
    parser.add_argument("--load", dest="list_file", help="Test custom file list from FILE")
    parser.add_argument("--config", dest="config_file", help="Path to TOML config file")
    parser.add_argument("--update", action="store_true", help="Update from GitHub repository")
    parser.add_argument(
        "--list-all-files",
        dest="list_all_files",
        action="store_true",
        help="List all file paths in the case database and exit",
    )

    parsed = parser.parse_args(argv)
    result = vars(parsed)

    # Remove args at their argparse defaults so they don't override config file values.
    # ScanConfig defaults will apply when these keys are absent from both CLI and file config.
    _ARGPARSE_DEFAULTS = {
        "path_based": False,
        "write_files": False,
        "skip_parsing": False,
        "invalid_ssl": False,
        "automatic": False,
        "all_versions": False,
        "random_agent": False,
        "ignore_proxy": False,
        "verbose": False,
        "follow_redirects": False,
        "quiet": False,
        "base64_encode": False,
        "prefix": "",
        "postfix": "",
        "multiplier": 1,
    }
    for key, default in _ARGPARSE_DEFAULTS.items():
        if result.get(key) == default:
            result.pop(key, None)

    # Normalize URL
    if result.get("url") and not result["url"].lower().startswith(("http://", "https://")):
        result["url"] = normalize_url(result["url"])

    # Apply prefix multiplier
    if result.get("prefix"):
        result["prefix"] = result["prefix"] * result.get("multiplier", 1)

    # Parse --random-delay "MIN-MAX" into tuple
    if result.get("random_delay") and isinstance(result["random_delay"], str):
        try:
            parts = result["random_delay"].split("-")
            result["random_delay"] = (float(parts[0]), float(parts[1]))
        except (ValueError, IndexError):
            print("[!] Invalid --random-delay format. Use 'MIN-MAX' (e.g. '0.5-2.0')", file=sys.stderr)
            sys.exit(1)

    if result.get("random_delay") and isinstance(result["random_delay"], tuple):
        min_val, max_val = result["random_delay"]
        if min_val < 0 or max_val < 0:
            print("[!] --random-delay values must be non-negative", file=sys.stderr)
            sys.exit(1)
        if min_val >= max_val:
            print("[!] --random-delay MIN must be less than MAX", file=sys.stderr)
            sys.exit(1)

    for code_key in ("match_codes", "filter_codes"):
        if result.get(code_key) and isinstance(result[code_key], str):
            try:
                codes = [int(c.strip()) for c in result[code_key].split(",")]
                for code in codes:
                    if not 100 <= code <= 599:
                        raise ValueError(f"HTTP status code out of range: {code}")
                result[code_key] = codes
            except ValueError as e:
                flag = "--match-code" if code_key == "match_codes" else "--filter-code"
                print(f"[!] Invalid {flag}: {e}", file=sys.stderr)
                sys.exit(1)

    return result


def validate_args(args: dict[str, Any]) -> None:
    """Validate parsed arguments, exiting on errors."""
    # Must have at least one action
    if not any((args.get("url"), args.get("list"), args.get("update"), args.get("list_all_files"))):
        print(
            "[!] Missing required argument: specify --url, --list, --update, or --list-all-files (try --help)",
            file=sys.stderr,
        )
        sys.exit(1)

    # URL scheme validation
    if args.get("url"):
        try:
            validate_url_scheme(args["url"])
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)

    # Concurrency validation
    if args.get("concurrency") is not None and args["concurrency"] < 1:
        print("[!] --concurrency must be at least 1", file=sys.stderr)
        sys.exit(1)

    if args.get("timeout") is not None and args["timeout"] <= 0:
        print("[!] --timeout must be greater than 0", file=sys.stderr)
        sys.exit(1)
    if args.get("delay") is not None and args["delay"] < 0:
        print("[!] --delay must be non-negative", file=sys.stderr)
        sys.exit(1)

    # Proxy scheme validation
    if args.get("proxy"):
        allowed_proxy_schemes = ("http://", "https://", "socks4://", "socks5://")
        if not args["proxy"].lower().startswith(allowed_proxy_schemes):
            print("[!] Invalid proxy scheme. Use http://, https://, socks4://, or socks5://", file=sys.stderr)
            sys.exit(1)

    # Header CRLF validation
    for hdr in args.get("headers") or []:
        try:
            validate_header(hdr)
        except ValueError as e:
            print(f"[!] Invalid header: {e}", file=sys.stderr)
            sys.exit(1)

    # Cookie CRLF validation
    if args.get("cookie") and any(c in args["cookie"] for c in "\r\n"):
        print("[!] Cookie contains CRLF characters (possible header injection)", file=sys.stderr)
        sys.exit(1)

    # User-Agent CRLF validation
    if args.get("user_agent") and any(c in args["user_agent"] for c in "\r\n"):
        print("[!] User-Agent contains CRLF characters (possible header injection)", file=sys.stderr)
        sys.exit(1)


async def run(argv: list[str] | None = None) -> None:
    """Main async entry point — parse args, load config, dispatch."""
    args = parse_args(argv)
    validate_args(args)

    # Handle non-scan commands
    if args.get("update"):
        from panoptic.update import do_update

        do_update()
        return

    if args.get("list_all_files"):
        import json as json_mod

        from panoptic.cases import list_all_files

        paths = list_all_files()
        fmt = args.get("output_format") or "text"

        if fmt == "json":
            print(json_mod.dumps(paths, indent=2))
        elif fmt == "csv":
            print("path")
            for path in paths:
                print(path)
        else:
            for path in paths:
                print(path)
        return

    if args.get("list"):
        import json as json_mod

        from panoptic.cases import list_values
        from panoptic.config import load_config, merge_config

        _file_config = load_config(args.get("config_file"))
        _config = merge_config({k: v for k, v in args.items() if v is not None}, _file_config)
        values = list_values(args["list"], config=_config)
        fmt = args.get("output_format") or "text"

        if fmt == "json":
            print(json_mod.dumps(sorted(values), indent=2))
        elif fmt == "csv":
            print(args["list"])
            for val in sorted(values):
                print(val)
        else:
            print(f"Available {args['list']} values ({len(values)}):")
            for val in sorted(values):
                print(f"  {val}")
        return

    # Load config and merge
    from panoptic.config import load_config, merge_config

    file_config = load_config(args.pop("config_file", None))
    config = merge_config(args, file_config)

    # Shared URL parsing for param detection and ext-param validation
    import re
    from urllib.parse import urlsplit

    parsed = urlsplit(config.url)
    params = config.data if config.data else parsed.query

    # Check if FUZZ marker is used in any injectable position
    has_fuzz = "FUZZ" in (config.data or "") or any("FUZZ" in h for h in (config.headers or []))

    # Auto-detect vulnerable parameter if not specified (ported from original)
    if not config.path_based and not config.param and not has_fuzz:
        match = re.match(r"(?P<param>[^=&]+)=(?P<value>[^&]+)", params)
        if match:
            config = config.replace(param=match.group("param"))
        else:
            print("[!] No usable GET/POST parameters found.", file=sys.stderr)
            print("[!] If this is a path-based URL, use --path-based", file=sys.stderr)
            sys.exit(1)

    # Validate --ext-param exists in query/data (anchored to prevent substring matches)
    if config.ext_param and not re.search(
        rf"(?:^|(?<=&)){re.escape(config.ext_param)}=(?P<value>[^&]*)",
        params,
    ):
        print(f"[!] Extension parameter '{config.ext_param}' not found.", file=sys.stderr)
        sys.exit(1)

    # Dispatch to scanner
    from panoptic.core import Scanner

    scanner = Scanner(config)
    await scanner.run()
