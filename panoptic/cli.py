"""Command-line interface for Panoptic.

Handles argument parsing, validation, and dispatch to scan/list/update modes.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlsplit

from rich_argparse import RawDescriptionRichHelpFormatter

from panoptic.utils import (
    has_parameter,
    normalize_url,
    open_secure_write,
    parse_status_codes,
    validate_header,
    validate_url_scheme,
)

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
    conn.add_argument(
        "--ignore-proxy",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Bypass system proxy settings",
    )
    conn.add_argument(
        "--random-agent",
        action=argparse.BooleanOptionalAction,
        default=None,
        dest="random_agent",
        help="Choose random User-Agent",
    )
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
        action=argparse.BooleanOptionalAction,
        default=None,
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
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Target file paths directly instead of query parameters",
    )
    scan.add_argument("-d", "--data", help="Send parameters via POST instead of GET")
    scan.add_argument("-t", "--type", dest="type_filter", help="Filter by type ('conf', 'log', 'other')")
    scan.add_argument("--prefix", default=None, help="Add prefix to file paths (e.g. '../')")
    scan.add_argument("--postfix", default=None, help="Add suffix to file paths (e.g. '%%00')")
    scan.add_argument("--multiplier", type=int, default=None, help="Repeat prefix N times (default: 1)")
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
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Base64-encode file paths before injection (for endpoints that decode)",
    )
    scan.add_argument("--ext-param", dest="ext_param", help="Name of parameter containing file extension")
    scan.add_argument(
        "--all-versions",
        dest="all_versions",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Test all versioned file paths",
    )

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
    out.add_argument(
        "-v",
        "--verbose",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Show detailed information",
    )
    out.add_argument(
        "-q",
        "--quiet",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Suppress banner, info, and progress — only show findings and warnings",
    )
    out.add_argument(
        "-w",
        "--write-files",
        dest="write_files",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Save discovered files to local output directory",
    )
    out.add_argument(
        "-x",
        "--skip-parsing",
        dest="skip_parsing",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Don't extract users from passwd files",
    )
    out.add_argument(
        "-i",
        "--invalid-ssl",
        dest="invalid_ssl",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Ignore SSL certificate validation errors",
    )
    out.add_argument(
        "-a",
        "--auto",
        dest="automatic",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="Avoid user interaction by using default options",
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
    from panoptic import __version__

    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument(
        "--list-all-files",
        dest="list_all_files",
        action="store_true",
        help="List all file paths in the case database and exit",
    )

    parsed = parser.parse_args(argv)
    result = vars(parsed)

    # Normalize URL
    if result.get("url") and not result["url"].lower().startswith(("http://", "https://")):
        result["url"] = normalize_url(result["url"])

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
                result[code_key] = parse_status_codes(result[code_key])
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
    if args.get("retries") is not None and args["retries"] < 0:
        print("[!] --retries must be non-negative", file=sys.stderr)
        sys.exit(1)
    if args.get("multiplier") is not None and args["multiplier"] < 1:
        print("[!] --multiplier must be at least 1", file=sys.stderr)
        sys.exit(1)

    if args.get("timeout") is not None and args["timeout"] <= 0:
        print("[!] --timeout must be greater than 0", file=sys.stderr)
        sys.exit(1)
    if args.get("delay") is not None and args["delay"] < 0:
        print("[!] --delay must be non-negative", file=sys.stderr)
        sys.exit(1)

    # Proxy scheme validation
    if args.get("proxy"):
        # SOCKS4 is intentionally excluded: httpx (via socksio) only supports
        # SOCKS5, so accepting socks4:// here would fail later at connection time.
        allowed_proxy_schemes = ("http://", "https://", "socks5://", "socks5h://")
        if not args["proxy"].lower().startswith(allowed_proxy_schemes):
            print(
                "[!] Invalid proxy scheme. Use http://, https://, socks5://, or socks5h://",
                file=sys.stderr,
            )
            sys.exit(1)
        parsed_proxy = urlsplit(args["proxy"])
        if not parsed_proxy.hostname:
            print("[!] Proxy URL must include a hostname", file=sys.stderr)
            sys.exit(1)
        try:
            proxy_port = parsed_proxy.port
        except ValueError as exc:
            print(f"[!] Invalid proxy port: {exc}", file=sys.stderr)
            sys.exit(1)
        del proxy_port

    # Header CRLF validation
    for hdr in args.get("headers") or []:
        try:
            validate_header(hdr, warn_deprecated=False)
        except ValueError as e:
            print(f"[!] Invalid header: {e}", file=sys.stderr)
            sys.exit(1)

    # Cookie CRLF validation
    if args.get("cookie") and any(c in args["cookie"] for c in "\r\n\x00"):
        print("[!] Cookie contains CRLF/NUL characters (possible header injection)", file=sys.stderr)
        sys.exit(1)

    # User-Agent CRLF validation
    if args.get("user_agent") and any(c in args["user_agent"] for c in "\r\n\x00"):
        print("[!] User-Agent contains CRLF/NUL characters (possible header injection)", file=sys.stderr)
        sys.exit(1)

    if args.get("quiet") and args.get("verbose"):
        print("[!] --quiet and --verbose cannot be used together", file=sys.stderr)
        sys.exit(1)

    if args.get("base64_encode") and args.get("ext_param"):
        print("[!] --base64 and --ext-param cannot be combined", file=sys.stderr)
        sys.exit(1)

    match_codes = set(args.get("match_codes") or [])
    filter_codes = set(args.get("filter_codes") or [])
    overlap = sorted(match_codes & filter_codes)
    if overlap:
        print(f"[!] Status codes cannot be both matched and filtered: {overlap}", file=sys.stderr)
        sys.exit(1)

    output_paths = [args.get(key) for key in ("output_file", "log_file", "resume_file")]
    normalized_paths = [str(Path(path).expanduser().resolve()) for path in output_paths if path]
    if len(normalized_paths) != len(set(normalized_paths)):
        print("[!] --output-file, --log-file, and --resume-file must use different paths", file=sys.stderr)
        sys.exit(1)


def _write_list_output(values: list[str], header: str, fmt: str, output_file: str | None) -> int:
    """Write list command output using format-aware serialization."""
    stream = sys.stdout
    file_stream = None
    try:
        if output_file:
            file_stream = open_secure_write(output_file, newline="")
            stream = file_stream
        if fmt == "json":
            json.dump(values, stream, indent=2)
            stream.write("\n")
        elif fmt == "csv":
            writer = csv.writer(stream, lineterminator="\n")
            writer.writerow([header])
            writer.writerows([value] for value in values)
        else:
            for value in values:
                stream.write(f"{value}\n")
    except OSError as exc:
        print(f"[!] Cannot write output: {exc}", file=sys.stderr)
        return 2
    finally:
        if file_stream:
            file_stream.close()
    return 0


async def run(argv: list[str] | None = None) -> int:
    """Main async entry point — parse args, load config, dispatch."""
    args = parse_args(argv)

    # Handle non-scan commands
    if args.get("update"):
        from panoptic.update import do_update

        validate_args(args)
        return do_update()

    # Lazy import — only needed for scan and --list modes
    from panoptic.config import load_config, merge_config

    config_file = args.pop("config_file", None)
    file_config = load_config(config_file)

    if args.get("list_all_files"):
        from panoptic.cases import list_all_files

        validate_args(args)
        try:
            list_config = merge_config(args, file_config)
        except (TypeError, ValueError) as exc:
            print(f"[!] Invalid configuration: {exc}", file=sys.stderr)
            return 2
        return _write_list_output(
            list_all_files(),
            "path",
            list_config.output_format.value,
            list_config.output_file,
        )

    if args.get("list"):
        from panoptic.cases import list_values

        validate_args(args)
        try:
            _config = merge_config(args, file_config)
        except (TypeError, ValueError) as exc:
            print(f"[!] Invalid configuration: {exc}", file=sys.stderr)
            return 2
        values = list_values(args["list"], config=_config)
        fmt = _config.output_format.value
        sorted_values = sorted(values)
        if fmt == "text" and not _config.output_file:
            print(f"Available {args['list']} values ({len(values)}):")
            sorted_values = [f"  {value}" for value in sorted_values]
        return _write_list_output(sorted_values, args["list"], fmt, _config.output_file)

    try:
        config = merge_config(args, file_config)
    except (TypeError, ValueError) as exc:
        print(f"[!] Invalid configuration: {exc}", file=sys.stderr)
        return 2

    validate_args(vars(config))

    # Shared URL parsing for param detection and ext-param validation
    parsed = urlsplit(config.url)
    params = config.data if config.data else parsed.query

    # Check if FUZZ is used in an injectable body or header value. A header name
    # containing the literal text "FUZZ" is not an injection point.
    has_fuzz = "FUZZ" in (config.data or "") or any(
        "FUZZ" in validate_header(header, warn_deprecated=False)[1] for header in (config.headers or [])
    )

    # Auto-detect vulnerable parameter if not specified (ported from original)
    if not config.path_based and not config.param and not has_fuzz:
        detected_param = next(
            (name for name, value in parse_qsl(params, keep_blank_values=True) if name and value),
            None,
        )
        if detected_param:
            config = config.replace(param=detected_param)
        else:
            print("[!] No usable GET/POST parameters found.", file=sys.stderr)
            print("[!] If this is a path-based URL, use --path-based", file=sys.stderr)
            return 1

    if not config.path_based and config.param and not has_fuzz and not has_parameter(params, config.param):
        print(f"[!] Parameter '{config.param}' not found in query/POST form data.", file=sys.stderr)
        if config.data:
            print("[!] For JSON or opaque POST bodies, place FUZZ at the injection point.", file=sys.stderr)
        return 1

    # Validate --ext-param against decoded or raw query/form parameter names.
    if config.ext_param and not has_parameter(params, config.ext_param):
        print(f"[!] Extension parameter '{config.ext_param}' not found.", file=sys.stderr)
        return 1

    # Dispatch to scanner
    from panoptic.core import Scanner

    scanner = Scanner(config)
    return await scanner.run()
