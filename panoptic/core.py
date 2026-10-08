"""Async scanner orchestrator for Panoptic.

Uses asyncio.Queue + worker pool for concurrent scanning with
dynamic case injection (passwd users, binlog files).
"""

from __future__ import annotations

import asyncio
import base64
import contextlib
import hashlib
import json
import os
import random
import sys
import tempfile
import threading
import time
from collections import Counter
from dataclasses import dataclass, field
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import TextIO
from urllib.parse import quote as url_quote
from urllib.parse import urlsplit, urlunsplit

from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)

from panoptic.cases import load_custom_list, parse_cases
from panoptic.heuristic import clean_response, filter_content, is_match
from panoptic.models import Case, FileType, OutputFormat, ScanConfig, ScanResult
from panoptic.network import NetworkClient, Response
from panoptic.output import CsvFormatter, JsonFormatter, TeeWriter, TextFormatter
from panoptic.parsers import extract_binlog_cases, extract_home_file_cases
from panoptic.update import get_revision
from panoptic.utils import (
    escape_control_chars,
    generate_invalid_filename,
    get_random_agent,
    normalize_os_name,
    open_secure_write,
    os_matches_restriction,
    redact_url,
    redact_urls_in_text,
    replace_parameter_value,
    sanitize_filename,
    validate_header,
)

PASSWD_FILES = frozenset({"/etc/passwd", "/etc/security/passwd"})
FUZZ_MARKER = "FUZZ"
# Bump whenever the stored data changes meaning (3: content_length in bytes).
CHECKPOINT_VERSION = 3
# Maximum UTF-8 byte length of a file name written by --write-files.
MAX_OUTPUT_FILENAME_BYTES = 200
_CHECKPOINT_CONFIG_EXCLUSIONS = frozenset(
    {
        # These options change execution mechanics or presentation, not which
        # cases and responses constitute the scan.
        "concurrency",
        "timeout",
        "retries",
        "delay",
        "random_delay",
        "output_format",
        "output_file",
        "log_file",
        "verbose",
        "quiet",
        "resume_file",
        "output_dir",
        # Connection settings that don't change who the scan runs as: a
        # randomized User-Agent or a different proxy must not prevent a resume.
        # Cookie and headers stay in (hashed) because they can carry identity.
        "user_agent",
        "random_agent",
        "proxy",
        "ignore_proxy",
        "invalid_ssl",
    }
)


def process_path(config: ScanConfig, location: str) -> str:
    """Apply all path transformations (prefix, postfix, replace_slash, base64)."""
    if config.replace_slash:
        location = location.replace("/", config.replace_slash)

    prefix = config.prefix * config.multiplier
    if prefix.endswith("/") and location.startswith("/"):
        location = location.lstrip("/")
    full_path = f"{prefix}{location}{config.postfix}"

    if config.base64_encode:
        full_path = base64.b64encode(full_path.encode()).decode()

    return full_path


def _encode_param_value(value: str) -> str:
    """URL-encode chars that would corrupt a query/form body.

    Safe chars (not encoded):
      /       : LFI path traversal separators must stay literal
      %       : Preserve pre-encoded sequences (e.g., --replace-slash "%2F")
    The plus sign is always encoded because standard query and form parsers
    decode a literal '+' as a space, corrupting some Base64 payloads.
    """
    return url_quote(value, safe="/%")


def _split_extension(full_path: str, replace_slash: str | None) -> tuple[str, str]:
    """Split a path into (path without extension, extension) on its basename only.

    Returns an empty extension when the basename has no dot.
    """
    separators = ["/", "\\"]
    if replace_slash:
        separators.append(replace_slash)
    basename_start = 0
    for separator in separators:
        index = full_path.rfind(separator)
        if index >= 0:
            basename_start = max(basename_start, index + len(separator))
    dot = full_path.rfind(".", basename_start)
    if dot < 0:
        return full_path, ""
    return full_path[:dot], full_path[dot + 1 :]


def _replace_fuzz_in_json(obj: object, replacement: str) -> object:
    """Recursively replace the FUZZ marker in every JSON string key and value."""
    if isinstance(obj, dict):
        return {
            (k.replace(FUZZ_MARKER, replacement) if isinstance(k, str) else k): _replace_fuzz_in_json(v, replacement)
            for k, v in obj.items()
        }
    if isinstance(obj, list):
        return [_replace_fuzz_in_json(v, replacement) for v in obj]
    if isinstance(obj, str):
        return obj.replace(FUZZ_MARKER, replacement)
    return obj


def _substitute_fuzz(template: str, replacement: str) -> str:
    """Replace the FUZZ marker while keeping the surrounding body well-formed.

    A JSON body is parsed and re-serialized so injected Windows paths, backslashes,
    and quotes stay valid JSON. A form-encoded body/query has the replacement
    percent-encoded so plus signs and delimiters (``&``, ``=``) cannot corrupt the
    structure. Any other (opaque) body keeps the raw, user-controlled substitution.
    """
    if template.lstrip().startswith(("{", "[")):
        try:
            obj = json.loads(template)
        except (json.JSONDecodeError, ValueError):
            pass
        else:
            return json.dumps(_replace_fuzz_in_json(obj, replacement), separators=(",", ":"))
    if "=" in template:
        return template.replace(FUZZ_MARKER, _encode_param_value(replacement))
    return template.replace(FUZZ_MARKER, replacement)


def build_payload(config: ScanConfig, location: str, request_params: str) -> str:
    """Build the request payload/URL for a given file location.

    In path-based mode the result is always a URL, requested with GET and its
    path sent verbatim so ``../`` traversal segments reach the target.
    """
    full_path = process_path(config, location)

    parsed = urlsplit(config.url)

    if config.path_based:
        path = parsed.path
        query_suffix = f"?{parsed.query}" if parsed.query else ""
        traversal = full_path.lstrip("/")
        last_slash = path.rfind("/")
        if last_slash >= 0:
            base_path = path[:last_slash]
            return f"{parsed.scheme}://{parsed.netloc}{base_path}/{traversal}{query_suffix}"
        return f"{parsed.scheme}://{parsed.netloc}/{traversal}{query_suffix}"

    result = request_params
    if FUZZ_MARKER in result:
        result = _substitute_fuzz(result, full_path)
    elif config.ext_param and config.param:
        # When ext_param is set, split the basename into name and extension; a
        # basename without a dot sends the whole path and an empty extension.
        path_without_ext, ext = _split_extension(full_path, config.replace_slash)
        result = replace_parameter_value(result, config.param, _encode_param_value(path_without_ext))
        result = replace_parameter_value(result, config.ext_param, _encode_param_value(ext))
    elif config.param:
        encoded_full_path = _encode_param_value(full_path)
        result = replace_parameter_value(result, config.param, encoded_full_path)

    if config.data:
        return result
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{result}"


def checkpoint_fingerprint(config: ScanConfig, cases: list[Case]) -> str:
    """Hash all scan-defining inputs without storing credentials in the checkpoint.

    Only a SHA-256 digest is stored, so cookie and header values (which can
    change the identity the scan runs as) are bound without being persisted.
    User-Agent, proxy and SSL settings are excluded so a re-drawn random
    User-Agent doesn't reject a resume. ``write_files`` is included because
    restored findings carry no file content to write.
    """
    # Include new ScanConfig fields by default. A future option cannot silently
    # become resume-unsafe merely because this function was not updated.
    scan_definition = {
        field.name: getattr(config, field.name)
        for field in dataclass_fields(config)
        if field.name not in _CHECKPOINT_CONFIG_EXCLUSIONS
    }
    # Status code order does not affect scan semantics.
    for code_field in ("match_codes", "filter_codes"):
        if scan_definition[code_field] is not None:
            scan_definition[code_field] = sorted(set(scan_definition[code_field]))
    scan_definition["os_filter"] = normalize_os_name(scan_definition["os_filter"])
    scan_definition["case_ids"] = sorted(case.case_id for case in cases)
    serialized = json.dumps(scan_definition, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(serialized.encode()).hexdigest()


def _case_to_dict(case: Case) -> dict[str, str | None]:
    return {
        "location": case.location,
        "os": case.os,
        "category": case.category,
        "software": case.software,
        "file_type": case.file_type.value if case.file_type else None,
    }


def _case_from_dict(obj: object) -> Case:
    if not isinstance(obj, dict):
        raise ValueError("checkpoint case must be an object")
    location = obj.get("location")
    if not isinstance(location, str):
        raise ValueError("checkpoint case location must be a string")
    values = {key: obj.get(key) for key in ("os", "category", "software", "file_type")}
    for key, value in values.items():
        if value is not None and not isinstance(value, str):
            raise ValueError(f"checkpoint case {key} must be a string or null")
    file_type = values["file_type"]
    return Case(
        location=location,
        os=values["os"],
        category=values["category"],
        software=values["software"],
        file_type=FileType(file_type) if file_type is not None else None,
    )


def _result_to_dict(result: ScanResult) -> dict[str, object]:
    # The request URL is not stored (it may embed credentials or session
    # tokens); it is rebuilt from the case and configuration on resume.
    return {
        "case": _case_to_dict(result.case),
        "status_code": result.status_code,
        "content_length": result.content_length,
        "timestamp": result.timestamp,
    }


def _result_from_dict(obj: object) -> ScanResult:
    if not isinstance(obj, dict):
        raise ValueError("checkpoint result must be an object")
    status_code = obj.get("status_code")
    content_length = obj.get("content_length")
    timestamp = obj.get("timestamp")
    for name, value in (("status_code", status_code), ("content_length", content_length)):
        if value is not None and (not isinstance(value, int) or isinstance(value, bool)):
            raise ValueError(f"checkpoint result {name} must be an integer or null")
    if not isinstance(timestamp, str):
        raise ValueError("checkpoint result timestamp must be a string")
    return ScanResult(
        case=_case_from_dict(obj.get("case")),
        found=True,
        url="",
        status_code=status_code,
        content_length=content_length,
        timestamp=timestamp,
    )


@dataclass
class CheckpointState:
    """Everything restored from a checkpoint file."""

    completed_ids: set[str] = field(default_factory=set)
    results: list[ScanResult] = field(default_factory=list)
    injected_cases: list[Case] = field(default_factory=list)
    restrict_os: str | None = None


def save_checkpoint(
    filepath: str,
    completed_ids: set[str],
    fingerprint: str = "",
    *,
    results: list[ScanResult] | None = None,
    injected_cases: list[Case] | None = None,
    restrict_os: str | None = None,
) -> None:
    """Save scan progress to a checkpoint file atomically.

    Besides the completed case IDs, the checkpoint keeps previously found
    results (without content or URL), dynamically injected cases (from parsed
    /etc/passwd or binlog hits) and a runtime OS restriction, so a resumed scan
    reports earlier findings and still probes derived cases.
    """
    dir_name = os.path.dirname(filepath) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "version": CHECKPOINT_VERSION,
                    "fingerprint": fingerprint,
                    "completed_ids": sorted(completed_ids),
                    "results": [_result_to_dict(result) for result in results or []],
                    "injected_cases": [_case_to_dict(case) for case in injected_cases or []],
                    "restrict_os": restrict_os,
                },
                f,
            )
        os.replace(tmp_path, filepath)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _load_checkpoint_data(filepath: str, expected_fingerprint: str | None = None) -> CheckpointState:
    """Load a checkpoint file written by this version of Panoptic.

    Files with any other format or version are rejected with ValueError.
    """
    if not os.path.exists(filepath):
        return CheckpointState()
    with open(filepath, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError("checkpoint is not valid JSON") from exc

    if not isinstance(data, dict) or data.get("version") != CHECKPOINT_VERSION:
        raise ValueError("checkpoint is from an incompatible version")

    fingerprint = data.get("fingerprint")
    if not isinstance(fingerprint, str):
        raise ValueError("checkpoint fingerprint is missing or invalid")
    if expected_fingerprint is not None and fingerprint != expected_fingerprint:
        raise ValueError("checkpoint belongs to a different scan configuration")

    completed_ids = data.get("completed_ids")
    if not isinstance(completed_ids, list) or not all(isinstance(case_id, str) for case_id in completed_ids):
        raise ValueError("checkpoint completed_ids must be a list of strings")
    raw_results = data.get("results")
    raw_injected = data.get("injected_cases")
    if not isinstance(raw_results, list) or not isinstance(raw_injected, list):
        raise ValueError("checkpoint results and injected_cases must be lists")
    restrict_os = data.get("restrict_os")
    if restrict_os is not None and not isinstance(restrict_os, str):
        raise ValueError("checkpoint restrict_os must be a string or null")
    return CheckpointState(
        completed_ids=set(completed_ids),
        results=[_result_from_dict(item) for item in raw_results],
        injected_cases=[_case_from_dict(item) for item in raw_injected],
        restrict_os=restrict_os,
    )


def load_checkpoint(filepath: str, expected_fingerprint: str | None = None) -> set[str]:
    """Load completed case IDs from a checkpoint file."""
    return _load_checkpoint_data(filepath, expected_fingerprint).completed_ids


def _truncate_utf8(value: str, max_bytes: int) -> str:
    """Truncate a string so its UTF-8 encoding fits in max_bytes, without splitting a character."""
    encoded = value.encode("utf-8")
    if len(encoded) <= max_bytes:
        return value
    return encoded[:max_bytes].decode("utf-8", errors="ignore")


def _format_error_counts(counts: object) -> str:
    """Format NetworkClient.error_counts as "ReadTimeout: 3, ConnectError: 1"."""
    if not isinstance(counts, Counter) or not counts:
        return ""
    return ", ".join(f"{name}: {count}" for name, count in counts.most_common())


async def _interruptible_input(prompt: str) -> str:
    """Read a line from stdin without blocking interpreter or event-loop shutdown.

    ``asyncio.to_thread`` runs on the default executor, which ``asyncio.run``
    joins on shutdown; a thread stuck in ``input()`` would then hang Ctrl-C.
    A daemon thread is not joined, so cancelling this coroutine returns at once.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future[str] = loop.create_future()

    def _deliver(result: str | None, error: BaseException | None) -> None:
        if future.done():
            return
        if error is not None:
            future.set_exception(error)
        else:
            future.set_result(result or "")

    def _read() -> None:
        try:
            answer = input(prompt)
        except BaseException as exc:  # relayed to the awaiting coroutine
            outcome: tuple[str | None, BaseException | None] = (None, exc)
        else:
            outcome = (answer, None)
        with contextlib.suppress(RuntimeError):  # event loop already closed
            loop.call_soon_threadsafe(_deliver, *outcome)

    threading.Thread(target=_read, name="panoptic-prompt", daemon=True).start()
    return await future


class Scanner:
    """Async scanner using Queue + workers for concurrent file probing."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._parsed_url = urlsplit(config.url)
        # POST targets the full configured URL (query string included); only the
        # fragment, which is never sent, is stripped.
        self._post_url = urlunsplit(self._parsed_url._replace(fragment=""))
        # Path-based mode always encodes the payload in the URL path, so it is
        # requested with GET even when --data is supplied.
        self._use_post = bool(config.data) and not config.path_based
        self.results: list[ScanResult] = []
        self.original_response: str = ""
        self.invalid_response: str = ""
        self.invalid_status_code: int = 0
        self.invalid_filename: str = ""
        self._cleaned_invalid: str = ""
        self._cleaned_invalid_key: tuple[str, str] | None = None
        # Canonicalize OS aliases (e.g. "OSX" -> "OS X") so the runtime restriction
        # compares against the same canonical OS labels parse_cases assigns to cases;
        # otherwise an aliased --os would load cases and then skip every one of them.
        self.restrict_os = normalize_os_name(config.os_filter)
        self.first_found = False
        self._first_found_lock = asyncio.Lock()
        self.completed_ids: set[str] = set()
        self.enqueued_ids: set[str] = set()
        # Cases derived at runtime (passwd home files, binlogs), keyed by case ID.
        self.injected_cases: dict[str, Case] = {}
        self.total_queued = 0
        self.total_processed = 0
        self.total_failed = 0
        self.operational_errors: list[str] = []
        self._checkpoint_dirty = False
        self._last_checkpoint_time = 0.0
        self._checkpoint_lock = asyncio.Lock()
        self._checkpoint_fingerprint = ""
        self._checkpoint_disabled = False
        # Checkpoint saves run in worker threads that keep running if their task
        # is cancelled; a sequence number under a thread lock guarantees an older
        # snapshot never overwrites a newer one.
        self._checkpoint_seq = 0
        self._checkpoint_written_seq = 0
        self._checkpoint_write_lock = threading.Lock()
        self._pause_lock = asyncio.Lock()
        self._fuzz_header_templates = self._parse_fuzz_headers()

    def _parse_fuzz_headers(self) -> list[tuple[str, str]]:
        """Parse --header values containing the FUZZ marker once."""
        templates: list[tuple[str, str]] = []
        for hdr in self.config.headers or []:
            try:
                name, value = validate_header(hdr, warn_deprecated=False)
            except ValueError:
                # Invalid headers are rejected when the HTTP client is built.
                continue
            if FUZZ_MARKER in value:
                templates.append((name, value))
        return templates

    async def run(self) -> int:
        """Execute the full scan workflow."""
        from panoptic import __version__

        # Set up log file tee if configured
        log_fp = None
        stderr_stream: TextIO = sys.stderr
        if self.config.log_file:
            try:
                log_fp = open_secure_write(self.config.log_file)
            except OSError as exc:
                print(
                    f"[!] Cannot open log file '{escape_control_chars(self.config.log_file)}': "
                    f"{escape_control_chars(str(exc))}",
                    file=sys.stderr,
                )
                self._write_output([], TextFormatter(sys.stderr, quiet=self.config.quiet))
                return 2
            stderr_stream = TeeWriter(sys.stderr, log_fp)  # type: ignore[assignment]

        try:
            try:
                return await self._run_scan(stderr_stream, __version__)
            except (OSError, ValueError) as exc:
                text_out = TextFormatter(stderr_stream, quiet=self.config.quiet)
                # Exception messages (notably network errors) can embed the request
                # or proxy URL, including userinfo credentials and query tokens.
                text_out.write_warning(f"Scan failed: {redact_urls_in_text(str(exc))}")
                self._write_output([], text_out)
                return 2
        finally:
            if log_fp:
                log_fp.close()

    def _restore_checkpoint(self, cases: list[Case], request_params: str, text_out: TextFormatter) -> None:
        """Restore completed IDs, earlier findings and injected cases from --resume."""
        assert self.config.resume_file is not None
        try:
            state = _load_checkpoint_data(self.config.resume_file, self._checkpoint_fingerprint)
        except (OSError, ValueError) as exc:
            text_out.write_warning(f"Ignoring resume checkpoint ({exc}); starting fresh")
            self.completed_ids = set()
            return

        base_ids = {case.case_id for case in cases}
        self.injected_cases = {case.case_id: case for case in state.injected_cases if case.case_id not in base_ids}
        valid_case_ids = base_ids | self.injected_cases.keys()
        self.completed_ids = state.completed_ids & valid_case_ids
        restored = [result for result in state.results if result.case.case_id in self.completed_ids]
        for result in restored:
            result.url = build_payload(self.config, result.case.location, request_params)
        self.results.extend(restored)
        if state.restrict_os and not self.restrict_os:
            self.restrict_os = state.restrict_os
        if self.restrict_os != normalize_os_name(self.config.os_filter) or any(r.case.os for r in restored):
            # The OS-restriction decision was already made in the earlier run.
            self.first_found = True

        if self.completed_ids:
            text_out.write_info(f"Resuming: {len(self.completed_ids)} cases already completed")
        if restored:
            text_out.write_info(f"Restored {len(restored)} previously found files")
        if state.restrict_os and self.restrict_os == state.restrict_os and not self.config.os_filter:
            text_out.write_info(f"Restored OS restriction: {self.restrict_os}")

    async def _run_scan(self, stderr_stream: TextIO, version: str) -> int:
        """Execute the scan with the given output stream."""
        text_out = TextFormatter(stderr_stream, quiet=self.config.quiet)

        # Show git revision in banner if available
        rev = get_revision()
        banner_version = f"{version}-{rev}" if rev else version
        text_out.write_banner(banner_version, redact_url(self.config.url), self.config)

        if self.config.invalid_ssl:
            text_out.write_warning("SSL certificate verification is disabled. Traffic is vulnerable to MITM.")

        cases = load_custom_list(self.config.list_file) if self.config.list_file else parse_cases(self.config)

        if not cases:
            text_out.write_warning("No available test cases with the specified attributes.")
            self._write_output([], text_out)
            return 2

        # Fingerprint before any runtime-only config change (e.g. random agent).
        self._checkpoint_fingerprint = checkpoint_fingerprint(self.config, cases)

        if self.config.random_agent:
            if self.config.user_agent:
                text_out.write_warning("--random-agent ignored because a User-Agent is already configured")
            else:
                self.config = self.config.replace(user_agent=get_random_agent())
                text_out.write_info(f"Using random User-Agent: {self.config.user_agent}")

        request_params = self.config.data or self._parsed_url.query

        if self.config.resume_file:
            self._restore_checkpoint(cases, request_params, text_out)

        text_out.write_info(f"Starting scan at: {time.strftime('%X')}")
        text_out.write_info("Checking original response...")

        async with NetworkClient(self.config) as client:
            orig_payload = self.config.data if self._use_post else self.config.url
            orig_resp = await self._fetch(client, orig_payload or self.config.url)
            if orig_resp is None:
                text_out.write_warning("Cannot connect to target. Check connection settings.")
                self._write_output([], text_out)
                return 2
            self.original_response = orig_resp.text

            self.invalid_filename = generate_invalid_filename()
            invalid_payload = build_payload(self.config, self.invalid_filename, request_params)
            inv_fuzz_hdrs = self._fuzz_headers(self.invalid_filename)
            inv_resp = await self._fetch(client, invalid_payload, headers=inv_fuzz_hdrs)

            if inv_resp is None:
                text_out.write_warning("Cannot retrieve invalid response baseline.")
                self._write_output([], text_out)
                return 2
            self.invalid_response = inv_resp.text
            self.invalid_status_code = inv_resp.status_code
            # Clean the invalid baseline once, off the event loop.
            await asyncio.to_thread(self._get_cleaned_invalid)

            text_out.write_info(f"Scanning {len(cases)} file paths with {self.config.concurrency} workers...\n")

            queue: asyncio.Queue[Case] = asyncio.Queue()
            # Restored injected cases are re-queued after the base case set.
            for case in [*cases, *self.injected_cases.values()]:
                if case.case_id not in self.completed_ids and case.case_id not in self.enqueued_ids:
                    await queue.put(case)
                    self.enqueued_ids.add(case.case_id)
                    self.total_queued += 1

            # Use a stop event + queue.join() to safely handle dynamic case injection.
            # Workers block on queue.get() and only exit when signaled after all work is done.
            stop_event = asyncio.Event()

            scan_start = time.monotonic()
            progress_ctx: Progress | None = None
            progress_task_id = None
            if not self.config.quiet:
                from rich.console import Console as RichConsole

                progress_ctx = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    console=RichConsole(file=stderr_stream, highlight=False),
                    transient=True,
                )
                progress_ctx.start()
                progress_task_id = progress_ctx.add_task("Scanning", total=self.total_queued)
                scan_out = TextFormatter(console=progress_ctx.console, quiet=False)
            else:
                scan_out = TextFormatter(stderr_stream, quiet=True)

            try:

                async def worker() -> None:
                    while not stop_event.is_set():
                        try:
                            case = await asyncio.wait_for(queue.get(), timeout=0.1)
                        except TimeoutError:
                            continue

                        try:
                            async with self._pause_lock:
                                pass  # Block while interactive prompt is active
                            processed = await self._process_case(
                                case,
                                client,
                                request_params,
                                queue,
                                scan_out,
                                progress_ctx,
                            )
                            if processed:
                                self.total_processed += 1
                            else:
                                self.total_failed += 1
                        except Exception as exc:
                            self.total_failed += 1
                            message = f"Case '{case.location}' failed: {redact_urls_in_text(str(exc))}"
                            self.operational_errors.append(message)
                            scan_out.write_warning(message)
                        finally:
                            queue.task_done()
                            # Update progress even for failed cases so the queue's
                            # completion state remains visible and accurate.
                            if progress_ctx is not None and progress_task_id is not None:
                                progress_ctx.update(
                                    progress_task_id,
                                    total=self.total_queued,
                                    completed=self.total_processed + self.total_failed,
                                )

                worker_tasks = [asyncio.create_task(worker()) for _ in range(self.config.concurrency)]

                # Wait until all enqueued work (including dynamically injected) is done
                try:
                    await queue.join()
                except BaseException:
                    # Interrupted (e.g. Ctrl-C): stop workers before the final
                    # checkpoint so none can record progress after it is taken.
                    for task in worker_tasks:
                        task.cancel()
                    raise
                finally:
                    stop_event.set()
                    worker_results = await asyncio.gather(*worker_tasks, return_exceptions=True)
                    for result in worker_results:
                        if isinstance(result, BaseException) and not isinstance(result, asyncio.CancelledError):
                            detail = redact_urls_in_text(str(result))
                            self.operational_errors.append(f"Worker terminated unexpectedly: {detail}")
                    # Hold the checkpoint lock so no concurrent flush can interleave.
                    async with self._checkpoint_lock:
                        await self._flush_checkpoint()
            finally:
                if progress_ctx is not None:
                    progress_ctx.stop()

        found_results = [r for r in self.results if r.found]

        if not found_results:
            text_out.write_info("No files found!")
        else:
            text_out.write_summary(found_results, self.total_processed)

        elapsed = time.monotonic() - scan_start
        rps = self.total_processed / elapsed if elapsed > 0 else 0
        text_out.write_info(f"Completed in {elapsed:.1f}s ({rps:.0f} req/s)")
        text_out.write_info(f"Finishing scan at: {time.strftime('%X')}")

        if self.total_failed:
            breakdown = _format_error_counts(getattr(client, "error_counts", None))
            details = f" (failed attempts: {breakdown})" if breakdown else ""
            text_out.write_warning(f"{self.total_failed} requests failed and were not checkpointed{details}")
        for error in self.operational_errors:
            if not error.startswith("Case '"):
                text_out.write_warning(error)

        output_ok = self._write_output(found_results, text_out)
        all_requests_failed = self.total_failed > 0 and self.total_processed == 0
        return 0 if output_ok and not all_requests_failed and not self.operational_errors else 2

    def _write_output(self, found_results: list[ScanResult], text_out: TextFormatter) -> bool:
        """Write configured machine/file output, including valid empty results on failure."""
        if self.config.output_format == OutputFormat.TEXT and not self.config.output_file:
            return True

        def write_to(stream: TextIO) -> None:
            match self.config.output_format:
                case OutputFormat.JSON:
                    JsonFormatter(stream).write_results(found_results)
                case OutputFormat.CSV:
                    CsvFormatter(stream).write_results(found_results)
                case OutputFormat.TEXT:
                    TextFormatter(stream).write_results(found_results, self.total_processed)

        try:
            if self.config.output_file:
                with open_secure_write(self.config.output_file, newline="") as stream:
                    write_to(stream)
            else:
                write_to(sys.stdout)
        except OSError as exc:
            text_out.write_warning(f"Cannot write output: {exc}")
            return False
        return True

    def _reflection_variants(self, location: str) -> tuple[str, ...]:
        """Return the forms in which a requested location may be echoed back.

        Covers the raw location, the transformed path actually sent (prefix,
        postfix, replace-slash, Base64) and its URL/JSON-encoded forms.
        """
        processed = process_path(self.config, location)
        variants = {
            location,
            processed,
            _encode_param_value(processed),
            url_quote(processed, safe=""),
            json.dumps(processed)[1:-1],
        }
        return tuple(variant for variant in variants if variant)

    def _get_cleaned_invalid(self) -> str:
        """Return the cleaned invalid baseline, computing it only when it changes."""
        key = (self.invalid_response, self.invalid_filename)
        if self._cleaned_invalid_key != key:
            self._cleaned_invalid = clean_response(
                self.invalid_response, *self._reflection_variants(self.invalid_filename)
            )
            self._cleaned_invalid_key = key
        return self._cleaned_invalid

    def _response_matches(self, html: str, location: str, cleaned_invalid: str) -> bool:
        """CPU-bound comparison of a response against the cleaned invalid baseline."""
        cleaned_html = clean_response(html, *self._reflection_variants(location))
        return is_match(cleaned_html, cleaned_invalid, self.config.heuristic_ratio)

    async def _process_case(
        self,
        case: Case,
        client: NetworkClient,
        request_params: str,
        queue: asyncio.Queue[Case],
        text_out: TextFormatter,
        progress: Progress | None = None,
    ) -> bool:
        """Process a single case: fetch, compare, record result."""
        if not os_matches_restriction(case.os, self.restrict_os):
            # OS-filtered cases are marked complete so they are not retried on resume.
            # Checked before any delay: skipped cases send no request to throttle.
            await self._mark_completed(case)
            return True

        if self.config.random_delay:
            delay = random.uniform(*self.config.random_delay)
            await asyncio.sleep(delay)
        elif self.config.delay > 0:
            await asyncio.sleep(self.config.delay)

        payload_str = build_payload(self.config, case.location, request_params)

        if self.config.verbose:
            text_out.write_verbose(f"Trying '{case.location}'")

        fuzz_hdrs = self._fuzz_headers(case.location)
        response = await self._fetch(client, payload_str, headers=fuzz_hdrs)

        if response is None:
            # Network failure: do NOT checkpoint so the case is retried on resume
            return False

        # User-specified status code filtering
        if self.config.filter_codes and response.status_code in self.config.filter_codes:
            await self._mark_completed(case)
            return True
        if self.config.match_codes and response.status_code not in self.config.match_codes:
            await self._mark_completed(case)
            return True

        # Unless the user explicitly selected status codes, skip responses where
        # the server returned a different error class than the invalid baseline.
        if (
            not self.config.match_codes
            and response.status_code // 100 != self.invalid_status_code // 100
            and response.status_code >= 400
        ):
            await self._mark_completed(case)
            return True

        html = response.text

        if self.config.bad_string and self.config.bad_string in html:
            await self._mark_completed(case)
            return True

        if self.config.match_string and self.config.match_string not in html:
            await self._mark_completed(case)
            return True

        cleaned_invalid = self._get_cleaned_invalid()
        # Cleaning and SequenceMatcher are CPU-bound; keep them off the event loop.
        if await asyncio.to_thread(self._response_matches, html, case.location, cleaned_invalid):
            result = ScanResult(
                case=case,
                found=True,
                url=payload_str,
                status_code=response.status_code,
                content=html if self.config.write_files else None,
                content_length=len(response.content),
            )
            self.results.append(result)
            text_out.write_found(result)

            async with self._first_found_lock:
                # Only an OS-specific hit decides the restriction; a hit on an
                # OS-agnostic case must not consume the one-time decision.
                if not self.first_found and case.os:
                    self.first_found = True
                    if not self.restrict_os:
                        await self._decide_os_restriction(case.os, text_out, progress)

            if self.config.write_files and html:
                self._write_file(case, html, text_out)

            if not self.config.skip_parsing:
                if case.location in PASSWD_FILES:
                    await self._enqueue_new_cases(extract_home_file_cases(html, case), queue)
                if "mysql-bin.index" in case.location:
                    await self._enqueue_new_cases(extract_binlog_cases(html, case), queue)

        await self._mark_completed(case)
        return True

    async def _decide_os_restriction(self, case_os: str, text_out: TextFormatter, progress: Progress | None) -> None:
        """Restrict further scanning to case_os, automatically or after asking."""
        if self.config.automatic:
            self.restrict_os = case_os
            text_out.write_info(f"Automatically restricting to OS: {case_os}")
            return

        # Hold pause lock to block other workers during prompt
        async with self._pause_lock:
            if progress is not None:
                progress.stop()
            try:
                try:
                    answer = await _interruptible_input(f"[?] Restrict further scans to '{case_os}'? [Y/n] ")
                except EOFError:
                    # EOF means there is no interactive user
                    # available to approve narrowing the scan.
                    answer = "n"
                if answer.strip().lower() in ("", "y", "yes"):
                    self.restrict_os = case_os
            finally:
                if progress is not None:
                    progress.start()

    def _fuzz_headers(self, location: str) -> dict[str, str] | None:
        """Build per-request headers with FUZZ replaced, or None if no FUZZ in headers."""
        if not self._fuzz_header_templates:
            return None

        fuzz_hdrs: dict[str, str] = {}
        processed = process_path(self.config, location)
        for name, value in self._fuzz_header_templates:
            substituted = value.replace(FUZZ_MARKER, processed)
            # Re-validate after substitution: case locations from custom
            # lists could inject control characters via the FUZZ marker.
            if any(c in substituted for c in "\r\n\x00"):
                continue
            fuzz_hdrs[name] = substituted
        return fuzz_hdrs or None

    async def _fetch(
        self,
        client: NetworkClient,
        payload: str,
        headers: dict[str, str] | None = None,
    ) -> Response | None:
        """POST ``payload`` as the body to the configured URL when --data is set
        (outside path-based mode); otherwise GET ``payload`` as the URL."""
        if self._use_post:
            return await client.fetch(self._post_url, data=payload, headers=headers)
        return await client.fetch(payload, headers=headers, raw_path=self.config.path_based)

    async def _mark_completed(self, case: Case) -> None:
        """Record a case as completed for resume/checkpoint support."""
        self.completed_ids.add(case.case_id)
        if self.config.resume_file and not self._checkpoint_disabled:
            self._checkpoint_dirty = True
            now = time.monotonic()
            if now - self._last_checkpoint_time >= 5.0:
                async with self._checkpoint_lock:
                    # Re-check: another worker may have flushed while we waited.
                    if now - self._last_checkpoint_time >= 5.0:
                        await self._flush_checkpoint()

    def _write_checkpoint_snapshot(
        self,
        seq: int,
        completed_ids: set[str],
        results: list[ScanResult],
        injected_cases: list[Case],
        restrict_os: str | None,
    ) -> None:
        """Persist a snapshot unless a newer one has already been written (worker thread)."""
        assert self.config.resume_file is not None
        with self._checkpoint_write_lock:
            if seq <= self._checkpoint_written_seq:
                return
            save_checkpoint(
                self.config.resume_file,
                completed_ids,
                self._checkpoint_fingerprint,
                results=results,
                injected_cases=injected_cases,
                restrict_os=restrict_os,
            )
            self._checkpoint_written_seq = seq

    async def _flush_checkpoint(self) -> None:
        """Flush checkpoint to disk if dirty."""
        if self._checkpoint_dirty and self.config.resume_file and not self._checkpoint_disabled:
            # Snapshot exactly what is being persisted. State grows while the
            # blocking save runs in a worker thread; if a case completes during
            # the save the snapshot will not contain it, so the dirty flag must stay
            # set to guarantee the newer state is flushed on the next write.
            self._checkpoint_seq += 1
            seq = self._checkpoint_seq
            snapshot = self.completed_ids.copy()
            found = [result for result in self.results if result.found]
            injected = list(self.injected_cases.values())
            try:
                await asyncio.to_thread(
                    self._write_checkpoint_snapshot,
                    seq,
                    snapshot,
                    found,
                    injected,
                    self.restrict_os,
                )
            except OSError as exc:
                self._checkpoint_disabled = True
                self._checkpoint_dirty = False
                self.operational_errors.append(f"Checkpoint disabled after write failure: {exc}")
            else:
                self._last_checkpoint_time = time.monotonic()
                # This state only ever grows, so a size change means new entries
                # landed during the save and still need to be written.
                if (
                    len(self.completed_ids) == len(snapshot)
                    and sum(1 for result in self.results if result.found) == len(found)
                    and len(self.injected_cases) == len(injected)
                ):
                    self._checkpoint_dirty = False

    async def _enqueue_new_cases(self, cases: list[Case], queue: asyncio.Queue[Case]) -> None:
        """Add newly discovered cases to the queue, skipping duplicates."""
        for case in cases:
            cid = case.case_id
            if cid not in self.completed_ids and cid not in self.enqueued_ids:
                await queue.put(case)
                self.enqueued_ids.add(cid)
                self.injected_cases.setdefault(cid, case)
                self.total_queued += 1

    def _write_file(self, case: Case, html: str, text_out: TextFormatter | None = None) -> None:
        """Write discovered file content to local output directory."""
        try:
            base = (Path.cwd() / Path(self.config.output_dir).expanduser()).resolve()
            host = self._parsed_url.hostname or "unknown-host"
            if self._parsed_url.port:
                host = f"{host}_{self._parsed_url.port}"
            output_dir = (base / sanitize_filename(host)).resolve()
            if not output_dir.is_relative_to(base):
                raise ValueError(f"Unsafe output directory: {output_dir}")
            output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            output_dir.chmod(0o700)

            # Always include case_id suffix to prevent collisions from paths that
            # sanitize identically (e.g. /foo/bar and /foo:bar both → foo_bar).
            suffix = f"_{case.case_id[:8]}.txt"
            # sanitize_filename already caps its output in UTF-8 bytes; cap again
            # here so the full name, suffix included, stays within
            # MAX_OUTPUT_FILENAME_BYTES without splitting a multibyte character.
            sanitized = _truncate_utf8(
                sanitize_filename(case.location),
                MAX_OUTPUT_FILENAME_BYTES - len(suffix.encode("utf-8")),
            )
            filename = f"{sanitized}{suffix}"
            filepath = output_dir / filename

            content = filter_content(html, self.original_response) if self.original_response else html

            # open_secure_write uses the strongest final-component symlink and
            # permission hardening exposed by the current platform.
            with open_secure_write(str(filepath)) as stream:
                stream.write(content)
        except (OSError, ValueError) as exc:
            (text_out or TextFormatter(sys.stderr)).write_warning(f"Could not write file for '{case.location}': {exc}")
