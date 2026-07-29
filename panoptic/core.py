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
import time
from dataclasses import fields as dataclass_fields
from pathlib import Path
from typing import TextIO
from urllib.parse import quote as url_quote
from urllib.parse import urlsplit

import httpx
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
from panoptic.models import Case, OutputFormat, ScanConfig, ScanResult
from panoptic.network import NetworkClient
from panoptic.output import CsvFormatter, JsonFormatter, TeeWriter, TextFormatter
from panoptic.parsers import extract_binlog_cases, extract_home_file_cases
from panoptic.update import get_revision
from panoptic.utils import (
    generate_invalid_filename,
    get_random_agent,
    normalize_os_name,
    open_secure_write,
    os_matches_restriction,
    redact_url,
    replace_parameter_value,
    sanitize_filename,
    validate_header,
)

PASSWD_FILES = frozenset({"/etc/passwd", "/etc/security/passwd"})
FUZZ_MARKER = "FUZZ"
CHECKPOINT_VERSION = 1
_CHECKPOINT_CONFIG_EXCLUSIONS = frozenset(
    {
        # These options change execution mechanics or presentation, not which
        # cases and responses constitute the scan.
        "concurrency",
        "timeout",
        "retries",
        "delay",
        "random_delay",
        "write_files",
        "output_format",
        "output_file",
        "log_file",
        "verbose",
        "quiet",
        "resume_file",
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


def _encode_param_value(value: str, *, is_post: bool = False) -> str:
    """URL-encode chars that would corrupt a query/form body.

    Safe chars (not encoded):
      /       : LFI path traversal separators must stay literal
      %       : Preserve pre-encoded sequences (e.g., --replace-slash "%2F")
    The plus sign is always encoded because standard query and form parsers
    decode a literal '+' as a space, corrupting some Base64 payloads.
    """
    return url_quote(value, safe="/%")


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


def _substitute_fuzz(template: str, replacement: str, *, is_post: bool) -> str:
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
        return template.replace(FUZZ_MARKER, _encode_param_value(replacement, is_post=is_post))
    return template.replace(FUZZ_MARKER, replacement)


def build_payload(config: ScanConfig, location: str, request_params: str) -> str:
    """Build the request payload/URL for a given file location."""
    full_path = process_path(config, location)

    parsed = urlsplit(config.url)

    if config.path_based:
        path = parsed.path
        query_suffix = f"?{parsed.query}" if parsed.query else ""
        last_slash = path.rfind("/")
        if last_slash >= 0:
            base_path = path[:last_slash]
            return f"{parsed.scheme}://{parsed.netloc}{base_path}/{full_path.lstrip('/')}{query_suffix}"
        return f"{parsed.scheme}://{parsed.netloc}/{full_path.lstrip('/')}{query_suffix}"

    is_post = bool(config.data)
    result = request_params
    if FUZZ_MARKER in result:
        result = _substitute_fuzz(result, full_path, is_post=is_post)
    elif config.ext_param and config.param and "." in full_path:
        # When ext_param is set, split path into base and extension
        path_without_ext, ext = full_path.rsplit(".", 1)
        encoded_path = _encode_param_value(path_without_ext, is_post=is_post)
        encoded_ext = _encode_param_value(ext, is_post=is_post)
        result = replace_parameter_value(result, config.param, encoded_path)
        result = replace_parameter_value(result, config.ext_param, encoded_ext)
    elif config.param:
        encoded_full_path = _encode_param_value(full_path, is_post=is_post)
        result = replace_parameter_value(result, config.param, encoded_full_path)

    if config.data:
        return result
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{result}"


def checkpoint_fingerprint(config: ScanConfig, cases: list[Case]) -> str:
    """Hash all scan-defining inputs without storing credentials in the checkpoint."""
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
    serialized = json.dumps(scan_definition, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


def save_checkpoint(filepath: str, completed_ids: set[str], fingerprint: str = "") -> None:
    """Save completed case IDs to a checkpoint file atomically."""
    dir_name = os.path.dirname(filepath) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "version": CHECKPOINT_VERSION,
                    "fingerprint": fingerprint,
                    "completed_ids": sorted(completed_ids),
                },
                f,
            )
        os.replace(tmp_path, filepath)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def _load_checkpoint_data(
    filepath: str,
    expected_fingerprint: str | None = None,
) -> tuple[set[str], bool]:
    """Load checkpoint IDs and report whether the file uses the legacy format."""
    if not os.path.exists(filepath):
        return set(), False
    with open(filepath, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as exc:
            raise ValueError("checkpoint is not valid JSON") from exc

    if isinstance(data, list):
        if not all(isinstance(case_id, str) for case_id in data):
            raise ValueError("legacy checkpoint must be a list of strings")
        return set(data), True
    if not isinstance(data, dict):
        raise ValueError("checkpoint must be an object or legacy list")
    if data.get("version") != CHECKPOINT_VERSION:
        raise ValueError(f"unsupported checkpoint version: {data.get('version')!r}")

    fingerprint = data.get("fingerprint")
    if not isinstance(fingerprint, str):
        raise ValueError("checkpoint fingerprint is missing or invalid")
    if expected_fingerprint is not None and fingerprint != expected_fingerprint:
        raise ValueError("checkpoint belongs to a different scan configuration")

    completed_ids = data.get("completed_ids")
    if not isinstance(completed_ids, list) or not all(isinstance(case_id, str) for case_id in completed_ids):
        raise ValueError("checkpoint completed_ids must be a list of strings")
    return set(completed_ids), False


def load_checkpoint(filepath: str, expected_fingerprint: str | None = None) -> set[str]:
    """Load completed case IDs from a current or legacy checkpoint file."""
    return _load_checkpoint_data(filepath, expected_fingerprint)[0]


class Scanner:
    """Async scanner using Queue + workers for concurrent file probing."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._parsed_url = urlsplit(config.url)
        self._base_url = f"{self._parsed_url.scheme}://{self._parsed_url.netloc}{self._parsed_url.path}"
        self.results: list[ScanResult] = []
        self.original_response: str = ""
        self.invalid_response: str = ""
        self.invalid_status_code: int = 0
        self.invalid_filename: str = ""
        # Canonicalize OS aliases (e.g. "OSX" -> "OS X") so the runtime restriction
        # compares against the same canonical OS labels parse_cases assigns to cases;
        # otherwise an aliased --os would load cases and then skip every one of them.
        self.restrict_os = normalize_os_name(config.os_filter)
        self.first_found = False
        self._first_found_lock = asyncio.Lock()
        self.completed_ids: set[str] = set()
        self.enqueued_ids: set[str] = set()
        self.total_queued = 0
        self.total_processed = 0
        self.total_failed = 0
        self.operational_errors: list[str] = []
        self._checkpoint_dirty = False
        self._last_checkpoint_time = 0.0
        self._checkpoint_lock = asyncio.Lock()
        self._checkpoint_fingerprint = ""
        self._checkpoint_disabled = False
        self._pause_lock = asyncio.Lock()

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
                print(f"[!] Cannot open log file '{self.config.log_file}': {exc}", file=sys.stderr)
                self._write_output([], TextFormatter(sys.stderr, quiet=self.config.quiet))
                return 2
            stderr_stream = TeeWriter(sys.stderr, log_fp)  # type: ignore[assignment]

        try:
            try:
                return await self._run_scan(stderr_stream, __version__)
            except (OSError, ValueError, httpx.HTTPError) as exc:
                text_out = TextFormatter(stderr_stream, quiet=self.config.quiet)
                text_out.write_warning(f"Scan failed: {exc}")
                self._write_output([], text_out)
                return 2
        finally:
            if log_fp:
                log_fp.close()

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

        if self.config.random_agent and not self.config.user_agent:
            self.config = self.config.replace(user_agent=get_random_agent())
            text_out.write_info(f"Using random User-Agent: {self.config.user_agent}")

        self._checkpoint_fingerprint = checkpoint_fingerprint(self.config, cases)

        if self.config.resume_file:
            try:
                self.completed_ids, legacy_checkpoint = _load_checkpoint_data(
                    self.config.resume_file,
                    self._checkpoint_fingerprint,
                )
            except (OSError, ValueError) as exc:
                text_out.write_warning(f"Ignoring resume checkpoint: {exc}")
                self.completed_ids = set()
            else:
                valid_case_ids = {case.case_id for case in cases}
                self.completed_ids.intersection_update(valid_case_ids)
                if legacy_checkpoint:
                    text_out.write_warning(
                        "Legacy checkpoint has no scan fingerprint; "
                        "only IDs matching the current case set were accepted"
                    )
            if self.completed_ids:
                text_out.write_info(f"Resuming: {len(self.completed_ids)} cases already completed")

        request_params = self.config.data or self._parsed_url.query

        text_out.write_info(f"Starting scan at: {time.strftime('%X')}")
        text_out.write_info("Checking original response...")

        async with NetworkClient(self.config) as client:
            orig_resp = await self._fetch(client, self._base_url, self.config.data or self.config.url)
            if orig_resp is None:
                text_out.write_warning("Cannot connect to target. Check connection settings.")
                self._write_output([], text_out)
                return 2
            self.original_response = orig_resp.text

            self.invalid_filename = generate_invalid_filename()
            invalid_payload = build_payload(self.config, self.invalid_filename, request_params)
            inv_fuzz_hdrs = self._fuzz_headers(self.invalid_filename)
            inv_resp = await self._fetch(client, self._base_url, invalid_payload, headers=inv_fuzz_hdrs)

            if inv_resp is None:
                text_out.write_warning("Cannot retrieve invalid response baseline.")
                self._write_output([], text_out)
                return 2
            self.invalid_response = inv_resp.text
            self.invalid_status_code = inv_resp.status_code

            text_out.write_info(f"Scanning {len(cases)} file paths with {self.config.concurrency} workers...\n")

            queue: asyncio.Queue[Case] = asyncio.Queue()
            for case in cases:
                if case.case_id not in self.completed_ids:
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
                        except (asyncio.TimeoutError, TimeoutError):
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
                            message = f"Case '{case.location}' failed: {exc}"
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
                finally:
                    await self._flush_checkpoint()
                    stop_event.set()
                    worker_results = await asyncio.gather(*worker_tasks, return_exceptions=True)
                    for result in worker_results:
                        if isinstance(result, BaseException):
                            self.operational_errors.append(f"Worker terminated unexpectedly: {result}")
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
            text_out.write_warning(f"{self.total_failed} requests failed and were not checkpointed")
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
        if self.config.random_delay:
            delay = random.uniform(*self.config.random_delay)
            await asyncio.sleep(delay)
        elif self.config.delay > 0:
            await asyncio.sleep(self.config.delay)

        if not os_matches_restriction(case.os, self.restrict_os):
            # OS-filtered cases are marked complete so they are not retried on resume
            await self._mark_completed(case)
            return True

        payload_str = build_payload(self.config, case.location, request_params)

        if self.config.verbose:
            text_out.write_verbose(f"Trying '{case.location}'")

        fuzz_hdrs = self._fuzz_headers(case.location)
        response = await self._fetch(client, self._base_url, payload_str, headers=fuzz_hdrs)

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

        cleaned_html = clean_response(html, case.location)
        cleaned_invalid = clean_response(self.invalid_response, self.invalid_filename)

        if is_match(cleaned_html, cleaned_invalid, self.config.heuristic_ratio):
            result = ScanResult(
                case=case,
                found=True,
                url=payload_str,
                status_code=response.status_code,
                content=html if self.config.write_files else None,
                content_length=len(html),
            )
            self.results.append(result)
            text_out.write_found(result)

            async with self._first_found_lock:
                if not self.first_found:
                    self.first_found = True
                    if case.os and not self.restrict_os:
                        if self.config.automatic:
                            self.restrict_os = case.os
                            text_out.write_info(f"Automatically restricting to OS: {case.os}")
                        else:
                            # Hold pause lock to block other workers during prompt
                            async with self._pause_lock:
                                if progress is not None:
                                    progress.stop()
                                try:
                                    try:
                                        answer = await asyncio.to_thread(
                                            input,
                                            f"[?] Restrict further scans to '{case.os}'? [Y/n] ",
                                        )
                                    except EOFError:
                                        # EOF means there is no interactive user
                                        # available to approve narrowing the scan.
                                        answer = "n"
                                    if answer.strip().lower() in ("", "y", "yes"):
                                        self.restrict_os = case.os
                                finally:
                                    if progress is not None:
                                        progress.start()

            if self.config.write_files and html:
                self._write_file(case, html)

            if not self.config.skip_parsing:
                if case.location in PASSWD_FILES:
                    await self._enqueue_new_cases(extract_home_file_cases(html, case), queue)
                if "mysql-bin.index" in case.location:
                    await self._enqueue_new_cases(extract_binlog_cases(html, case), queue)

        await self._mark_completed(case)
        return True

    def _fuzz_headers(self, location: str) -> dict[str, str] | None:
        """Build per-request headers with FUZZ replaced, or None if no FUZZ in headers."""
        if not self.config.headers:
            return None

        fuzz_hdrs: dict[str, str] = {}
        processed = process_path(self.config, location)
        for hdr in self.config.headers:
            name, value = validate_header(hdr, warn_deprecated=False)
            if FUZZ_MARKER not in value:
                continue
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
        base_url: str,
        payload: str,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response | None:
        """Fetch using POST if config.data is set, otherwise GET."""
        if self.config.data:
            return await client.fetch(base_url, data=payload, headers=headers)
        return await client.fetch(payload, headers=headers)

    async def _mark_completed(self, case: Case) -> None:
        """Record a case as completed for resume/checkpoint support."""
        self.completed_ids.add(case.case_id)
        if self.config.resume_file and not self._checkpoint_disabled:
            self._checkpoint_dirty = True
            now = time.monotonic()
            if now - self._last_checkpoint_time >= 5.0:
                async with self._checkpoint_lock:
                    if time.monotonic() - self._last_checkpoint_time >= 5.0:
                        await self._flush_checkpoint()

    async def _flush_checkpoint(self) -> None:
        """Flush checkpoint to disk if dirty."""
        if self._checkpoint_dirty and self.config.resume_file and not self._checkpoint_disabled:
            # Snapshot exactly what is being persisted. completed_ids grows while
            # the blocking save runs in a worker thread; if a case completes during
            # the save the snapshot will not contain it, so the dirty flag must stay
            # set to guarantee the newer ID is flushed on the next write.
            snapshot = self.completed_ids.copy()
            try:
                await asyncio.to_thread(
                    save_checkpoint,
                    self.config.resume_file,
                    snapshot,
                    self._checkpoint_fingerprint,
                )
            except OSError as exc:
                self._checkpoint_disabled = True
                self._checkpoint_dirty = False
                self.operational_errors.append(f"Checkpoint disabled after write failure: {exc}")
            else:
                self._last_checkpoint_time = time.monotonic()
                # completed_ids only ever grows, so a size change means new IDs
                # landed during the save and still need to be written.
                if len(self.completed_ids) == len(snapshot):
                    self._checkpoint_dirty = False

    async def _enqueue_new_cases(self, cases: list[Case], queue: asyncio.Queue[Case]) -> None:
        """Add newly discovered cases to the queue, skipping duplicates."""
        for case in cases:
            cid = case.case_id
            if cid not in self.completed_ids and cid not in self.enqueued_ids:
                await queue.put(case)
                self.enqueued_ids.add(cid)
                self.total_queued += 1

    def _write_file(self, case: Case, html: str) -> None:
        """Write discovered file content to local output directory."""
        try:
            base = (Path.cwd() / "output").resolve()
            host = self._parsed_url.hostname or "unknown-host"
            if self._parsed_url.port:
                host = f"{host}_{self._parsed_url.port}"
            output_dir = (base / sanitize_filename(host)).resolve()
            if not output_dir.is_relative_to(base):
                raise ValueError(f"Unsafe output directory: {output_dir}")
            output_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            output_dir.chmod(0o700)

            sanitized = sanitize_filename(case.location)
            # Always include case_id suffix to prevent collisions from paths that
            # sanitize identically (e.g. /foo/bar and /foo:bar both → foo_bar).
            suffix = f"_{case.case_id[:8]}.txt"
            # Cap filename length to stay within filesystem limits (typically 255 bytes).
            max_name_len = 255 - len(suffix)
            if len(sanitized) > max_name_len:
                sanitized = sanitized[:max_name_len]
            filename = f"{sanitized}{suffix}"
            filepath = output_dir / filename

            content = filter_content(html, self.original_response) if self.original_response else html

            # open_secure_write uses the strongest final-component symlink and
            # permission hardening exposed by the current platform.
            with open_secure_write(str(filepath)) as stream:
                stream.write(content)
        except (OSError, ValueError) as exc:
            print(f"[!] Warning: could not write file for '{case.location}': {exc}", file=sys.stderr)
