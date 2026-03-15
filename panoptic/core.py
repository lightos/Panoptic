"""Async scanner orchestrator for Panoptic.

Uses asyncio.Queue + worker pool for concurrent scanning with
dynamic case injection (passwd users, binlog files).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import re
import time
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
from panoptic.heuristic import (
    SKIP_RETRIEVE_THRESHOLD,
    clean_response,
    filter_content,
    is_match,
)
from panoptic.models import Case, OutputFormat, ScanConfig, ScanResult
from panoptic.network import NetworkClient
from panoptic.output import CsvFormatter, JsonFormatter, TeeWriter, TextFormatter
from panoptic.parsers import extract_binlog_cases, extract_home_file_cases
from panoptic.utils import (
    generate_invalid_filename,
    get_random_agent,
    redact_url,
    sanitize_filename,
)

PASSWD_FILES = ["/etc/passwd", "/etc/security/passwd"]
FUZZ_MARKER = "FUZZ"


def process_path(config: ScanConfig, location: str) -> str:
    """Apply all path transformations (prefix, postfix, replace_slash, base64)."""
    if config.replace_slash:
        location = location.replace("/", config.replace_slash)

    prefix = config.prefix
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
    GET-specific safe: = and + (base64 compat, PHP $_GET handles natively)
    POST-specific: + MUST be encoded as %2B (decoded as space by form parsers)
    """
    if is_post:
        return url_quote(value, safe="=/%")
    return url_quote(value, safe="=+/%")


def build_payload(config: ScanConfig, location: str, request_params: str) -> str:
    """Build the request payload/URL for a given file location."""
    full_path = process_path(config, location)

    if config.path_based:
        parsed = urlsplit(config.url)
        path = parsed.path
        last_slash = path.rfind("/")
        if last_slash >= 0:
            base_path = path[:last_slash]
            return f"{parsed.scheme}://{parsed.netloc}{base_path}/{full_path}"
        return f"{parsed.scheme}://{parsed.netloc}/{full_path}"

    is_post = bool(config.data)
    result = request_params
    if FUZZ_MARKER in result:
        result = result.replace(FUZZ_MARKER, full_path)
    elif config.ext_param and config.param and "." in full_path:
        # When ext_param is set, split path into base and extension
        path_without_ext, ext = full_path.rsplit(".", 1)
        encoded_path = _encode_param_value(path_without_ext, is_post=is_post)
        encoded_ext = _encode_param_value(ext, is_post=is_post)
        result = re.sub(
            rf"(?:^|(?<=&)){re.escape(config.param)}=(?P<value>[^&]*)",
            rf"{config.param}={encoded_path}",
            result,
        )
        result = re.sub(
            rf"(?:^|(?<=&)){re.escape(config.ext_param)}=(?P<value>[^&]*)",
            rf"{config.ext_param}={encoded_ext}",
            result,
        )
    elif config.param:
        encoded_full_path = _encode_param_value(full_path, is_post=is_post)
        result = re.sub(
            rf"(?:^|(?<=&)){re.escape(config.param)}=(?P<value>[^&]*)",
            rf"{config.param}={encoded_full_path}",
            result,
        )

    parsed = urlsplit(config.url)
    if config.data:
        return result
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{result}"


def save_checkpoint(filepath: str, completed_ids: set[str]) -> None:
    """Save completed case IDs to a checkpoint file atomically."""
    import contextlib
    import tempfile

    dir_name = os.path.dirname(filepath) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sorted(completed_ids), f)
        os.replace(tmp_path, filepath)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def load_checkpoint(filepath: str) -> set[str]:
    """Load completed case IDs from a checkpoint file."""
    if not os.path.exists(filepath):
        return set()
    try:
        with open(filepath, encoding="utf-8") as f:
            return set(json.load(f))
    except (json.JSONDecodeError, OSError):
        return set()


class Scanner:
    """Async scanner using Queue + workers for concurrent file probing."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.results: list[ScanResult] = []
        self.original_response: str = ""
        self.invalid_response: str = ""
        self.invalid_status_code: int = 0
        self.invalid_filename: str = ""
        self.restrict_os: str | None = config.os_filter
        self.first_found = False
        self._first_found_lock = asyncio.Lock()
        self.completed_ids: set[str] = set()
        self.enqueued_ids: set[str] = set()
        self.total_queued = 0
        self.total_processed = 0
        self._checkpoint_dirty = False
        self._last_checkpoint_time = 0.0
        self._checkpoint_lock = asyncio.Lock()
        self._pause_lock = asyncio.Lock()

    async def run(self) -> None:
        """Execute the full scan workflow."""
        import sys

        from panoptic import __version__

        # Set up log file tee if configured
        log_fp = None
        stderr_stream: TextIO = sys.stderr
        if self.config.log_file:
            log_fp = open(self.config.log_file, "w", encoding="utf-8")  # noqa: SIM115
            stderr_stream = TeeWriter(sys.stderr, log_fp)  # type: ignore[assignment]

        try:
            await self._run_scan(stderr_stream, __version__)
        finally:
            if log_fp:
                log_fp.close()

    async def _run_scan(self, stderr_stream: TextIO, version: str) -> None:
        """Execute the scan with the given output stream."""
        text_out = TextFormatter(stderr_stream, quiet=self.config.quiet)

        # Show git revision in banner if available
        from panoptic.update import get_revision

        rev = get_revision()
        banner_version = f"{version}-{rev}" if rev else version
        text_out.write_banner(banner_version, redact_url(self.config.url))

        if self.config.random_agent and not self.config.user_agent:
            self.config = self.config.replace(user_agent=get_random_agent())
            text_out.write_info(f"Using random User-Agent: {self.config.user_agent}")

        if self.config.invalid_ssl:
            text_out.write_warning("SSL certificate verification is disabled. Traffic is vulnerable to MITM.")

        cases = load_custom_list(self.config.list_file) if self.config.list_file else parse_cases(self.config)

        if not cases:
            text_out.write_warning("No available test cases with the specified attributes.")
            return

        if self.config.resume_file:
            self.completed_ids = load_checkpoint(self.config.resume_file)
            if self.completed_ids:
                text_out.write_info(f"Resuming: {len(self.completed_ids)} cases already completed")

        parsed = urlsplit(self.config.url)
        request_params = self.config.data or parsed.query

        text_out.write_info(f"Starting scan at: {time.strftime('%X')}")
        text_out.write_info("Checking original response...")

        async with NetworkClient(self.config) as client:
            base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
            orig_resp = await self._fetch(client, base_url, self.config.data or self.config.url)
            if orig_resp is None:
                text_out.write_warning("Cannot connect to target. Check connection settings.")
                return
            self.original_response = orig_resp.text

            self.invalid_filename = generate_invalid_filename()
            invalid_payload = build_payload(self.config, self.invalid_filename, request_params)
            inv_fuzz_hdrs = self._fuzz_headers(self.invalid_filename)
            inv_resp = await self._fetch(client, base_url, invalid_payload, headers=inv_fuzz_hdrs)

            if inv_resp is None:
                text_out.write_warning("Cannot retrieve invalid response baseline.")
                return
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
                            await self._process_case(case, client, request_params, queue, scan_out, progress_ctx)
                            self.total_processed += 1
                            # Update progress bar total when dynamic cases are added
                            if progress_ctx is not None and progress_task_id is not None:
                                progress_ctx.update(
                                    progress_task_id, total=self.total_queued, completed=self.total_processed
                                )
                        finally:
                            queue.task_done()

                worker_tasks = [asyncio.create_task(worker()) for _ in range(self.config.concurrency)]

                # Wait until all enqueued work (including dynamically injected) is done
                try:
                    await queue.join()
                finally:
                    await self._flush_checkpoint()
                    stop_event.set()
                    await asyncio.gather(*worker_tasks, return_exceptions=True)
            finally:
                if progress_ctx is not None:
                    progress_ctx.stop()

        elapsed = time.monotonic() - scan_start
        rps = self.total_processed / elapsed if elapsed > 0 else 0
        text_out.write_info(f"Scan completed in {elapsed:.1f}s ({rps:.0f} req/s)")

        found_results = [r for r in self.results if r.found]

        if not found_results:
            text_out.write_info("No files found!")
        else:
            text_out.write_summary(found_results, self.total_processed)

        text_out.write_info(f"Finishing scan at: {time.strftime('%X')}")

        if self.config.output_format != OutputFormat.TEXT or self.config.output_file:
            import sys

            def _write_output(stream: TextIO) -> None:
                match self.config.output_format:
                    case OutputFormat.JSON:
                        JsonFormatter(stream).write_results(found_results)
                    case OutputFormat.CSV:
                        CsvFormatter(stream).write_results(found_results)
                    case OutputFormat.TEXT:
                        TextFormatter(stream).write_summary(found_results, self.total_processed)

            if self.config.output_file:
                with open(self.config.output_file, "w", encoding="utf-8") as stream:
                    _write_output(stream)
            else:
                _write_output(sys.stdout)

    async def _process_case(
        self,
        case: Case,
        client: NetworkClient,
        request_params: str,
        queue: asyncio.Queue[Case],
        text_out: TextFormatter,
        progress: Progress | None = None,
    ) -> None:
        """Process a single case: fetch, compare, record result."""
        if self.config.random_delay:
            delay = random.uniform(*self.config.random_delay)
            await asyncio.sleep(delay)
        elif self.config.delay > 0:
            await asyncio.sleep(self.config.delay)

        if self.restrict_os and case.os and case.os != self.restrict_os:
            # OS-filtered cases are marked complete so they are not retried on resume
            await self._mark_completed(case)
            return

        parsed = urlsplit(self.config.url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        payload_str = build_payload(self.config, case.location, request_params)

        if self.config.verbose:
            text_out.write_verbose(f"Trying '{case.location}'")

        fuzz_hdrs = self._fuzz_headers(case.location)
        response = await self._fetch(client, base_url, payload_str, headers=fuzz_hdrs)

        if response is None:
            # Network failure: do NOT checkpoint so the case is retried on resume
            return

        # Skip responses where the server returned a different error class than
        # the baseline. E.g. baseline returns 200 (PHP warning) but this path
        # gets a 403/404 from the web server before the app even runs — that's
        # not a found file, it's a different error page.
        if response.status_code // 100 != self.invalid_status_code // 100 and response.status_code >= 400:
            await self._mark_completed(case)
            return

        # User-specified status code filtering
        if self.config.filter_codes and response.status_code in self.config.filter_codes:
            await self._mark_completed(case)
            return
        if self.config.match_codes and response.status_code not in self.config.match_codes:
            await self._mark_completed(case)
            return

        # Content-Length skip optimization: if response is much larger than baseline
        # and we're not writing files, classify as found by status alone
        try:
            content_length = int(response.headers.get("content-length", 0))
        except (ValueError, TypeError):
            content_length = 0
        baseline_length = max(len(self.original_response), len(self.invalid_response))
        if (
            not self.config.write_files
            and not self.config.match_string
            and content_length > 0
            and content_length - baseline_length > SKIP_RETRIEVE_THRESHOLD
        ):
            result = ScanResult(
                case=case,
                found=True,
                url=payload_str,
                status_code=response.status_code,
                content_length=content_length,
            )
            self.results.append(result)
            text_out.write_found(result)
            await self._mark_completed(case)
            return

        html = response.text

        if self.config.bad_string and self.config.bad_string in html:
            await self._mark_completed(case)
            return

        if self.config.match_string and self.config.match_string not in html:
            await self._mark_completed(case)
            return

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
                                    answer = await asyncio.to_thread(
                                        input,
                                        f"[?] Restrict further scans to '{case.os}'? [Y/n] ",
                                    )
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

    def _fuzz_headers(self, location: str) -> dict[str, str] | None:
        """Build per-request headers with FUZZ replaced, or None if no FUZZ in headers."""
        if not self.config.headers:
            return None
        from panoptic.utils import validate_header

        fuzz_hdrs: dict[str, str] = {}
        processed = process_path(self.config, location)
        for hdr in self.config.headers:
            if FUZZ_MARKER in hdr:
                name, value = validate_header(hdr)
                fuzz_hdrs[name] = value.replace(FUZZ_MARKER, processed)
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
        if self.config.resume_file:
            self._checkpoint_dirty = True
            now = time.monotonic()
            if now - self._last_checkpoint_time >= 5.0:
                async with self._checkpoint_lock:
                    if time.monotonic() - self._last_checkpoint_time >= 5.0:
                        await self._flush_checkpoint()

    async def _flush_checkpoint(self) -> None:
        """Flush checkpoint to disk if dirty."""
        if self._checkpoint_dirty and self.config.resume_file:
            await asyncio.to_thread(
                save_checkpoint,
                self.config.resume_file,
                self.completed_ids.copy(),
            )
            self._checkpoint_dirty = False
            self._last_checkpoint_time = time.monotonic()

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
        parsed = urlsplit(self.config.url)
        base = (Path.cwd() / "output").resolve()
        output_dir = (base / parsed.netloc.replace(":", "_")).resolve()
        if not str(output_dir).startswith(str(base)):
            raise ValueError(f"Unsafe output directory: {output_dir}")
        output_dir.mkdir(parents=True, exist_ok=True)

        sanitized = sanitize_filename(case.location)
        # Include case_id suffix when traversal markers were stripped,
        # since different traversal depths produce identical sanitized names.
        filename = f"{sanitized}_{case.case_id[:8]}.txt" if ".." in case.location else f"{sanitized}.txt"
        filepath = output_dir / filename

        content = filter_content(html, self.original_response) if self.original_response else html

        filepath.write_text(content, encoding="utf-8")
