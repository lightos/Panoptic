"""Regression tests for scanner fixes (wire paths, resume, comparison, shutdown)."""

import asyncio
import base64
import io
import json
import threading
import time
from collections import Counter
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
from pytest_httpx import HTTPXMock

from panoptic.core import (
    MAX_OUTPUT_FILENAME_BYTES,
    Scanner,
    _format_error_counts,
    _interruptible_input,
    _load_checkpoint_data,
    build_payload,
    checkpoint_fingerprint,
    process_path,
    save_checkpoint,
)
from panoptic.heuristic import MAX_COMPARE_LENGTH, clean_response, is_match
from panoptic.models import Case, OutputFormat, ScanConfig, ScanResult
from panoptic.network import NetworkClient
from panoptic.output import TextFormatter
from panoptic.utils import redact_urls_in_text

PASSWD = "root:x:0:0:root:/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\n"


def _response(text: str, status: int = 200) -> MagicMock:
    response = MagicMock()
    response.text = text
    response.status_code = status
    return response


def _patched_client(client_cls: MagicMock) -> None:
    client_cls.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
    client_cls.return_value.__aexit__ = AsyncMock(return_value=None)


class TestPathBasedWire:
    async def test_traversal_survives_client_normalization(self, httpx_mock: HTTPXMock) -> None:
        """The bytes reaching the transport must keep every traversal segment."""
        config = ScanConfig(
            url="http://example.com/a/b/view",
            path_based=True,
            prefix="../",
            multiplier=5,
            retries=0,
        )
        httpx_mock.add_response(text="ok")
        scanner = Scanner(config)
        payload = build_payload(config, "/etc/passwd", "")
        async with NetworkClient(config) as client:
            assert await scanner._fetch(client, payload) is not None

        request = httpx_mock.get_requests()[0]
        assert request.url.raw_path == b"/a/b/" + b"../" * 5 + b"etc/passwd"
        assert request.method == "GET"

    async def test_path_based_with_data_uses_get(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com/a/view", path_based=True, data="x=1", retries=0)
        httpx_mock.add_response(text="ok")
        scanner = Scanner(config)
        payload = build_payload(config, "/etc/passwd", config.data or "")
        async with NetworkClient(config) as client:
            await scanner._fetch(client, payload)
        request = httpx_mock.get_requests()[0]
        assert request.method == "GET"
        assert request.url.raw_path == b"/a/etc/passwd"
        assert request.content == b""


class TestPostTarget:
    async def test_post_keeps_query_and_drops_fragment(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com/inc.php?token=abc#frag", param="file", data="file=x", retries=0)
        httpx_mock.add_response(text="ok")
        scanner = Scanner(config)
        async with NetworkClient(config) as client:
            await scanner._fetch(client, "file=%2Fetc%2Fpasswd")
        request = httpx_mock.get_requests()[0]
        assert request.method == "POST"
        assert request.url.raw_path == b"/inc.php?token=abc"
        assert request.content == b"file=%2Fetc%2Fpasswd"


class TestExtParam:
    def test_dot_in_directory_is_not_an_extension(self) -> None:
        config = ScanConfig(url="http://example.com/?file=x&ext=php", param="file", ext_param="ext")
        payload = build_payload(config, "/etc/nginx/conf.d/default", "file=x&ext=php")
        assert "file=/etc/nginx/conf.d/default" in payload
        assert payload.endswith("ext=")

    def test_basename_extension_is_split(self) -> None:
        config = ScanConfig(url="http://example.com/?file=x&ext=php", param="file", ext_param="ext")
        payload = build_payload(config, "/etc/conf.d/app.conf", "file=x&ext=php")
        assert "file=/etc/conf.d/app&" in payload
        assert payload.endswith("ext=conf")


class TestCheckpointResume:
    async def test_flush_persists_results_and_injected_cases(self, tmp_path: Path) -> None:
        checkpoint = str(tmp_path / "cp.json")
        scanner = Scanner(ScanConfig(url="http://example.com/?f=x", param="f", resume_file=checkpoint))
        scanner._checkpoint_fingerprint = "fp"
        passwd = Case(location="/etc/passwd", os="*NIX")
        derived = Case(location="/home/alice/.bashrc", os="*NIX")
        scanner.results.append(ScanResult(case=passwd, found=True, url="http://secret@x/", status_code=200))
        scanner.injected_cases[derived.case_id] = derived
        scanner.completed_ids.add(passwd.case_id)
        scanner._checkpoint_dirty = True
        await scanner._flush_checkpoint()

        raw = Path(checkpoint).read_text(encoding="utf-8")
        assert "secret" not in raw  # request URLs are rebuilt, never stored
        state = _load_checkpoint_data(checkpoint, "fp")
        assert [r.case for r in state.results] == [passwd]
        assert state.injected_cases == [derived]

    async def test_resume_restores_findings_and_requeues_injected_cases(self, tmp_path: Path) -> None:
        checkpoint = str(tmp_path / "cp.json")
        out_file = tmp_path / "out.json"
        passwd = Case(location="/etc/passwd", os="*NIX")
        other = Case(location="/etc/other", os="*NIX")
        derived = Case(location="/home/alice/.bashrc", os="*NIX")
        config = ScanConfig(
            url="http://example.com/inc.php?file=x",
            param="file",
            quiet=True,
            automatic=True,
            concurrency=1,
            resume_file=checkpoint,
            output_format=OutputFormat.JSON,
            output_file=str(out_file),
        )
        save_checkpoint(
            checkpoint,
            {passwd.case_id},
            checkpoint_fingerprint(config, [passwd, other]),
            results=[ScanResult(case=passwd, found=True, url="", status_code=200, content_length=10)],
            injected_cases=[derived],
            restrict_os="*NIX",
        )

        scanner = Scanner(config)
        fetched: list[str] = []

        async def fake_fetch(client: object, payload: str, headers: object = None) -> MagicMock:
            fetched.append(payload)
            return _response("not found")

        with (
            patch("panoptic.core.parse_cases", return_value=[passwd, other]),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch("panoptic.core.get_revision", return_value=None),
            patch.object(scanner, "_fetch", new=fake_fetch),
        ):
            _patched_client(client_cls)
            assert await scanner._run_scan(io.StringIO(), "test") == 0

        assert not any("%2Fetc%2Fpasswd" in p or "/etc/passwd" in p for p in fetched)
        assert any("bashrc" in p for p in fetched)
        assert any("other" in p for p in fetched)
        assert scanner.restrict_os == "*NIX"
        output = json.loads(out_file.read_text(encoding="utf-8"))
        assert [entry["location"] for entry in output] == ["/etc/passwd"]

    async def test_incompatible_checkpoint_starts_fresh(self, tmp_path: Path) -> None:
        checkpoint = tmp_path / "cp.json"
        checkpoint.write_text(json.dumps(["id1"]), encoding="utf-8")
        scanner = Scanner(ScanConfig(url="http://example.com/?f=x", param="f", resume_file=str(checkpoint)))
        stream = io.StringIO()
        scanner._restore_checkpoint([Case(location="/etc/passwd")], "f=x", TextFormatter(stream))
        assert scanner.completed_ids == set()
        assert "incompatible version" in stream.getvalue()
        assert "starting fresh" in stream.getvalue()

    def test_stale_snapshot_never_overwrites_newer(self, tmp_path: Path) -> None:
        checkpoint = str(tmp_path / "cp.json")
        scanner = Scanner(ScanConfig(url="http://example.com", resume_file=checkpoint))
        scanner._write_checkpoint_snapshot(2, {"new"}, [], [], None)
        scanner._write_checkpoint_snapshot(1, {"old"}, [], [], None)
        assert json.loads(Path(checkpoint).read_text())["completed_ids"] == ["new"]


class TestFingerprintVolatileFields:
    def test_volatile_fields_do_not_change_fingerprint(self) -> None:
        cases = [Case(location="/etc/passwd")]
        base = ScanConfig(url="http://example.com/?f=x", param="f")
        varied = base.replace(
            user_agent="Random/1.0",
            random_agent=True,
            proxy="http://127.0.0.1:8080",
            ignore_proxy=True,
            invalid_ssl=True,
        )
        assert checkpoint_fingerprint(base, cases) == checkpoint_fingerprint(varied, cases)

    @pytest.mark.parametrize(
        "change",
        [
            {"cookie": "sid=guest"},
            {"headers": ["Authorization: Bearer guest"]},
            {"write_files": True},
        ],
    )
    def test_identity_and_write_files_change_fingerprint(self, change: dict[str, object]) -> None:
        """A resume must not reuse findings made as another identity or without file content."""
        cases = [Case(location="/etc/passwd")]
        base = ScanConfig(
            url="http://example.com/?f=x", param="f", cookie="sid=admin", headers=["Authorization: Bearer admin"]
        )
        assert checkpoint_fingerprint(base, cases) != checkpoint_fingerprint(base.replace(**change), cases)

    def test_fingerprint_does_not_store_credentials(self) -> None:
        fingerprint = checkpoint_fingerprint(
            ScanConfig(url="http://example.com/?f=x", cookie="sid=secret", headers=["Authorization: Bearer secret"]),
            [Case(location="/etc/passwd")],
        )
        assert "secret" not in fingerprint

    def test_fuzz_header_changes_fingerprint(self) -> None:
        cases = [Case(location="/etc/passwd")]
        base = ScanConfig(url="http://example.com/", headers=["X-File: FUZZ"])
        other = base.replace(headers=["X-Path: FUZZ"])
        assert checkpoint_fingerprint(base, cases) != checkpoint_fingerprint(other, cases)

    async def test_random_agent_does_not_affect_resume_fingerprint(self) -> None:
        config = ScanConfig(url="http://example.com/?f=x", param="f", random_agent=True, quiet=True)
        cases = [Case(location="/etc/passwd")]
        scanner = Scanner(config)
        with (
            patch("panoptic.core.parse_cases", return_value=cases),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch("panoptic.core.get_revision", return_value=None),
            patch.object(scanner, "_fetch", new=AsyncMock(return_value=None)),
        ):
            _patched_client(client_cls)
            await scanner._run_scan(io.StringIO(), "test")
        assert scanner.config.user_agent
        assert scanner._checkpoint_fingerprint == checkpoint_fingerprint(config, cases)

    async def test_configured_agent_with_random_agent_warns(self) -> None:
        config = ScanConfig(url="http://example.com/?f=x", param="f", random_agent=True, user_agent="Mine")
        scanner = Scanner(config)
        stream = io.StringIO()
        with (
            patch("panoptic.core.parse_cases", return_value=[Case(location="/etc/passwd")]),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch("panoptic.core.get_revision", return_value=None),
            patch.object(scanner, "_fetch", new=AsyncMock(return_value=None)),
        ):
            _patched_client(client_cls)
            await scanner._run_scan(stream, "test")
        assert "--random-agent ignored" in stream.getvalue()
        assert scanner.config.user_agent == "Mine"


class TestReflectionCleaning:
    def _scanner(self, **overrides: object) -> Scanner:
        config = ScanConfig(url="http://example.com/?f=x", param="f", **overrides)  # type: ignore[arg-type]
        scanner = Scanner(config)
        scanner.invalid_filename = "zzqxnonexistentfilenamezzqx"
        sent = process_path(config, scanner.invalid_filename)
        scanner.invalid_response = f"<p>File {base64.b64encode(sent.encode()).decode()} missing</p>"
        return scanner

    @pytest.mark.parametrize(
        "overrides",
        [
            {"base64_encode": True, "prefix": "../../../../"},
            {"replace_slash": "....//", "prefix": "../../"},
            {"prefix": "../../../../../../", "postfix": "%00"},
        ],
    )
    def test_transformed_reflection_is_not_a_hit(self, overrides: dict[str, object]) -> None:
        scanner = self._scanner(**overrides)
        sent_invalid = process_path(scanner.config, scanner.invalid_filename)
        location = "/etc/x"
        sent = process_path(scanner.config, location)
        if scanner.config.base64_encode:
            scanner.invalid_response = f"<p>File {sent_invalid} missing</p>"
            html = f"<p>File {sent} missing</p>"
        else:
            from urllib.parse import quote

            scanner.invalid_response = f"<p>File {quote(sent_invalid, safe='')} missing</p>"
            html = f"<p>File {quote(sent, safe='')} missing</p>"
        assert scanner._response_matches(html, location, scanner._get_cleaned_invalid()) is False

    def test_cleaned_invalid_computed_once(self) -> None:
        scanner = self._scanner()
        with patch("panoptic.core.clean_response", wraps=clean_response) as spy:
            first = scanner._get_cleaned_invalid()
            second = scanner._get_cleaned_invalid()
        assert first == second
        assert spy.call_count == 1

    async def test_comparison_runs_off_event_loop(self) -> None:
        scanner = self._scanner(automatic=True, skip_parsing=True)
        scanner.invalid_status_code = 200
        calls: list[object] = []
        real_to_thread = asyncio.to_thread

        async def spy(func: object, *args: object) -> object:
            calls.append(func)
            return await real_to_thread(func, *args)  # type: ignore[arg-type]

        with (
            patch.object(scanner, "_fetch", new=AsyncMock(return_value=_response("root:x:0:0"))),
            patch("panoptic.core.asyncio.to_thread", new=spy),
        ):
            await scanner._process_case(Case(location="/etc/passwd"), AsyncMock(), "f=x", asyncio.Queue(), MagicMock())
        assert scanner._response_matches in calls


class TestHeuristicBounds:
    def test_clean_response_regex_is_linear(self) -> None:
        start = time.perf_counter()
        clean_response("%2e%2e%2f" * 40 + "y", "../" * 40 + "x")
        assert time.perf_counter() - start < 1.0

    def test_clean_response_strips_encoded_and_entity_forms(self) -> None:
        cleaned = clean_response("a %2Fetc%2Fpasswd b &#47;etc&#47;passwd c", "/etc/passwd")
        assert "passwd" not in cleaned

    def test_comparison_is_capped(self) -> None:
        common = "a" * MAX_COMPARE_LENGTH
        assert is_match(common + "x" * 10_000, common + "y" * 10_000) is False
        assert len(clean_response(common + "tail", "/etc/passwd")) == MAX_COMPARE_LENGTH


class TestOsRestriction:
    async def test_os_agnostic_hit_does_not_latch_first_found(self) -> None:
        scanner = Scanner(ScanConfig(url="http://example.com/?f=x", param="f", automatic=True, skip_parsing=True))
        scanner.invalid_status_code = 200
        text_out = MagicMock()
        with (
            patch.object(scanner, "_fetch", new=AsyncMock(return_value=_response("hit"))),
            patch("panoptic.core.is_match", return_value=True),
        ):
            await scanner._process_case(Case(location="/any"), AsyncMock(), "f=x", asyncio.Queue(), text_out)
            assert scanner.first_found is False
            await scanner._process_case(
                Case(location="/etc/issue", os="*NIX"), AsyncMock(), "f=x", asyncio.Queue(), text_out
            )
        assert scanner.restrict_os == "*NIX"

    async def test_skipped_case_does_not_sleep(self) -> None:
        scanner = Scanner(ScanConfig(url="http://example.com/?f=x", param="f", delay=30.0, os_filter="Windows"))
        sleep = AsyncMock()
        fetch = AsyncMock()
        with patch("panoptic.core.asyncio.sleep", new=sleep), patch.object(scanner, "_fetch", new=fetch):
            assert await scanner._process_case(
                Case(location="/etc/passwd", os="*NIX"), AsyncMock(), "f=x", asyncio.Queue(), MagicMock()
            )
        sleep.assert_not_called()
        fetch.assert_not_called()


class TestInterrupts:
    def test_prompt_cancellation_does_not_hang_shutdown(self) -> None:
        release = threading.Event()

        def blocking_input(prompt: str) -> str:
            release.wait(timeout=10)
            return "y"

        async def main() -> None:
            task = asyncio.create_task(_interruptible_input("? "))
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        start = time.perf_counter()
        with patch("builtins.input", side_effect=blocking_input):
            asyncio.run(main())
        elapsed = time.perf_counter() - start
        release.set()
        assert elapsed < 2.0

    async def test_cancel_stops_workers_then_flushes(self, tmp_path: Path) -> None:
        checkpoint = str(tmp_path / "cp.json")
        cases = [Case(location="/first"), Case(location="/second")]
        config = ScanConfig(
            url="http://example.com/?f=x",
            param="f",
            quiet=True,
            concurrency=2,
            resume_file=checkpoint,
        )
        scanner = Scanner(config)
        scanner._last_checkpoint_time = time.monotonic()  # suppress throttled flushes
        blocked = asyncio.Event()

        async def process(case: Case, *args: object) -> bool:
            if case.location == "/first":
                await scanner._mark_completed(case)
                return True
            blocked.set()
            await asyncio.Event().wait()
            return True

        with (
            patch("panoptic.core.parse_cases", return_value=cases),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch("panoptic.core.get_revision", return_value=None),
            patch.object(scanner, "_fetch", new=AsyncMock(return_value=_response("base"))),
            patch.object(scanner, "_process_case", new=process),
        ):
            _patched_client(client_cls)
            task = asyncio.create_task(scanner._run_scan(io.StringIO(), "test"))
            await asyncio.wait_for(blocked.wait(), timeout=2)
            await asyncio.sleep(0.05)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

        data = json.loads(Path(checkpoint).read_text(encoding="utf-8"))
        assert data["completed_ids"] == [cases[0].case_id]
        assert not any("Worker terminated" in error for error in scanner.operational_errors)


class TestMiscCleanups:
    def test_fuzz_headers_parsed_once(self) -> None:
        scanner = Scanner(ScanConfig(url="http://example.com/", headers=["X-File: FUZZ", "X-Static: 1"]))
        with patch("panoptic.core.validate_header", side_effect=AssertionError("re-parsed")):
            assert scanner._fuzz_headers("/etc/passwd") == {"X-File": "/etc/passwd"}
            assert scanner._fuzz_headers("/etc/hosts") == {"X-File": "/etc/hosts"}

    def test_write_file_warning_uses_formatter(self, tmp_path: Path) -> None:
        scanner = Scanner(ScanConfig(url="http://example.com/?f=x", param="f", write_files=True))
        stream = io.StringIO()
        with (
            patch("panoptic.core.Path.cwd", return_value=tmp_path),
            patch("panoptic.core.open_secure_write", side_effect=OSError("disk full")),
        ):
            scanner._write_file(Case(location="/etc/passwd"), "data", TextFormatter(stream))
        assert "disk full" in stream.getvalue()

    def test_write_file_name_capped_in_utf8_bytes(self, tmp_path: Path) -> None:
        scanner = Scanner(ScanConfig(url="http://example.com/?f=x", param="f", write_files=True))
        with patch("panoptic.core.Path.cwd", return_value=tmp_path):
            scanner._write_file(Case(location="/" + "é" * 300), "data")
        (written,) = list((tmp_path / "output" / "example.com").iterdir())
        assert len(written.name.encode("utf-8")) <= MAX_OUTPUT_FILENAME_BYTES
        assert written.read_text(encoding="utf-8") == "data"

    def test_write_file_uses_custom_output_dir(self, tmp_path: Path) -> None:
        config = ScanConfig(url="http://example.com/?f=x", param="f", write_files=True, output_dir="loot/run1")
        scanner = Scanner(config)
        with patch("panoptic.core.Path.cwd", return_value=tmp_path):
            scanner._write_file(Case(location="/etc/passwd"), "root:x")
        files = list((tmp_path / "loot" / "run1" / "example.com").iterdir())
        assert len(files) == 1
        assert not (tmp_path / "output").exists()

    async def test_scan_failure_message_is_redacted(self) -> None:
        scanner = Scanner(ScanConfig(url="http://example.com/?f=x", param="f"))
        stream = io.StringIO()
        error = httpx.ConnectError("failed for http://bob:hunter2@example.com/x?token=s3cr3t")
        with (
            patch.object(scanner, "_run_scan", new=AsyncMock(side_effect=error)),
            patch("panoptic.core.sys.stderr", stream),
        ):
            assert await scanner.run() == 2
        message = stream.getvalue()
        assert "Scan failed" in message
        assert "hunter2" not in message and "s3cr3t" not in message

    def test_redact_text_handles_multiple_urls(self) -> None:
        text = redact_urls_in_text("a http://u:p@h.example/?k=v b https://h2.example/p")
        assert "u:p" not in text and "k=v" not in text and "https://h2.example/p" in text

    def test_format_error_counts(self) -> None:
        assert _format_error_counts(Counter({"ReadTimeout": 3, "ConnectError": 1})) == "ReadTimeout: 3, ConnectError: 1"
        assert _format_error_counts(MagicMock()) == ""
