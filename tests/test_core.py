"""Tests for panoptic.core — async scanner orchestrator."""

import asyncio
import io
import json
import os
import threading
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from panoptic.core import (
    Scanner,
    build_payload,
    checkpoint_fingerprint,
    load_checkpoint,
    save_checkpoint,
)
from panoptic.models import Case, OutputFormat, ScanConfig
from panoptic.output import TextFormatter
from panoptic.utils import os_matches_restriction


class TestBuildPayload:
    def test_basic_param_replacement(self) -> None:
        config = ScanConfig(url="http://example.com/test.php?file=test.txt", param="file")
        payload = build_payload(config, "/etc/passwd", "file=test.txt")
        assert "file=" in payload
        assert "/etc/passwd" in payload

    def test_prefix_postfix(self) -> None:
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt", param="file", prefix="../../../", postfix="%00"
        )
        payload = build_payload(config, "/etc/passwd", "file=test.txt")
        assert "../../../" in payload
        assert "%00" in payload

    def test_path_based(self) -> None:
        config = ScanConfig(url="http://example.com/files/view/test.txt", path_based=True)
        url = build_payload(config, "/etc/passwd", "")
        assert url == "http://example.com/files/view/etc/passwd"

    def test_replace_slash(self) -> None:
        config = ScanConfig(url="http://example.com/test.php?file=test.txt", param="file", replace_slash="/./")
        payload = build_payload(config, "/etc/passwd", "file=test.txt")
        assert "/./" in payload

    def test_param_not_substring_matched(self) -> None:
        """--param id must not match userid."""
        config = ScanConfig(url="http://example.com/test.php?userid=1&id=2", param="id")
        payload = build_payload(config, "/etc/passwd", "userid=1&id=2")
        assert "userid=1" in payload  # userid unchanged
        assert "id=/etc/passwd" in payload or "id=%2Fetc%2Fpasswd" in payload

    def test_ext_param_not_substring_matched(self) -> None:
        """--ext-param type must not match content_type."""
        config = ScanConfig(
            url="http://example.com/test.php?content_type=html&type=txt&file=test.txt",
            param="file",
            ext_param="type",
        )
        payload = build_payload(config, "/etc/passwd.conf", "content_type=html&type=txt&file=test.txt")
        assert "content_type=html" in payload  # content_type unchanged

    def test_get_payload_encodes_ampersand(self) -> None:
        """Payload containing & must be encoded in GET query strings."""
        config = ScanConfig(url="http://example.com/test.php?file=test.txt", param="file")
        payload = build_payload(config, "/etc/foo&bar", "file=test.txt")
        assert "foo%26bar" in payload

    def test_post_payload_encodes_plus_as_percent2b(self) -> None:
        """POST payloads must encode + to prevent space decoding in form bodies."""
        config = ScanConfig(
            url="http://example.com/test.php",
            param="file",
            data="file=test.txt",
        )
        payload = build_payload(config, "/etc/foo+bar", "file=test.txt")
        assert "%2B" in payload or "foo%2Bbar" in payload

    def test_get_payload_encodes_plus(self) -> None:
        """GET payloads must encode + because query parsers decode it as a space."""
        config = ScanConfig(url="http://example.com/test.php?file=test.txt", param="file")
        payload = build_payload(config, "/etc/foo+bar", "file=test.txt")
        assert "foo%2Bbar" in payload

    def test_multiplier_applies_during_payload_construction(self) -> None:
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt",
            param="file",
            prefix="../",
            multiplier=3,
        )
        payload = build_payload(config, "/etc/passwd", "file=test.txt")
        assert "../../../etc/passwd" in payload

    def test_replace_slash_percent_not_double_encoded(self) -> None:
        """--replace-slash with pre-encoded value like %2F must not double-encode."""
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt",
            param="file",
            replace_slash="%2F",
        )
        payload = build_payload(config, "/etc/passwd", "file=test.txt")
        assert "%2F" in payload
        assert "%252F" not in payload

    def test_fuzz_mode_no_encoding(self) -> None:
        """FUZZ mode should not auto-encode — user controls the template."""
        config = ScanConfig(url="http://example.com/test.php", data='{"file":"FUZZ"}')
        payload = build_payload(config, "/etc/passwd", '{"file":"FUZZ"}')
        assert "/etc/passwd" in payload

    def test_fuzz_json_body_preserves_valid_json_for_windows_path(self) -> None:
        """A Windows path with backslashes/quotes must stay valid JSON after FUZZ substitution."""
        body = '{"file":"FUZZ"}'
        config = ScanConfig(url="http://example.com/api", data=body)
        payload = build_payload(config, r"C:\Windows\win.ini", body)
        # Must round-trip as valid JSON with the raw path recovered intact.
        assert json.loads(payload) == {"file": r"C:\Windows\win.ini"}

    def test_fuzz_json_body_escapes_embedded_quote(self) -> None:
        body = '{"path":"FUZZ"}'
        config = ScanConfig(url="http://example.com/api", data=body)
        payload = build_payload(config, 'a"b', body)
        assert json.loads(payload) == {"path": 'a"b'}

    def test_fuzz_json_marker_in_key_is_replaced(self) -> None:
        body = '{"FUZZ":"x"}'
        config = ScanConfig(url="http://example.com/api", data=body)
        payload = build_payload(config, "/etc/passwd", body)
        assert json.loads(payload) == {"/etc/passwd": "x"}

    def test_fuzz_form_body_percent_encodes_delimiters(self) -> None:
        """Form-encoded FUZZ bodies must encode +, &, = so the structure survives."""
        body = "file=FUZZ&id=1"
        config = ScanConfig(url="http://example.com/api", data=body)
        payload = build_payload(config, "/etc/foo+bar&baz=qux", body)
        assert "foo%2Bbar%26baz%3Dqux" in payload
        assert payload.endswith("&id=1")  # trailing structure preserved

    def test_fuzz_opaque_body_keeps_raw_substitution(self) -> None:
        """A non-JSON, non-form body leaves the substitution untouched."""
        body = "prefix-FUZZ-suffix"
        config = ScanConfig(url="http://example.com/api", data=body)
        payload = build_payload(config, "/etc/passwd", body)
        assert payload == "prefix-/etc/passwd-suffix"

    def test_encoded_parameter_name_is_replaced(self) -> None:
        params = "file%5B0%5D=old&id=1"
        config = ScanConfig(url=f"http://example.com/?{params}", param="file[0]")
        payload = build_payload(config, "/etc/passwd", params)
        assert payload == "http://example.com/?file%5B0%5D=/etc/passwd&id=1"

    def test_parameter_name_backslash_is_not_a_regex_replacement(self) -> None:
        params = r"x\1=old&id=1"
        config = ScanConfig(url=f"http://example.com/?{params}", param=r"x\1")
        payload = build_payload(config, "/etc/passwd", params)
        assert payload.endswith(r"?x\1=/etc/passwd&id=1")

    def test_base64_padding_is_percent_encoded(self) -> None:
        config = ScanConfig(
            url="http://example.com/?file=old",
            param="file",
            base64_encode=True,
        )
        payload = build_payload(config, "/etc/passwd", "file=old")
        assert payload.endswith("file=L2V0Yy9wYXNzd2Q%3D")


class TestScanner:
    async def test_scanner_initializes(self) -> None:
        config = ScanConfig(
            url="http://target.test/include.php?file=test.txt",
            param="file",
            concurrency=1,
            timeout=5.0,
            retries=0,
            automatic=True,
        )
        scanner = Scanner(config)
        assert scanner.config == config

    async def test_checkpoint_state(self, tmp_path: Path) -> None:
        """Verify checkpoint saves and loads case IDs."""
        cases = [
            Case(location="/etc/passwd", os="*NIX"),
            Case(location="/etc/shadow", os="*NIX"),
        ]

        checkpoint_file = str(tmp_path / "checkpoint.json")

        # Save
        completed_ids = {cases[0].case_id}
        save_checkpoint(checkpoint_file, completed_ids)

        # Load
        loaded_ids = load_checkpoint(checkpoint_file)
        assert cases[0].case_id in loaded_ids
        assert cases[1].case_id not in loaded_ids

    async def test_load_empty_checkpoint(self, tmp_path: Path) -> None:
        assert load_checkpoint(str(tmp_path / "nonexistent.json")) == set()

    def test_generic_unix_restriction_keeps_specific_unix_cases(self) -> None:
        assert os_matches_restriction("FreeBSD", "*NIX") is True
        assert os_matches_restriction("OS X", "*NIX") is True
        assert os_matches_restriction("Windows", "*NIX") is False
        assert os_matches_restriction("*NIX", "FreeBSD") is True
        assert os_matches_restriction("DragonFly BSD, FreeBSD", "FreeBSD") is True

    def test_runtime_restriction_canonicalizes_os_alias(self) -> None:
        """An aliased --os (e.g. OSX) must match the canonical case OS at runtime."""
        for alias in ("OSX", "osx", "OsX"):
            scanner = Scanner(ScanConfig(url="http://example.com", os_filter=alias))
            assert scanner.restrict_os == "OS X"
            # A canonicalized OS X case must now pass the runtime restriction.
            assert os_matches_restriction("OS X", scanner.restrict_os) is True


class TestWriteFile:
    def test_no_filename_collision(self, tmp_path: Path) -> None:
        """Paths differing only in traversal depth must not overwrite each other."""
        config = ScanConfig(
            url="http://example.com/test.php?file=x",
            param="file",
            write_files=True,
        )
        scanner = Scanner(config)
        scanner.original_response = "<html>original</html>"

        case1 = Case(location="../../etc/passwd", os="*NIX")
        case2 = Case(location="../../../etc/passwd", os="*NIX")

        # Use monkeypatch approach with tmp_path
        with patch("panoptic.core.Path.cwd", return_value=tmp_path):
            scanner._write_file(case1, "content1")
            scanner._write_file(case2, "content2")

        output_dir = tmp_path / "output" / "example.com"
        files = list(output_dir.iterdir())
        assert len(files) == 2, f"Expected 2 files, got {len(files)}: {files}"
        if os.name == "posix":
            assert all(os.stat(path).st_mode & 0o777 == 0o600 for path in files)

    @pytest.mark.skipif(os.name != "posix", reason="requires POSIX symlinks")
    def test_discovered_file_write_refuses_symlink(self, tmp_path: Path) -> None:
        """A symlink pre-planted at the discovered-file path must not be clobbered."""
        from panoptic.utils import sanitize_filename

        config = ScanConfig(url="http://example.com/test.php?file=x", param="file", write_files=True)
        scanner = Scanner(config)
        scanner.original_response = "<html>original</html>"
        case = Case(location="/etc/passwd", os="*NIX")

        secret = tmp_path / "secret.txt"
        secret.write_text("do-not-clobber", encoding="utf-8")

        with patch("panoptic.core.Path.cwd", return_value=tmp_path):
            output_dir = tmp_path / "output" / "example.com"
            output_dir.mkdir(parents=True)
            filename = f"{sanitize_filename(case.location)}_{case.case_id[:8]}.txt"
            (output_dir / filename).symlink_to(secret)
            # _write_file swallows OSError (logs a warning) rather than raising.
            scanner._write_file(case, "malicious content")

        assert secret.read_text(encoding="utf-8") == "do-not-clobber"


class TestScanOutputFilePermissions:
    @pytest.mark.skipif(os.name != "posix", reason="requires POSIX file permissions")
    async def test_output_file_is_owner_only(self, tmp_path: Path) -> None:
        out_path = tmp_path / "results.json"
        config = ScanConfig(
            url="http://example.com/test.php?file=x",
            param="file",
            quiet=True,
            output_format=OutputFormat.JSON,
            output_file=str(out_path),
        )
        scanner = Scanner(config)
        with (
            patch("panoptic.core.parse_cases", return_value=[Case(location="/etc/passwd")]),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch("panoptic.core.get_revision", return_value=None),
            patch.object(scanner, "_fetch", new=AsyncMock(return_value=None)),
        ):
            client_cls.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            client_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            await scanner._run_scan(io.StringIO(), "test")

        assert out_path.exists()
        assert os.stat(out_path).st_mode & 0o777 == 0o600

    @pytest.mark.skipif(os.name != "posix", reason="requires POSIX file permissions")
    async def test_log_file_is_owner_only(self, tmp_path: Path) -> None:
        log_path = tmp_path / "scan.log"
        config = ScanConfig(
            url="http://example.com/test.php?file=x",
            param="file",
            quiet=True,
            log_file=str(log_path),
        )
        scanner = Scanner(config)
        with (
            patch("panoptic.core.parse_cases", return_value=[Case(location="/etc/passwd")]),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch("panoptic.core.get_revision", return_value=None),
            patch.object(scanner, "_fetch", new=AsyncMock(return_value=None)),
        ):
            client_cls.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            client_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            await scanner.run()

        assert log_path.exists()
        assert os.stat(log_path).st_mode & 0o777 == 0o600


class TestFirstFoundRace:
    async def test_only_one_os_restriction_with_concurrent_matches(self) -> None:
        """Multiple concurrent matching cases must trigger OS restriction exactly once."""
        config = ScanConfig(
            url="http://target.test/include.php?file=test.txt",
            param="file",
            concurrency=4,
            automatic=True,
        )
        scanner = Scanner(config)
        scanner.invalid_response = "<html>not found</html>"
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "nonexistent"
        scanner.original_response = "<html>original</html>"

        text_out = AsyncMock()
        text_out.write_found = lambda r: None
        text_out.write_info = lambda m: None
        text_out.write_verbose = lambda m: None

        queue: asyncio.Queue[Case] = asyncio.Queue()

        cases = [Case(location=f"/etc/file{i}", os="*NIX", category="OS", software="Linux") for i in range(10)]

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.headers = {"content-length": "0"}

        with (
            patch.object(scanner, "_fetch", return_value=mock_response),
            patch("panoptic.core.is_match", return_value=True),
        ):
            await asyncio.gather(
                *[scanner._process_case(case, AsyncMock(), "file=test.txt", queue, text_out) for case in cases]
            )

        assert scanner.restrict_os == "*NIX"
        assert scanner.first_found is True


class TestAtomicCheckpoint:
    def test_save_checkpoint_atomic(self, tmp_path: Path) -> None:
        """Checkpoint writes must be atomic (temp file + rename)."""
        filepath = str(tmp_path / "checkpoint.json")
        save_checkpoint(filepath, {"id1", "id2"}, "fingerprint")
        with open(filepath) as f:
            data = json.load(f)
        assert data["version"] == 1
        assert data["fingerprint"] == "fingerprint"
        assert set(data["completed_ids"]) == {"id1", "id2"}

    def test_save_checkpoint_no_partial_writes(self, tmp_path: Path) -> None:
        """If process dies mid-write, old checkpoint must survive."""
        filepath = str(tmp_path / "checkpoint.json")
        save_checkpoint(filepath, {"id1"})
        save_checkpoint(filepath, {"id1", "id2", "id3"})
        with open(filepath) as f:
            data = json.load(f)
        assert len(data["completed_ids"]) == 3

    def test_checkpoint_rejects_different_scan(self, tmp_path: Path) -> None:
        filepath = str(tmp_path / "checkpoint.json")
        save_checkpoint(filepath, {"id1"}, "scan-a")
        with pytest.raises(ValueError, match="different scan"):
            load_checkpoint(filepath, "scan-b")

    def test_checkpoint_fingerprint_changes_with_target(self) -> None:
        cases = [Case(location="/etc/passwd", os="*NIX")]
        first = checkpoint_fingerprint(ScanConfig(url="http://one.example/?f=x"), cases)
        second = checkpoint_fingerprint(ScanConfig(url="http://two.example/?f=x"), cases)
        assert first != second

    def test_checkpoint_fingerprint_normalizes_unordered_status_codes(self) -> None:
        cases = [Case(location="/etc/passwd", os="*NIX")]
        first = checkpoint_fingerprint(
            ScanConfig(url="http://example.com/?f=x", match_codes=[200, 404]),
            cases,
        )
        second = checkpoint_fingerprint(
            ScanConfig(url="http://example.com/?f=x", match_codes=[404, 200]),
            cases,
        )
        assert first == second

    def test_checkpoint_fingerprint_ignores_output_destination(self) -> None:
        cases = [Case(location="/etc/passwd", os="*NIX")]
        first = checkpoint_fingerprint(ScanConfig(url="http://example.com/?f=x"), cases)
        second = checkpoint_fingerprint(
            ScanConfig(url="http://example.com/?f=x", output_file="results.json"),
            cases,
        )
        assert first == second

    def test_legacy_checkpoint_is_loaded(self, tmp_path: Path) -> None:
        filepath = tmp_path / "checkpoint.json"
        filepath.write_text(json.dumps(["id1", "id2"]), encoding="utf-8")
        assert load_checkpoint(str(filepath), "fingerprint-not-present-in-legacy") == {"id1", "id2"}


class TestMatchString:
    async def test_match_string_excludes_non_matching_response(self) -> None:
        """Responses WITHOUT match_string should NOT be reported as found."""
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt",
            param="file",
            match_string="root:x:0:0",
            automatic=True,
        )
        scanner = Scanner(config)
        scanner.invalid_response = "<html>not found</html>"
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "nonexistent"

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "<html>some content without the string</html>"
        mock_response.headers = {"content-length": "0"}

        text_out = AsyncMock()
        queue: asyncio.Queue[Case] = asyncio.Queue()
        case = Case(location="/etc/shadow", os="*NIX")

        with (
            patch.object(scanner, "_fetch", return_value=mock_response),
            patch("panoptic.core.is_match", return_value=True),
        ):
            await scanner._process_case(case, AsyncMock(), "file=test.txt", queue, text_out)

        assert len(scanner.results) == 0

    async def test_match_string_includes_matching_response(self) -> None:
        """Responses WITH match_string should be reported as found."""
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt",
            param="file",
            match_string="root:x:0:0",
            automatic=True,
        )
        scanner = Scanner(config)
        scanner.invalid_response = "<html>not found</html>"
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "nonexistent"

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.headers = {"content-length": "0"}

        text_out = AsyncMock()
        text_out.write_found = lambda r: None
        text_out.write_info = lambda m: None
        queue: asyncio.Queue[Case] = asyncio.Queue()
        case = Case(location="/etc/passwd", os="*NIX")

        with (
            patch.object(scanner, "_fetch", return_value=mock_response),
            patch("panoptic.core.is_match", return_value=True),
        ):
            await scanner._process_case(case, AsyncMock(), "file=test.txt", queue, text_out)

        assert len(scanner.results) == 1
        assert scanner.results[0].found is True

    async def test_match_string_disables_content_length_fast_path(self) -> None:
        """Content-Length optimization must be skipped when match_string requires body inspection."""
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt",
            param="file",
            match_string="root:x:0:0",
            automatic=True,
        )
        scanner = Scanner(config)
        scanner.invalid_response = "x" * 100
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "nonexistent"
        scanner.original_response = "x" * 100

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "large body " * 500
        mock_response.headers = {"content-length": "50000"}

        text_out = AsyncMock()
        text_out.write_found = lambda r: None
        queue: asyncio.Queue[Case] = asyncio.Queue()
        case = Case(location="/etc/passwd", os="*NIX")

        with patch.object(scanner, "_fetch", return_value=mock_response):
            await scanner._process_case(case, AsyncMock(), "file=test.txt", queue, text_out)

        assert len(scanner.results) == 0

    async def test_large_identical_response_is_not_found(self) -> None:
        """A large Content-Length must not bypass body comparison."""
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt",
            param="file",
            automatic=True,
        )
        scanner = Scanner(config)
        scanner.invalid_response = "not found" * 1000
        scanner.original_response = scanner.invalid_response
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "nonexistent"

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = scanner.invalid_response
        mock_response.headers = {"content-length": "50000"}

        queue: asyncio.Queue[Case] = asyncio.Queue()
        case = Case(location="/etc/passwd", os="*NIX")
        text_out = AsyncMock()
        with patch.object(scanner, "_fetch", return_value=mock_response):
            processed = await scanner._process_case(case, AsyncMock(), "file=test.txt", queue, text_out)

        assert processed is True
        assert scanner.results == []


class TestInteractiveRestriction:
    async def test_eof_does_not_approve_os_restriction(self) -> None:
        scanner = Scanner(
            ScanConfig(
                url="http://example.com/test.php?file=x",
                param="file",
                skip_parsing=True,
            )
        )
        scanner.invalid_response = "not found"
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "missing"
        response = AsyncMock()
        response.status_code = 200
        response.text = "found contents"

        with (
            patch.object(scanner, "_fetch", return_value=response),
            patch("panoptic.core.is_match", return_value=True),
            patch("builtins.input", side_effect=EOFError),
        ):
            await scanner._process_case(
                Case(location="/a/file", os="FreeBSD"),
                AsyncMock(),
                "file=x",
                asyncio.Queue(),
                TextFormatter(io.StringIO()),
            )

        assert scanner.restrict_os is None


class TestCheckpointThrottling:
    async def test_rapid_marks_throttle_writes(self, tmp_path: Path) -> None:
        """Rapid _mark_completed calls should not write on every call."""
        checkpoint_file = str(tmp_path / "checkpoint.json")
        config = ScanConfig(url="http://example.com", resume_file=checkpoint_file)
        scanner = Scanner(config)
        scanner._last_checkpoint_time = time.monotonic()  # Pretend we just wrote

        write_count = 0
        original_save = save_checkpoint

        def counting_save(filepath: str, completed_ids: set[str], fingerprint: str = "") -> None:
            nonlocal write_count
            write_count += 1
            original_save(filepath, completed_ids, fingerprint)

        with patch("panoptic.core.save_checkpoint", side_effect=counting_save):
            for i in range(20):
                case = Case(location=f"/etc/file{i}", os="*NIX")
                await scanner._mark_completed(case)

        assert write_count <= 1, f"Expected <=1 writes during throttle window, got {write_count}"

    async def test_flush_retains_dirty_during_real_event_loop_concurrency(self, tmp_path: Path) -> None:
        """An event-loop task completing a case mid-save must remain dirty."""
        checkpoint_file = str(tmp_path / "checkpoint.json")
        config = ScanConfig(url="http://example.com", resume_file=checkpoint_file)
        scanner = Scanner(config)
        scanner._checkpoint_fingerprint = "fp"
        first = Case(location="/first")
        second = Case(location="/second")
        scanner.completed_ids = {first.case_id}
        scanner._checkpoint_dirty = True
        # Keep _mark_completed from starting its own throttled flush; this test
        # exercises a second event-loop task mutating state while the first flush
        # is blocked inside asyncio.to_thread.
        scanner._last_checkpoint_time = time.monotonic()

        original_save = save_checkpoint
        save_started = threading.Event()
        allow_save = threading.Event()

        def blocking_save(filepath: str, completed_ids: set[str], fingerprint: str = "") -> None:
            save_started.set()
            if not allow_save.wait(timeout=2):
                raise TimeoutError("test did not release checkpoint save")
            original_save(filepath, completed_ids, fingerprint)

        with patch("panoptic.core.save_checkpoint", side_effect=blocking_save):
            flush_task = asyncio.create_task(scanner._flush_checkpoint())
            save_observed = await asyncio.wait_for(asyncio.to_thread(save_started.wait, 1), timeout=2)
            assert save_observed, "checkpoint save did not start"
            await scanner._mark_completed(second)
            allow_save.set()
            await asyncio.wait_for(flush_task, timeout=2)

        # The first snapshot contains only the case completed before the save.
        with open(checkpoint_file) as f:
            data = json.load(f)
        assert data["completed_ids"] == [first.case_id]
        # The second case arrived on the event loop while the worker-thread save
        # was blocked, so dirty must remain set and a subsequent flush must persist it.
        assert scanner._checkpoint_dirty is True
        await scanner._flush_checkpoint()
        assert load_checkpoint(checkpoint_file, "fp") == {first.case_id, second.case_id}
        assert scanner._checkpoint_dirty is False

    async def test_flush_on_shutdown(self, tmp_path: Path) -> None:
        """_flush_checkpoint must write dirty state even without time threshold."""
        checkpoint_file = str(tmp_path / "checkpoint.json")
        config = ScanConfig(url="http://example.com", resume_file=checkpoint_file)
        scanner = Scanner(config)
        scanner.completed_ids = {"id1", "id2", "id3"}
        scanner._checkpoint_dirty = True

        await scanner._flush_checkpoint()

        with open(checkpoint_file) as f:
            data = json.load(f)
        assert set(data["completed_ids"]) == {"id1", "id2", "id3"}
        assert scanner._checkpoint_dirty is False


class TestWorkerSupervision:
    async def test_case_exception_does_not_deadlock_queue(self) -> None:
        config = ScanConfig(
            url="http://example.com/test.php?file=x",
            param="file",
            concurrency=1,
            automatic=True,
            quiet=True,
        )
        scanner = Scanner(config)
        response = AsyncMock()
        response.text = "baseline"
        response.status_code = 200

        cases = [Case(location="/first"), Case(location="/second")]
        with (
            patch("panoptic.core.parse_cases", return_value=cases),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch.object(scanner, "_fetch", new=AsyncMock(side_effect=[response, response])),
            patch.object(scanner, "_process_case", new=AsyncMock(side_effect=[RuntimeError("boom"), True])),
        ):
            client_cls.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            client_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            exit_code = await asyncio.wait_for(scanner._run_scan(io.StringIO(), "test"), timeout=1)

        assert exit_code == 2
        assert scanner.total_failed == 1
        assert scanner.total_processed == 1

    async def test_partial_request_failure_does_not_fail_completed_scan(self) -> None:
        config = ScanConfig(
            url="http://example.com/test.php?file=x",
            param="file",
            concurrency=1,
            automatic=True,
            quiet=True,
        )
        scanner = Scanner(config)
        response = AsyncMock()
        response.text = "baseline"
        response.status_code = 200

        with (
            patch("panoptic.core.parse_cases", return_value=[Case(location="/first"), Case(location="/second")]),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch.object(scanner, "_fetch", new=AsyncMock(side_effect=[response, response])),
            patch.object(scanner, "_process_case", new=AsyncMock(side_effect=[False, True])),
        ):
            client_cls.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            client_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            exit_code = await scanner._run_scan(io.StringIO(), "test")

        assert exit_code == 0
        assert scanner.total_failed == 1
        assert scanner.total_processed == 1

    async def test_all_request_failures_are_operational_failure(self) -> None:
        config = ScanConfig(
            url="http://example.com/test.php?file=x",
            param="file",
            concurrency=1,
            automatic=True,
            quiet=True,
        )
        scanner = Scanner(config)
        response = AsyncMock()
        response.text = "baseline"
        response.status_code = 200

        with (
            patch("panoptic.core.parse_cases", return_value=[Case(location="/only")]),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch.object(scanner, "_fetch", new=AsyncMock(side_effect=[response, response])),
            patch.object(scanner, "_process_case", new=AsyncMock(return_value=False)),
        ):
            client_cls.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            client_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            exit_code = await scanner._run_scan(io.StringIO(), "test")

        assert exit_code == 2
        assert scanner.total_failed == 1
        assert scanner.total_processed == 0

    async def test_connection_failure_emits_valid_empty_json(self) -> None:
        config = ScanConfig(
            url="http://example.com/test.php?file=x",
            param="file",
            quiet=True,
            output_format=OutputFormat.JSON,
        )
        scanner = Scanner(config)
        output = io.StringIO()
        with (
            patch("panoptic.core.parse_cases", return_value=[Case(location="/etc/passwd")]),
            patch("panoptic.core.NetworkClient") as client_cls,
            patch("panoptic.core.get_revision", return_value=None),
            patch.object(scanner, "_fetch", new=AsyncMock(return_value=None)),
            patch("panoptic.core.sys.stdout", output),
        ):
            client_cls.return_value.__aenter__ = AsyncMock(return_value=AsyncMock())
            client_cls.return_value.__aexit__ = AsyncMock(return_value=None)
            exit_code = await scanner._run_scan(io.StringIO(), "test")

        assert exit_code == 2
        assert json.loads(output.getvalue()) == []

    async def test_checkpoint_write_failure_is_operational_error(self, tmp_path: Path) -> None:
        checkpoint = tmp_path / "missing" / "checkpoint.json"
        scanner = Scanner(ScanConfig(url="http://example.com", resume_file=str(checkpoint)))
        scanner.completed_ids = {"id1"}
        scanner._checkpoint_dirty = True
        await scanner._flush_checkpoint()
        assert scanner._checkpoint_disabled is True
        assert any("Checkpoint disabled" in error for error in scanner.operational_errors)
