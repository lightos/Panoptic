"""Tests for panoptic.core — async scanner orchestrator."""

import asyncio
import json
import time
from pathlib import Path
from unittest.mock import AsyncMock, patch

from panoptic.core import Scanner, build_payload, load_checkpoint, save_checkpoint
from panoptic.models import Case, ScanConfig


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
        assert "/etc/passwd" in url

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
        from unittest.mock import patch as mock_patch

        with mock_patch("panoptic.core.Path.cwd", return_value=tmp_path):
            scanner._write_file(case1, "content1")
            scanner._write_file(case2, "content2")

        output_dir = tmp_path / "output" / "example.com"
        files = list(output_dir.iterdir())
        assert len(files) == 2, f"Expected 2 files, got {len(files)}: {files}"


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
        save_checkpoint(filepath, {"id1", "id2"})
        with open(filepath) as f:
            data = json.load(f)
        assert set(data) == {"id1", "id2"}

    def test_save_checkpoint_no_partial_writes(self, tmp_path: Path) -> None:
        """If process dies mid-write, old checkpoint must survive."""
        filepath = str(tmp_path / "checkpoint.json")
        save_checkpoint(filepath, {"id1"})
        save_checkpoint(filepath, {"id1", "id2", "id3"})
        with open(filepath) as f:
            data = json.load(f)
        assert len(data) == 3


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


class TestCheckpointThrottling:
    async def test_rapid_marks_throttle_writes(self, tmp_path: Path) -> None:
        """Rapid _mark_completed calls should not write on every call."""
        checkpoint_file = str(tmp_path / "checkpoint.json")
        config = ScanConfig(url="http://example.com", resume_file=checkpoint_file)
        scanner = Scanner(config)
        scanner._last_checkpoint_time = time.monotonic()  # Pretend we just wrote

        write_count = 0
        original_save = save_checkpoint

        def counting_save(*args: object, **kwargs: object) -> None:
            nonlocal write_count
            write_count += 1
            original_save(*args, **kwargs)

        with patch("panoptic.core.save_checkpoint", side_effect=counting_save):
            for i in range(20):
                case = Case(location=f"/etc/file{i}", os="*NIX")
                await scanner._mark_completed(case)

        assert write_count <= 1, f"Expected <=1 writes during throttle window, got {write_count}"

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
        assert set(data) == {"id1", "id2", "id3"}
        assert scanner._checkpoint_dirty is False
