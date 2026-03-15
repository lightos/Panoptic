"""Tests for panoptic.core — async scanner orchestrator."""

from pathlib import Path

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
