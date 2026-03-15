"""Tests for panoptic.heuristic — the core detection logic."""

from panoptic.heuristic import clean_response, filter_content, is_match


class TestCleanResponse:
    def test_removes_filepath(self) -> None:
        response = "Error: /etc/passwd not found in /etc/passwd"
        cleaned = clean_response(response, "/etc/passwd")
        assert "/etc/passwd" not in cleaned

    def test_case_insensitive_removal(self) -> None:
        """Fixes original bug: re.sub passed re.I as count arg (line 488)."""
        response = "File /ETC/PASSWD was not found"
        cleaned = clean_response(response, "/etc/passwd")
        # The case-insensitive variant should also be removed
        assert "PASSWD" not in cleaned

    def test_handles_special_chars_in_filepath(self) -> None:
        response = "Looking for /var/log/app.log in system"
        cleaned = clean_response(response, "/var/log/app.log")
        assert "/var/log/app.log" not in cleaned

    def test_empty_response(self) -> None:
        assert clean_response("", "/etc/passwd") == ""

    def test_no_match(self) -> None:
        response = "Hello world"
        assert clean_response(response, "/etc/passwd") == "Hello world"


class TestIsMatch:
    def test_identical_responses_no_match(self) -> None:
        """If response matches invalid baseline, file was NOT found."""
        html = "<html>404 Not Found</html>"
        invalid = "<html>404 Not Found</html>"
        assert is_match(html, invalid) is False

    def test_different_responses_match(self) -> None:
        """If response differs from invalid baseline, file WAS found."""
        html = "root:x:0:0:root:/root:/bin/bash"
        invalid = "<html>404 Not Found</html>"
        assert is_match(html, invalid) is True

    def test_similar_responses_no_match(self) -> None:
        """Responses above heuristic ratio threshold are NOT matches."""
        html = "<html>File abc not found</html>"
        invalid = "<html>File xyz not found</html>"
        # These are very similar — should not be considered a match
        assert is_match(html, invalid, ratio=0.9) is False

    def test_custom_ratio(self) -> None:
        html = "Some response content here"
        invalid = "Some response content there"
        # With a very high ratio (strict), small differences count
        assert is_match(html, invalid, ratio=0.99) is True

    def test_none_html_returns_false(self) -> None:
        """Guard: if html is None, return False (fixes original crash)."""
        assert is_match(None, "invalid response") is False

    def test_none_invalid_returns_false(self) -> None:
        """Guard: if invalid_response is None, return False."""
        assert is_match("some html", None) is False


class TestFilterContent:
    def test_strips_common_prefix_suffix(self) -> None:
        original = "<html><head></head><body>ORIGINAL</body></html>"
        found = "<html><head></head><body>root:x:0:0</body></html>"
        filtered = filter_content(found, original)
        assert "root:x:0:0" in filtered
        # Common wrapping should be stripped
        assert not filtered.startswith("<html><head></head><body>")

    def test_no_common_content(self) -> None:
        original = "completely different content"
        found = "root:x:0:0:root:/root:/bin/bash"
        filtered = filter_content(found, original)
        assert filtered == found

    def test_empty_original(self) -> None:
        found = "some content"
        assert filter_content(found, "") == found
