"""Tests for panoptic.heuristic — the core detection logic."""

import time

from panoptic.heuristic import MAX_COMPARE_LENGTH, clean_response, filter_content, is_match, similarity


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

    def test_reordered_body_uses_full_similarity_ratio(self) -> None:
        """Bodies with identical character counts but different structure must differ."""
        found = "A" * 5000 + "B" * 5000
        invalid = "AB" * 5000
        assert is_match(found, invalid) is True


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


class TestFuzzyPathWildcards:
    def test_separators_still_match_encoded_reflections(self) -> None:
        assert clean_response("missing: _etc_passwd!", "/etc/passwd") == "missing: !"

    def test_alphanumeric_content_is_not_treated_as_separator(self) -> None:
        """File content like 'xetcXpasswd' must survive cleaning for '/etc/passwd'."""
        assert clean_response("xetcXpasswd", "/etc/passwd") == "xetcXpasswd"
        assert is_match("xetcXpasswd", "")


class TestDynamicPages:
    PAGE = (
        "<html><head><meta name='csrf' content='{token}'></head>\n<body><p>Rendered at {ts}</p>\n{body}</body></html>\n"
    )

    def _page(self, token: str, ts: str, body: str = "") -> str:
        filler = "".join(f"<p>static paragraph number {i}</p>\n" for i in range(40))
        return self.PAGE.format(token=token, ts=ts, body=filler + body)

    def test_volatile_tokens_do_not_look_like_a_found_file(self) -> None:
        """Pages over 200 chars differing only in tokens/timestamps are the same page."""
        first = self._page("8a7f151c2eb11d4246da6ae6ec3f730e", "1759912345")
        second = self._page("5c3feb74cca2c5f2eabf58b684f489b4", "1759912399")
        assert similarity(first, second) == 1.0
        assert is_match(first, second) is False

    def test_file_inside_dynamic_page_is_found(self) -> None:
        baseline = self._page("5c3feb74cca2c5f2eabf58b684f489b4", "1759912399")
        found = self._page(
            "8a7f151c2eb11d4246da6ae6ec3f730e",
            "1759912345",
            "<pre>" + "root:x:0:0:root:/root:/bin/bash\n" * 20 + "</pre>",
        )
        assert is_match(found, baseline) is True

    def test_token_shaped_file_content_keeps_its_weight(self) -> None:
        """Base64 key material normalizes to placeholders of equal length, not to nothing."""
        baseline = self._page("5c3feb74cca2c5f2eabf58b684f489b4", "1")
        key = "\n".join("b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW" for _ in range(25))
        found = self._page("5c3feb74cca2c5f2eabf58b684f489b4", "1", f"<pre>{key}</pre>")
        assert is_match(found, baseline) is True

    def test_long_words_are_not_treated_as_tokens(self) -> None:
        assert similarity("A" * 5000 + "B" * 5000, "AB" * 5000) < 0.9

    def test_small_difference_in_single_segment_response(self) -> None:
        assert similarity("File not found:\n", "File not found: \n") > 0.9


class TestSimilarityPerformance:
    def _large_page(self) -> str:
        return "<html><body>" + "".join(f"<p class='row'>entry {i} text</p>\n" for i in range(3000)) + "</body></html>"

    def test_large_mostly_equal_pages_are_fast_and_accurate(self) -> None:
        base = self._large_page()[:MAX_COMPARE_LENGTH]
        found = base[:30000] + "<pre>" + "root:x:0:0:root:/root:/bin/bash\n" * 300 + "</pre>" + base[30000:]
        started = time.perf_counter()
        assert is_match(found, base) is True
        assert time.perf_counter() - started < 1.0

    def test_reordered_large_page_is_bounded(self) -> None:
        lines = self._large_page().split("\n")
        reordered = "\n".join(reversed(lines))
        started = time.perf_counter()
        similarity(reordered, "\n".join(lines))
        assert time.perf_counter() - started < 1.0
