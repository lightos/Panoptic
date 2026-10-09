"""Tests for panoptic.heuristic — the core detection logic."""

import random
import time

from panoptic.heuristic import (
    MAX_COMPARE_LENGTH,
    _lcs_length,
    clean_response,
    filter_content,
    is_match,
    similarity,
)


def _minified(count: int) -> str:
    """Minified-looking script: no whitespace, distinct letter identifiers (digits are normalized away)."""

    def name(index: int) -> str:
        letters = ""
        index += 26 * 27
        while index:
            index, rest = divmod(index, 26)
            letters = chr(97 + rest) + letters
        return letters

    return "".join(f"{name(i)}=function(a,b){{return!a.{name(i)}Get(b)&&b;}};{name(i)}V=[a,b];" for i in range(count))


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

    def test_small_edit_in_long_single_segment_response(self) -> None:
        """A one-character edit in a region too long to compare by character is not a found file."""
        page = "Error: " + "the requested resource could not be located on this server " * 50
        edited = page[:1500] + "X" + page[1501:]
        assert similarity(page, edited) > 0.99
        assert is_match(edited, page) is False

    def test_separated_edits_in_minified_response(self) -> None:
        """Edits near both ends of a response without whitespace leave a long differing middle."""
        page = _minified(80)
        start, end = len(page) // 20, len(page) * 19 // 20
        edited = page[:start] + "ZZ" + page[start + 2 : end] + "YY" + page[end + 2 :]
        assert similarity(page, edited) > 0.99
        assert is_match(edited, page) is False

    def test_file_inside_long_minified_response_is_found(self) -> None:
        page = _minified(80)
        found = page[:2000] + "root:x:0:0:root:/root:/bin/bash\n" * 40 + page[2000:]
        assert is_match(found, page) is True

    def test_file_inside_long_single_segment_response_is_found(self) -> None:
        page = "Error: " + "the requested resource could not be located on this server " * 50
        found = page[:1500] + "root:x:0:0:root:/root:/bin/bash daemon:x:1:1:daemon " * 40 + page[1500:]
        assert is_match(found, page) is True


class TestSimilarityPerformance:
    def _large_page(self) -> str:
        return "<html><body>" + "".join(f"<p class='row'>entry {i} text</p>\n" for i in range(3000)) + "</body></html>"

    def test_large_mostly_equal_pages_are_fast_and_accurate(self) -> None:
        base = self._large_page()[:MAX_COMPARE_LENGTH]
        found = base[:30000] + "<pre>" + "root:x:0:0:root:/root:/bin/bash\n" * 300 + "</pre>" + base[30000:]
        started = time.perf_counter()
        assert is_match(found, base) is True
        assert time.perf_counter() - started < 1.0

    def test_long_differing_single_segment_responses_are_bounded(self) -> None:
        first = " ".join(f"alpha{i % 97}beta" for i in range(8000))[:MAX_COMPARE_LENGTH]
        second = " ".join(f"gamma{i % 89}delta" for i in range(8000))[:MAX_COMPARE_LENGTH]
        started = time.perf_counter()
        assert similarity(first, second) < 0.9
        assert time.perf_counter() - started < 1.0

    def test_large_minified_page_with_separated_edits_is_fast_and_accurate(self) -> None:
        page = _minified(2000)[:MAX_COMPARE_LENGTH]
        edited = "".join("Q" if i % 1300 == 0 else char for i, char in enumerate(page))
        started = time.perf_counter()
        assert similarity(page, edited) > 0.99
        assert time.perf_counter() - started < 1.0

    def test_repetitive_large_responses_are_bounded(self) -> None:
        first = "".join("ab;"[(i * 7) % 3 if i % 5 else i % 2] for i in range(MAX_COMPARE_LENGTH))
        second = "".join("ab;"[(i * 5) % 3 if i % 7 else i % 2] for i in range(MAX_COMPARE_LENGTH))
        started = time.perf_counter()
        similarity(first, second)
        assert time.perf_counter() - started < 2.0

    def test_repetitive_punctuation_is_fast(self) -> None:
        """Repetitive tokens made difflib's matcher take seconds on a few KB."""
        first = "X;" + "alpha();" * 400 + "left"
        second = "Y;" + "alpha();!" * 400 + "right"
        started = time.perf_counter()
        assert similarity(first, second) > 0.9
        assert time.perf_counter() - started < 1.0

    def test_many_distinct_characters_are_bounded(self) -> None:
        first = "".join(chr(0x4E00 + (i * 7919) % 30000) for i in range(MAX_COMPARE_LENGTH))
        second = "".join(chr(0x4E00 + (i * 104729) % 30000) for i in range(MAX_COMPARE_LENGTH))
        started = time.perf_counter()
        assert similarity(first, second) < 0.9
        assert time.perf_counter() - started < 2.0

    def test_reordered_large_page_is_bounded(self) -> None:
        lines = self._large_page().split("\n")
        reordered = "\n".join(reversed(lines))
        started = time.perf_counter()
        similarity(reordered, "\n".join(lines))
        assert time.perf_counter() - started < 1.0


def _reference_lcs(first: str, second: str) -> int:
    previous = [0] * (len(second) + 1)
    for char in first:
        current = [0]
        for index, other in enumerate(second):
            current.append(previous[index] + 1 if char == other else max(previous[index + 1], current[index]))
        previous = current
    return previous[-1]


class TestLcsLength:
    def test_matches_reference_dynamic_programming(self) -> None:
        rng = random.Random(7)
        for _ in range(300):
            first = "".join(rng.choice("ab;<") for _ in range(rng.randint(0, 40)))
            second = "".join(rng.choice("ab;<") for _ in range(rng.randint(0, 40)))
            assert _lcs_length(first, second) == _reference_lcs(first, second)

    def test_bucketed_alphabet_never_undercounts(self) -> None:
        """Past the alphabet cap rare characters share a mask, which can only add matches."""
        first = "".join(chr(0x4E00 + i) for i in range(3000)) + "abc"
        second = "".join(chr(0x4E00 + 2999 - i) for i in range(3000)) + "abc"
        assert _lcs_length(first, second) >= _reference_lcs(first[-200:], second[-200:])
