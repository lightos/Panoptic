"""Tests for panoptic.heuristic — the core detection logic."""

import difflib
import itertools
import random
import time

import pytest

from panoptic import heuristic
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
        assert time.perf_counter() - started < 3.0

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

    def test_uncached_masks_stay_exact(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Symbols past the mask cache are rebuilt when used, never approximated."""
        monkeypatch.setattr(heuristic, "_MAX_CACHED_MASKS", 2)
        rng = random.Random(11)
        for _ in range(200):
            first = "".join(rng.choice("abcdefgh;<") for _ in range(rng.randint(0, 40)))
            second = "".join(rng.choice("abcdefgh;<") for _ in range(rng.randint(0, 40)))
            assert _lcs_length(first, second) == _reference_lcs(first, second)


def _two_pass_reference(first: str, second: str) -> float:
    """Unbudgeted reference: difflib segment opcodes, then difflib characters in replaced regions."""
    first, second = heuristic._normalize(first), heuristic._normalize(second)
    total = len(first) + len(second)
    if total == 0 or first == second:
        return 1.0
    a = [segment for segment in heuristic._SEGMENT_RE.findall(first) if segment]
    b = [segment for segment in heuristic._SEGMENT_RE.findall(second) if segment]
    matched = 0
    for tag, a_lo, a_hi, b_lo, b_hi in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        if tag == "equal":
            matched += sum(map(len, a[a_lo:a_hi]))
        elif tag == "replace":
            region = difflib.SequenceMatcher(None, "".join(a[a_lo:a_hi]), "".join(b[b_lo:b_hi]), autojunk=False)
            matched += sum(block.size for block in region.get_matching_blocks())
    return 2 * matched / total


def _random_page(rng: random.Random, rows: int) -> str:
    words = ["the", "file", "not", "found", "error", "a", "", " ", "<p>", "</p>", "<br>", "\n", "\r\n", "x"]
    return "".join(rng.choice(words) for _ in range(rows))


def _exhausted(first: str, second: str) -> bool:
    """Whether the comparison runs out of work at the current allowance.

    An interrupted search always leaves a range with content on both sides,
    which is then scored by ``_range_lcs``; completed searches never call it.
    """
    calls: list[int] = []
    original = heuristic._range_lcs

    def spy(x: str, y: str) -> int:
        calls.append(1)
        return original(x, y)

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(heuristic, "_range_lcs", spy)
        similarity(first, second)
    return bool(calls)


class TestSimilarityContract:
    """The agreed contract: exact two-pass SequenceMatcher scores within the allowance, bounded fallback past it."""

    def test_segments_concatenate_back_to_the_text(self) -> None:
        for text in ["", ">", "\n", "a", "a>b\nc", "no delimiters", "<a><b>\r\n</b>\n\ntail", ">>\n\n>"]:
            segments = [segment for segment in heuristic._SEGMENT_RE.findall(text) if segment]
            assert "".join(segments) == text

    def test_exhaustive_short_texts_match_reference(self) -> None:
        texts = ["".join(chars) for n in range(5) for chars in itertools.product("a>\n", repeat=n)]
        for first in texts:
            for second in texts:
                assert similarity(first, second) == pytest.approx(_two_pass_reference(first, second), abs=1e-12)

    def test_random_texts_match_reference_in_both_orders(self) -> None:
        rng = random.Random(42)
        for _ in range(1500):
            first = _random_page(rng, rng.randint(0, 60))
            second = _random_page(rng, rng.randint(0, 60))
            for x, y in ((first, second), (second, first)):
                assert similarity(x, y) == pytest.approx(_two_pass_reference(x, y), abs=1e-12)

    def test_edge_trimming_is_not_applied_on_the_exact_path(self) -> None:
        """SequenceMatcher matches 2 characters here; trimming common edges would credit 3."""
        assert similarity("aaa", "abaa") == pytest.approx(4 / 7)

    def test_replaced_segments_without_common_segments_are_compared_by_character(self) -> None:
        assert similarity("<p>Not found</p>", "<p>Not found.</p>") > 0.9

    def test_fallback_never_scores_below_reference(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rng = random.Random(9)
        for budget in (0, 1, 2, 5, 20, 100, 1000):
            monkeypatch.setattr(heuristic, "_MAX_MATCH_WORK", budget)
            for _ in range(150):
                first = _random_page(rng, rng.randint(0, 50))
                second = _random_page(rng, rng.randint(0, 50))
                score = similarity(first, second)
                assert 0.0 <= score <= 1.0
                assert score >= _two_pass_reference(first, second) - 1e-12

    def test_score_is_exact_from_the_minimum_sufficient_allowance(self, monkeypatch: pytest.MonkeyPatch) -> None:
        rng = random.Random(5)
        for _ in range(40):
            first = _random_page(rng, 40)
            second = _random_page(rng, 40)
            reference = _two_pass_reference(first, second)
            low, high = 0, 100_000
            monkeypatch.setattr(heuristic, "_MAX_MATCH_WORK", high)
            assert not _exhausted(first, second)
            while low < high:  # smallest allowance that never falls back
                middle = (low + high) // 2
                monkeypatch.setattr(heuristic, "_MAX_MATCH_WORK", middle)
                if _exhausted(first, second):
                    low = middle + 1
                else:
                    high = middle
            monkeypatch.setattr(heuristic, "_MAX_MATCH_WORK", low)
            assert similarity(first, second) == pytest.approx(reference, abs=1e-12)
            if low:
                monkeypatch.setattr(heuristic, "_MAX_MATCH_WORK", low - 1)
                assert _exhausted(first, second)
                assert similarity(first, second) >= reference - 1e-12

    def test_allowance_is_shared_across_character_regions(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Many individually cheap replaced regions must not each get a fresh allowance."""
        first = "".join(
            f"<li id={_minified(1)[:3]}{chr(97 + i // 26)}{chr(97 + i % 26)}>item a</li>" for i in range(200)
        )
        second = "".join(
            f"<li id={_minified(1)[:3]}{chr(97 + i // 26)}{chr(97 + i % 26)}>item b!</li>" for i in range(200)
        )
        segments_a = [segment for segment in heuristic._SEGMENT_RE.findall(heuristic._normalize(first)) if segment]
        segments_b = [segment for segment in heuristic._SEGMENT_RE.findall(heuristic._normalize(second)) if segment]
        work = heuristic._Work()
        heuristic._matching_blocks(segments_a, segments_b, work)
        segment_work = heuristic._MAX_MATCH_WORK - work.left
        assert not work.exhausted
        # Enough for the segment pass and a few of the 200 character regions.
        monkeypatch.setattr(heuristic, "_MAX_MATCH_WORK", segment_work + 100)
        assert _exhausted(first, second)
        assert similarity(first, second) >= _two_pass_reference(first, second) - 1e-12
        monkeypatch.undo()
        assert not _exhausted(first, second)
        assert similarity(first, second) == pytest.approx(_two_pass_reference(first, second), abs=1e-12)

    def test_repetitive_template_is_bounded(self) -> None:
        """Repeated segments make the segment pass itself expensive; the allowance still bounds it."""
        first = "".join(f"<p>alpha beta {chr(97 + i % 26)}</p>\n<hr>\n" for i in range(2000))
        second = "".join(f"<p>alpha beta {chr(98 + i % 25)}!</p>\n<hr>\n" for i in range(2000))
        started = time.perf_counter()
        assert 0.9 < similarity(first, second) <= 1.0
        assert time.perf_counter() - started < 2.0


_VIEWER = (
    "<html><head><title>Document viewer</title></head><body><h1>Document preview</h1>",
    '<a href="/">Return to the document list</a>',
    "</pre><footer>Document viewer</footer></body></html>",
)
_PLAIN_ERROR = "The requested file could not be found. Please check the file name and try again."
_PHP_ERROR = (
    "Warning: include(): Failed opening '' for inclusion "
    "(include_path='.:/usr/share/php') in /var/www/html/index.php on line 12"
)
_PASSWD_ROOT = "root:x:0:0:root:/root:/bin/bash\n"
_PASSWD_TWO = _PASSWD_ROOT + "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n"
_SSH_CONFIG = "Host *\n    ForwardAgent no\n    ForwardX11 no\n    PasswordAuthentication yes\n    SendEnv LANG LC_*\n"
_NGINX_CONFIG = (
    "server {\n    listen 80;\n    server_name localhost;\n    root /var/www/html;\n    index index.html;\n}\n"
)
_HOSTS = "127.0.0.1 localhost\n127.0.1.1 webserver\n::1 localhost ip6-localhost ip6-loopback\n"


class TestReviewedClassifications:
    """Labeled cases from the Codex reviews of the similarity rewrite."""

    @pytest.mark.parametrize(
        ("content", "error", "links"),
        [
            (_PASSWD_TWO, _PLAIN_ERROR, 9),
            (_PASSWD_ROOT, _PHP_ERROR, 10),
            (_PASSWD_TWO, _PHP_ERROR, 13),
            (_SSH_CONFIG, _PLAIN_ERROR, 9),
            (_SSH_CONFIG, _PHP_ERROR, 13),
            (_NGINX_CONFIG, _PLAIN_ERROR, 9),
            (_NGINX_CONFIG, _PHP_ERROR, 11),
            (_HOSTS, _PHP_ERROR, 17),
        ],
    )
    def test_short_file_in_document_viewer_is_found(self, content: str, error: str, links: int) -> None:
        wrapper = _VIEWER[0] + _VIEWER[1] * links + "<pre>"
        assert is_match(wrapper + content + _VIEWER[2], wrapper + error + _VIEWER[2]) is True

    def test_unique_characters_in_reversed_blocks_are_found(self) -> None:
        blocks = ["".join(chr(0x4E00 + block * 1024 + offset) for offset in range(1024)) for block in range(20)]
        assert is_match("".join(blocks), "".join(reversed(blocks))) is True

    @pytest.mark.parametrize(
        ("baseline", "response"),
        [
            (
                "<html>\n" + (" " * 8 + "<p>The requested document could not be found.</p>\n") * 12 + "</html>",
                "<html>\n" + (" " * 9 + "<p>The requested document could not be found.</p>\n") * 12 + "</html>",
            ),
            (
                "<html>\n<body>\n<p>Not found</p>\n" * 20 + "</body></html>\n",
                ("<html>\n<body>\n<p>Not found</p>\n" * 20 + "</body></html>\n").replace("\n", "\r\n"),
            ),
            (
                '<html><body><p class="documentPreviewUnavailable">The requested file is unavailable.</p>' * 2
                + "</body></html>",
                '<html><body><p class="documentPreviewNotAvailable">The requested file is unavailable.</p>' * 2
                + "</body></html>",
            ),
            (
                '<script>window.requestId="alpha";'
                + 'window.renderError("File_not_found");' * 100
                + 'window.traceId="first";</script>',
                '<script>window.requestId="bravo";'
                + 'window.renderError("File_not_found");' * 100
                + 'window.traceId="other";</script>',
            ),
            (
                '{"request":"bravo","detail":"' + "resource_unavailable;" * 200 + '","trace":"other"}',
                '{"request":"alpha","detail":"' + "resource_unavailable;" * 200 + '","trace":"first"}',
            ),
            ("Y;" + "alpha();!" * 400 + "right", "X;" + "alpha();" * 400 + "left"),
        ],
        ids=["indentation", "crlf", "class-rename", "minified-script", "compact-json", "repetitive-statements"],
    )
    def test_formatting_and_small_edits_are_not_found(self, baseline: str, response: str) -> None:
        started = time.perf_counter()
        assert is_match(response, baseline) is False
        assert time.perf_counter() - started < 1.0
