"""Heuristic response comparison engine for Panoptic.

All functions are pure (no side effects, no globals) for testability.
"""

from __future__ import annotations

import bisect
import difflib
import functools
import html as html_lib
import os
import re
from collections.abc import Sequence
from urllib.parse import unquote

# Default similarity ratio above which responses are considered "the same"
DEFAULT_HEURISTIC_RATIO = 0.9

# Maximum number of characters of a response body that are cleaned and compared.
# Comparison is quadratic in the body size, so unbounded bodies could stall the
# scan; the start of a response is enough to tell a hit from the baseline.
MAX_COMPARE_LENGTH = 64 * 1024

# Volatile values that differ between otherwise identical responses (CSRF
# tokens, nonces, session IDs, timestamps, counters) are replaced before
# comparison so dynamic pages don't look like a found file.
# Token candidates only count as volatile when they mix letters and digits, as
# random hex/base64 values do; plain words and repeated characters are kept.
_VOLATILE_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_-]{16,}={0,2}|\d+")
_HAS_LETTER_RE = re.compile(r"[A-Za-z]")


def _normalize_token(match: re.Match[str]) -> str:
    token = match.group(0)
    if token.isdigit() or (_HAS_LETTER_RE.search(token) and any(char.isdigit() for char in token)):
        # Keep the length so found content made of tokens (e.g. base64 key
        # material) still weighs as much as it did before normalization.
        return "0" * len(token)
    return token


# Responses are split into segments (lines, and runs ending in ">" so minified
# HTML still splits). Segments are matched first, then the characters of each
# region that differs, both with SequenceMatcher's matching blocks (as with
# ``autojunk=False``): the segment pass localizes the differences so the
# character pass stays small on template pages.
_SEGMENT_RE = re.compile(r"[^\n>]*(?:[\n>]|$)")

# Both passes are reimplemented so their work can be capped: every row of a
# longest-match search is charged, before it runs, one unit plus the number of
# positions inside the searched range (found by bisection), against one
# allowance per comparison. A server
# controls the bodies, and repetitive ones would otherwise stall the scan.
_MAX_MATCH_WORK = 2_000_000

# Once the allowance is spent, the ranges still unresolved are scored by their
# longest common subsequence of characters, computed bit-parallel: one pass of
# big-integer operations per character of the shorter range, so the cost
# depends only on the range sizes. Bit masks of the most frequent characters
# are kept; the others are rebuilt when used, which bounds memory without
# approximating.
_MAX_CACHED_MASKS = 2048


# Paths longer than this are only removed literally (case-insensitively) rather
# than through the per-character wildcard pattern.
_MAX_FUZZY_PATH_LENGTH = 256


def _decode_reflections(text: str) -> str:
    """Decode percent-escapes and HTML entities so encoded reflections compare equal."""
    if "%" in text:
        text = unquote(text, errors="replace")
    if "&" in text:
        text = html_lib.unescape(text)
    return text


@functools.lru_cache(maxsize=1024)
def _fuzzy_path_pattern(filepath: str) -> re.Pattern[str]:
    """Compile a linear-time pattern matching ``filepath`` with any separator characters.

    Every non-alphanumeric character becomes a single non-alphanumeric wildcard
    (so file content like ``xetcXpasswd`` is not mistaken for ``/etc/passwd``)
    and every alphanumeric character is literal. The pattern has no alternation or
    quantifiers, so matching cannot backtrack catastrophically.
    """
    if len(filepath) <= _MAX_FUZZY_PATH_LENGTH and any(char.isalnum() for char in filepath):
        regex = "".join(re.escape(char) if char.isalnum() else "[^0-9a-z]" for char in filepath)
    else:
        # Very long paths, or paths without any literal anchor (a pure wildcard
        # pattern would erase arbitrary text), are removed literally.
        regex = re.escape(filepath)
    return re.compile(regex, flags=re.I)


def clean_response(response: str, *filepaths: str) -> str:
    """Remove reflections of a filepath (and its transformed variants) from a response.

    Used to normalize responses before comparison so the requested path, which
    servers often echo back in error pages, doesn't affect the heuristic match.
    ``filepaths`` holds the requested path plus transformed forms that were actually
    sent (e.g. with prefix/postfix, replace-slash, Base64 or URL encoding).
    With no non-empty paths only the truncation and decoding apply.

    The response is truncated to MAX_COMPARE_LENGTH characters. Exact
    occurrences are removed first; the remaining text then has percent-escapes
    and HTML entities decoded, and each decoded path is removed
    case-insensitively with non-alphanumeric characters treated as wildcards.
    """
    if not response:
        return ""

    response = response[:MAX_COMPARE_LENGTH]
    # Longest first, so a short path does not break up a longer reflection
    # (e.g. removing "/etc/passwd" from "../../etc/passwd" would leave "../..").
    needles = sorted({path for path in filepaths if path}, key=len, reverse=True)

    # Direct string replacement (case-sensitive)
    for needle in needles:
        response = response.replace(needle, "")

    # Encoded/escaped variants: decode the response, then remove decoded paths.
    response = _decode_reflections(response)
    decoded_needles = sorted({_decode_reflections(needle) for needle in needles}, key=len, reverse=True)
    for needle in decoded_needles:
        if needle:
            response = _fuzzy_path_pattern(needle).sub("", response)

    return response


def is_match(
    html: str | None,
    invalid_response: str | None,
    ratio: float = DEFAULT_HEURISTIC_RATIO,
) -> bool:
    """Determine if an HTML response indicates a file was found.

    Compares the response against the invalid (baseline) response.
    If the similarity ratio is below the threshold, the responses are
    considered different enough that the file was likely found.

    Only the first MAX_COMPARE_LENGTH characters of each body are compared.

    Returns True if the file appears to be found, False otherwise.
    """
    if html is None or invalid_response is None:
        return False

    html = html[:MAX_COMPARE_LENGTH]
    invalid_response = invalid_response[:MAX_COMPARE_LENGTH]
    if html == invalid_response:
        return False

    return similarity(html, invalid_response) < ratio


def _normalize(text: str) -> str:
    return _VOLATILE_TOKEN_RE.sub(_normalize_token, text[:MAX_COMPARE_LENGTH])


def similarity(first: str, second: str) -> float:
    """Return a 0..1 similarity of two responses, ignoring volatile tokens.

    The ratio is 2 * matched / total characters of the normalized texts, where
    matched counts the characters of segments matched as SequenceMatcher would
    match the two segment lists, plus, in each region where segments differ,
    the characters SequenceMatcher would match between the two regions. When
    the work allowance runs out, regions left unresolved are scored by their
    longest common subsequence instead. Only the first MAX_COMPARE_LENGTH
    characters of each text are compared.
    """
    first, second = _normalize(first), _normalize(second)
    total = len(first) + len(second)
    if total == 0 or first == second:
        return 1.0
    return 2 * _matched_characters(first, second) / total


class _Work:
    """The work allowance shared by every search of one comparison."""

    def __init__(self) -> None:
        self.left = _MAX_MATCH_WORK
        self.exhausted = False


def _matched_characters(first: str, second: str) -> int:
    work = _Work()
    a = [segment for segment in _SEGMENT_RE.findall(first) if segment]
    b = [segment for segment in _SEGMENT_RE.findall(second) if segment]
    a_offsets = _offsets(a)
    b_offsets = _offsets(b)
    matched = 0
    # Regions between matched segments, in order: replaced segments are compared
    # by character; inserted or deleted ones match nothing.
    a_pos = b_pos = 0
    for i, j, size in [*_matching_blocks(a, b, work), (len(a), len(b), 0)]:
        if a_pos < i and b_pos < j:
            matched += _matched_in_region(
                first[a_offsets[a_pos] : a_offsets[i]], second[b_offsets[b_pos] : b_offsets[j]], work
            )
        matched += a_offsets[i + size] - a_offsets[i]
        a_pos, b_pos = i + size, j + size
    return matched


def _offsets(segments: list[str]) -> list[int]:
    offsets = [0]
    for segment in segments:
        offsets.append(offsets[-1] + len(segment))
    return offsets


def _matched_in_region(a: str, b: str, work: _Work) -> int:
    """Return the characters matched between two differing regions."""
    if work.exhausted:
        return _range_lcs(a, b)
    matched = 0
    a_pos = b_pos = 0
    for i, j, size in [*_matching_blocks(a, b, work), (len(a), len(b), 0)]:
        # A gap left by a completed search shares no characters; only an
        # interrupted search leaves gaps that still need scoring.
        if work.exhausted and a_pos < i and b_pos < j:
            matched += _range_lcs(a[a_pos:i], b[b_pos:j])
        matched += size
        a_pos, b_pos = i + size, j + size
    return matched


def _matching_blocks(a: Sequence[str], b: Sequence[str], work: _Work) -> list[tuple[int, int, int]]:
    """Return SequenceMatcher's matching blocks (i, j, size), sorted, without the sentinel.

    Mirrors ``get_matching_blocks()``: find the longest common block, then
    repeat on the ranges to its left and right. If the allowance runs out, the
    search stops with the blocks completed so far; the interrupted range and
    those still queued are the gaps between them.
    """
    b2j: dict[str, list[int]] = {}
    for j, item in enumerate(b):
        b2j.setdefault(item, []).append(j)
    blocks: list[tuple[int, int, int]] = []
    queue = [(0, len(a), 0, len(b))]
    while queue:
        alo, ahi, blo, bhi = queue.pop()
        found = _longest_match(a, b2j, alo, ahi, blo, bhi, work)
        if found is None:
            break
        i, j, size = found
        if size:
            blocks.append(found)
            if alo < i and blo < j:
                queue.append((alo, i, blo, j))
            if i + size < ahi and j + size < bhi:
                queue.append((i + size, ahi, j + size, bhi))
    blocks.sort()
    return blocks


def _longest_match(
    a: Sequence[str], b2j: dict[str, list[int]], alo: int, ahi: int, blo: int, bhi: int, work: _Work
) -> tuple[int, int, int] | None:
    """``SequenceMatcher.find_longest_match`` without junk, charged against ``work``.

    Returns (i, j, size), or None when a row would exceed the allowance: the
    comparison is then marked exhausted and the partial result is discarded.
    Ties go to the earliest block in ``a``, then in ``b``, as in difflib.
    """
    besti, bestj, bestsize = alo, blo, 0
    j2len: dict[int, int] = {}
    nothing: list[int] = []
    for i in range(alo, ahi):
        positions = b2j.get(a[i], nothing)
        start = bisect.bisect_left(positions, blo)
        stop = bisect.bisect_left(positions, bhi, start)
        cost = 1 + stop - start
        if cost > work.left:
            work.exhausted = True
            return None
        work.left -= cost
        new_j2len: dict[int, int] = {}
        for j in positions[start:stop]:
            k = new_j2len[j] = j2len.get(j - 1, 0) + 1
            if k > bestsize:
                besti, bestj, bestsize = i - k + 1, j - k + 1, k
        j2len = new_j2len
    return besti, bestj, bestsize


def _range_lcs(a: str, b: str) -> int:
    """Return the longest common subsequence length, counting common ends directly."""
    prefix = len(os.path.commonprefix([a, b]))
    a, b = a[prefix:], b[prefix:]
    suffix = len(os.path.commonprefix([a[::-1], b[::-1]]))
    if suffix:
        a, b = a[:-suffix], b[:-suffix]
    return prefix + suffix + _lcs_length(a, b)


def _lcs_length(first: str, second: str) -> int:
    """Return the length of the longest common subsequence of two strings.

    Bit-parallel dynamic programming (Allison-Dix / Hyyro): each bit of ``row``
    is one column of the DP table over the longer string, and every character
    of the shorter string updates the whole row with a few integer operations.
    """
    if len(first) < len(second):
        first, second = second, first
    if not second:
        return 0
    shared = set(first) & set(second)
    if not shared:
        return 0
    positions: dict[str, list[int]] = {}
    for index, char in enumerate(first):
        if char in shared:
            positions.setdefault(char, []).append(index)
    size = (len(first) + 7) // 8

    def mask(indexes: list[int]) -> int:
        bits = bytearray(size)
        for index in indexes:
            bits[index >> 3] |= 1 << (index & 7)
        return int.from_bytes(bits, "little")

    frequent = sorted(positions, key=lambda char: len(positions[char]), reverse=True)
    cached = {char: mask(positions[char]) for char in frequent[:_MAX_CACHED_MASKS]}
    full = (1 << len(first)) - 1
    row = full
    for char in second:
        if char in shared:
            char_mask = cached.get(char)
            if char_mask is None:
                char_mask = mask(positions[char])
            matches = row & char_mask
            row = ((row + matches) | (row - matches)) & full
    return len(first) - row.bit_count()


def filter_content(html: str, original_response: str) -> str:
    """Filter retrieved file content from surrounding HTML page content.

    Strips common prefix/suffix between the found response and the original
    (no-payload) response, leaving just the file content.
    Used when --write-files is active.
    """
    if not original_response:
        return html

    matcher = difflib.SequenceMatcher(None, html, original_response)
    matching_blocks = matcher.get_matching_blocks()

    content = html

    if matching_blocks:
        # Strip common prefix
        start = matching_blocks[0]
        if start.a == start.b == 0 and start.size > 0:
            content = content[start.size :]

        # Strip common suffix
        if len(matching_blocks) > 2:
            end = matching_blocks[-2]
            if end.size > 0 and end.a + end.size == len(html) and end.b + end.size == len(original_response):
                content = content[: -end.size]

    return content
