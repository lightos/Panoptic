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
from collections import Counter
from urllib.parse import unquote

# Default similarity ratio above which responses are considered "the same"
DEFAULT_HEURISTIC_RATIO = 0.9

# Maximum number of characters of a response body that are cleaned and compared.
# SequenceMatcher is quadratic in the worst case, so unbounded bodies could stall
# the scan; the start of a response is enough to tell a hit from the baseline.
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


# Responses are compared as segments (lines, and runs ending in ">" so minified
# HTML still splits), weighted by length. Comparing characters instead is either
# quadratic (autojunk off) or wrong for text over 200 characters (autojunk on
# discards every character that is common in the page).
_SEGMENT_RE = re.compile(r"[^\n>]*(?:[\n>]|$)")

# Differing regions are compared character by character while the summed
# products of their lengths stay within this budget, bounding the quadratic
# worst case. Larger regions are split into tokens and aligned on tokens that
# occur once on each side (as patience diff does); only what cannot be
# anchored that way and is still over budget counts as entirely different.
_MAX_CHAR_COMPARE_CELLS = 4_000_000
# Tokens for regions too large to compare character by character: words,
# whitespace runs and single punctuation characters, so minified code and JSON
# without whitespace still split into small, mostly distinctive pieces.
_TOKEN_RE = re.compile(r"\w+|\s+|[^\w\s]")

# Differing segment regions are aligned in order only below this size
# (segments x segments); larger ones fall back to an order-insensitive count.
_MAX_SEGMENT_COMPARE_CELLS = 250_000

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


def _segments(text: str) -> list[str]:
    normalized = _VOLATILE_TOKEN_RE.sub(_normalize_token, text)
    return [segment for segment in _SEGMENT_RE.findall(normalized) if segment]


def similarity(first: str, second: str) -> float:
    """Return a 0..1 similarity of two responses, ignoring volatile tokens.

    Equivalent to ``SequenceMatcher.ratio()`` (2 * matched / total) on the
    normalized text, but computed in two passes so it stays fast on large pages:
    whole segments are matched first, then each differing region is compared
    character by character when it is small enough to do so cheaply.
    """
    first_segments = _segments(first)
    second_segments = _segments(second)
    total = sum(map(len, first_segments)) + sum(map(len, second_segments))
    if total == 0:
        return 1.0
    # Pages usually share a template and differ in one region: count the common
    # leading and trailing segments directly and match only the middle.
    prefix = 0
    limit = min(len(first_segments), len(second_segments))
    while prefix < limit and first_segments[prefix] == second_segments[prefix]:
        prefix += 1
    suffix = 0
    while (
        suffix < limit - prefix
        and first_segments[len(first_segments) - 1 - suffix] == second_segments[len(second_segments) - 1 - suffix]
    ):
        suffix += 1
    matched = sum(map(len, first_segments[:prefix])) + sum(map(len, first_segments[len(first_segments) - suffix :]))
    first_segments = first_segments[prefix : len(first_segments) - suffix]
    second_segments = second_segments[prefix : len(second_segments) - suffix]
    if len(first_segments) * len(second_segments) > _MAX_SEGMENT_COMPARE_CELLS:
        # Too many differing segments to align (e.g. heavily reordered pages):
        # count shared segments regardless of order, which is linear.
        shared = Counter(first_segments) & Counter(second_segments)
        matched += sum(len(segment) * count for segment, count in shared.items())
        return 2 * matched / total
    matcher = difflib.SequenceMatcher(None, first_segments, second_segments, autojunk=False)
    budget = _MAX_CHAR_COMPARE_CELLS
    for tag, a_start, a_end, b_start, b_end in matcher.get_opcodes():
        if tag == "equal":
            matched += sum(map(len, first_segments[a_start:a_end]))
        elif tag == "replace":
            region_matched, budget = _match_region(
                "".join(first_segments[a_start:a_end]), "".join(second_segments[b_start:b_end]), budget
            )
            matched += region_matched
    return 2 * matched / total


def _match_region(a_text: str, b_text: str, budget: int) -> tuple[int, int]:
    """Return the characters two differing regions share, and the budget left.

    The common leading and trailing characters are counted directly, so a long
    region with a small edit (e.g. a single-line page) is not scored as wholly
    different. The rest is matched by character within the budget, else by
    anchored tokens.
    """
    prefix = len(os.path.commonprefix([a_text, b_text]))
    a_text, b_text = a_text[prefix:], b_text[prefix:]
    suffix = len(os.path.commonprefix([a_text[::-1], b_text[::-1]]))
    if suffix:
        a_text, b_text = a_text[:-suffix], b_text[:-suffix]
    matched = prefix + suffix
    cells = len(a_text) * len(b_text)
    if cells <= budget:
        blocks = difflib.SequenceMatcher(None, a_text, b_text, autojunk=False).get_matching_blocks()
        return matched + sum(block.size for block in blocks), budget - cells
    token_matched, budget = _match_tokens(_TOKEN_RE.findall(a_text), _TOKEN_RE.findall(b_text), budget)
    return matched + token_matched, budget


def _match_tokens(a: list[str], b: list[str], budget: int) -> tuple[int, int]:
    """Return the characters shared by two token sequences, and the budget left.

    Sequences within the budget are aligned exactly. Larger ones are anchored
    on tokens that occur once in each, in an order both agree on (the longest
    increasing run of their positions), and the gaps between anchors are
    matched the same way. Gaps without anchors that are over budget count as
    different. Each pass is O(n log n), so the work stays bounded.
    """
    matched = 0
    pending = [(0, len(a), 0, len(b))]
    while pending:
        a_lo, a_hi, b_lo, b_hi = pending.pop()
        while a_lo < a_hi and b_lo < b_hi and a[a_lo] == b[b_lo]:
            matched += len(a[a_lo])
            a_lo += 1
            b_lo += 1
        while a_lo < a_hi and b_lo < b_hi and a[a_hi - 1] == b[b_hi - 1]:
            matched += len(a[a_hi - 1])
            a_hi -= 1
            b_hi -= 1
        cells = (a_hi - a_lo) * (b_hi - b_lo)
        if cells == 0:
            continue
        if cells <= budget:
            budget -= cells
            a_part, b_part = a[a_lo:a_hi], b[b_lo:b_hi]
            matcher = difflib.SequenceMatcher(None, a_part, b_part, autojunk=False)
            for block in matcher.get_matching_blocks():
                matched += sum(map(len, a_part[block.a : block.a + block.size]))
            continue
        anchors = _unique_anchors(a, a_lo, a_hi, b, b_lo, b_hi)
        if not anchors:
            continue
        prev_a, prev_b = a_lo, b_lo
        for a_pos, b_pos in anchors:
            matched += len(a[a_pos])
            pending.append((prev_a, a_pos, prev_b, b_pos))
            prev_a, prev_b = a_pos + 1, b_pos + 1
        pending.append((prev_a, a_hi, prev_b, b_hi))
    return matched, budget


def _unique_anchors(a: list[str], a_lo: int, a_hi: int, b: list[str], b_lo: int, b_hi: int) -> list[tuple[int, int]]:
    """Return positions of tokens occurring once in each range, in an order both share."""
    a_counts = Counter(a[a_lo:a_hi])
    b_positions: dict[str, int] = {}
    b_counts: Counter[str] = Counter()
    for pos in range(b_lo, b_hi):
        token = b[pos]
        b_counts[token] += 1
        b_positions[token] = pos
    pairs = [(pos, b_positions[a[pos]]) for pos in range(a_lo, a_hi) if a_counts[a[pos]] == 1 and b_counts[a[pos]] == 1]
    # Longest increasing subsequence of the b positions (pairs are in a order).
    tails: list[int] = []
    tail_index: list[int] = []
    previous = [-1] * len(pairs)
    for index, (_, b_pos) in enumerate(pairs):
        slot = bisect.bisect_left(tails, b_pos)
        if slot == len(tails):
            tails.append(b_pos)
            tail_index.append(index)
        else:
            tails[slot] = b_pos
            tail_index[slot] = index
        previous[index] = tail_index[slot - 1] if slot else -1
    chain: list[tuple[int, int]] = []
    index = tail_index[-1] if tail_index else -1
    while index >= 0:
        chain.append(pairs[index])
        index = previous[index]
    chain.reverse()
    return chain


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
