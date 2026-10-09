"""Heuristic response comparison engine for Panoptic.

All functions are pure (no side effects, no globals) for testability.
"""

from __future__ import annotations

import difflib
import functools
import html as html_lib
import os
import re
from collections.abc import Hashable, Sequence
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


# Responses are compared by the longest common subsequence of their tokens
# (ASCII words, whitespace runs, and any other single character), weighted by
# token length. Whole tokens keep scattered single-letter matches between
# unrelated words from inflating the score, as SequenceMatcher's contiguous
# blocks did; non-ASCII word characters are separate tokens so a CJK sentence
# is not one indivisible token.
_TOKEN_RE = re.compile(r"[A-Za-z0-9_]+|\s+|.", re.S)

# The subsequence is computed bit-parallel: one pass of big-integer operations
# per symbol of the shorter text, so the cost depends only on the input sizes
# (well under a second for two 64 KiB bodies), never on how repetitive the
# content is. Bit masks of the most frequent symbols are kept; the others are
# rebuilt when used, which bounds memory without approximating.
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

    The ratio is 2 * common / total, where ``common`` counts the characters
    of the longest common subsequence of tokens of the normalized texts (close
    to ``SequenceMatcher.ratio()``, but with a bounded cost). Only the first
    MAX_COMPARE_LENGTH characters of each text are compared.
    """
    first, second = _normalize(first), _normalize(second)
    total = len(first) + len(second)
    if total == 0:
        return 1.0
    # Pages usually share a template and differ in one region: count the common
    # leading and trailing characters directly and compare only the middle.
    prefix = len(os.path.commonprefix([first, second]))
    first, second = first[prefix:], second[prefix:]
    suffix = len(os.path.commonprefix([first[::-1], second[::-1]]))
    if suffix:
        first, second = first[:-suffix], second[:-suffix]
    return 2 * (prefix + suffix + _token_lcs_weight(first, second)) / total


def _token_lcs_weight(first: str, second: str) -> int:
    """Return how many characters the longest common token subsequence covers.

    Each token stands for as many symbols as it has characters, so the plain
    subsequence length of the expanded sequences is the character weight.
    """
    ids: dict[str, int] = {}

    def expand(text: str) -> list[int]:
        symbols: list[int] = []
        for token in _TOKEN_RE.findall(text):
            symbols.extend([ids.setdefault(token, len(ids))] * len(token))
        return symbols

    return _lcs_length(expand(first), expand(second))


def _lcs_length(first: Sequence[Hashable], second: Sequence[Hashable]) -> int:
    """Return the length of the longest common subsequence of two sequences.

    Bit-parallel dynamic programming (Allison-Dix / Hyyro): each bit of ``row``
    is one column of the DP table over the longer sequence, and every symbol
    of the shorter one updates the whole row with a few integer operations.
    """
    if len(first) < len(second):
        first, second = second, first
    if not second:
        return 0
    shared = set(first) & set(second)
    if not shared:
        return 0
    positions: dict[Hashable, list[int]] = {}
    for index, symbol in enumerate(first):
        if symbol in shared:
            positions.setdefault(symbol, []).append(index)
    size = (len(first) + 7) // 8

    def mask(indexes: list[int]) -> int:
        bits = bytearray(size)
        for index in indexes:
            bits[index >> 3] |= 1 << (index & 7)
        return int.from_bytes(bits, "little")

    frequent = sorted(positions, key=lambda symbol: len(positions[symbol]), reverse=True)
    cached = {symbol: mask(positions[symbol]) for symbol in frequent[:_MAX_CACHED_MASKS]}
    full = (1 << len(first)) - 1
    row = full
    for symbol in second:
        if symbol in shared:
            symbol_mask = cached.get(symbol)
            if symbol_mask is None:
                symbol_mask = mask(positions[symbol])
            matches = row & symbol_mask
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
