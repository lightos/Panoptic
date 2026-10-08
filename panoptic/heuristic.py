"""Heuristic response comparison engine for Panoptic.

All functions are pure (no side effects, no globals) for testability.
"""

from __future__ import annotations

import difflib
import functools
import html as html_lib
import re
from urllib.parse import unquote

# Default similarity ratio above which responses are considered "the same"
DEFAULT_HEURISTIC_RATIO = 0.9

# Maximum number of characters of a response body that are cleaned and compared.
# SequenceMatcher is quadratic in the worst case, so unbounded bodies could stall
# the scan; the start of a response is enough to tell a hit from the baseline.
MAX_COMPARE_LENGTH = 64 * 1024

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

    Every non-alphanumeric character becomes a single-character wildcard and every
    alphanumeric character is literal. The pattern has no alternation or
    quantifiers, so matching cannot backtrack catastrophically.
    """
    if len(filepath) <= _MAX_FUZZY_PATH_LENGTH and any(char.isalnum() for char in filepath):
        regex = "".join(re.escape(char) if char.isalnum() else "." for char in filepath)
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

    # quick_ratio() is an upper bound: when it is already below the threshold,
    # the full ratio must also be below it and can safely be skipped. A high
    # quick ratio is not conclusive (reordered bodies can score 1.0), so those
    # responses still require the full comparison.
    matcher = difflib.SequenceMatcher(None, html, invalid_response)
    if matcher.quick_ratio() < ratio:
        return True
    return matcher.ratio() < ratio


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
