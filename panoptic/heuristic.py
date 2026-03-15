"""Heuristic response comparison engine for Panoptic.

All functions are pure (no side effects, no globals) for testability.
"""

from __future__ import annotations

import difflib
import re

# Default similarity ratio above which responses are considered "the same"
DEFAULT_HEURISTIC_RATIO = 0.9

# Content-Length threshold for skipping full body retrieval
SKIP_RETRIEVE_THRESHOLD = 1000


def clean_response(response: str, filepath: str) -> str:
    """Remove occurrences of a filepath from a response string.

    Used to normalize responses before comparison so the filepath itself
    doesn't affect the heuristic match.

    Note: Uses flags=re.I (not positional arg) — fixes original bug at line 488
    where re.I was passed as the count parameter.
    """
    if not response:
        return ""

    # Direct string replacement (case-sensitive)
    response = response.replace(filepath, "")

    # Regex replacement for encoded/escaped variants.
    # Cap filepath length to prevent ReDoS from crafted paths with many special chars.
    if len(filepath) <= 256:
        regex = re.sub(r"[^A-Za-z0-9]", r"(.|&\\w+;|%[0-9A-Fa-f]{2})", filepath)
        response = re.sub(regex, "", response, flags=re.I)
    else:
        # For very long paths, fall back to case-insensitive literal replacement
        response = re.sub(re.escape(filepath), "", response, flags=re.I)

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

    Returns True if the file appears to be found, False otherwise.
    """
    if html is None or invalid_response is None:
        return False

    matcher = difflib.SequenceMatcher(None, html, invalid_response)
    return matcher.quick_ratio() < ratio


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
