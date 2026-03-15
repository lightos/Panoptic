OpenAI Codex v0.114.0 (research preview)
--------
workdir: /home/manchine/dev/Panoptic
model: gpt-5.4
provider: openai
approval: never
sandbox: read-only
reasoning effort: high
reasoning summaries: none
session id: 019cf2e2-d6e7-7d91-b757-2af1aa0a040f
--------
user
Review implementation plan at: /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md

Read the plan file and analyze for:
- Completeness: Are all requirements addressed?
- Correctness: Will the approach work?
- Risk: What could go wrong?
- Missing steps: What's not covered?
- Over-engineering: Is anything unnecessary?

For each issue:
- SECTION: <plan section>
- SEVERITY: CRITICAL|HIGH|MEDIUM|LOW
- ISSUE: <description>
- SUGGESTION: <fix>

mcp startup: no servers
codex
Reviewing the plan file first, then I’ll cross-check its assumptions against the codebase so the findings are about actual feasibility rather than just the document in isolation.
exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md" in /home/manchine/dev/Panoptic succeeded in 0ms:
# Panoptic Bugfix, UX & Features Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix all identified bugs, improve terminal UX, and add missing features to the Panoptic LFI scanner.

**Architecture:** All changes are within existing modules — no new files. Changes touch `models.py` (new fields + validation), `cli.py` (new args + parsing), `core.py` (bugfixes + new features), `network.py` (cleanup + features), `output.py` (quiet mode + redaction), `config.py` (merge normalization), and `utils.py` (filename safety).

**Tech Stack:** Python 3.10+, asyncio, httpx, rich, pytest, pytest-httpx, mypy --strict

**Design spec:** `docs/superpowers/specs/2026-03-15-bugfix-ux-features-design.md`

**Test command:** `python3 -m pytest tests/ -x -q`
**Type check:** `python3 -m mypy panoptic/`
**Lint:** `python3 -m ruff check panoptic/`

---

## Chunk 1: Critical Bugfixes

exec
/bin/bash -lc "rg --files /home/manchine/dev/Panoptic | sed 's#"'^#/##'"' | head -n 200" in /home/manchine/dev/Panoptic succeeded in 0ms:
//home/manchine/dev/Panoptic/pyproject.toml
//home/manchine/dev/Panoptic/README.md
//home/manchine/dev/Panoptic/LICENSE
//home/manchine/dev/Panoptic/tests/test_core.py
//home/manchine/dev/Panoptic/tests/test_cli.py
//home/manchine/dev/Panoptic/tests/__init__.py
//home/manchine/dev/Panoptic/tests/test_integration.py
//home/manchine/dev/Panoptic/tests/test_parsers.py
//home/manchine/dev/Panoptic/tests/test_cases.py
//home/manchine/dev/Panoptic/tests/test_utils.py
//home/manchine/dev/Panoptic/tests/test_network.py
//home/manchine/dev/Panoptic/tests/conftest.py
//home/manchine/dev/Panoptic/tests/test_update.py
//home/manchine/dev/Panoptic/tests/test_config.py
//home/manchine/dev/Panoptic/tests/test_output.py
//home/manchine/dev/Panoptic/tests/test_models.py
//home/manchine/dev/Panoptic/tests/test_heuristic.py
//home/manchine/dev/Panoptic/CLAUDE.md
//home/manchine/dev/Panoptic/panoptic.py
//home/manchine/dev/Panoptic/panoptic/update.py
codex
The plan is broader than a few bugfixes, so I’m reading the rest of it and checking the referenced modules/tests where the document makes concrete implementation claims.
exec
/bin/bash -lc "sed -n '261,520p' /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md" in /home/manchine/dev/Panoptic succeeded in 0ms:
Run: `python3 -m pytest tests/test_output.py -v`
Expected: ALL PASS

- [ ] **Step 5: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add panoptic/output.py tests/test_output.py
git commit -m "fix: redact query param values in JSON/CSV output to prevent credential leaks"
```

---

### Task 4: Remove dead code — `except httpx.HTTPStatusError` (spec item 3e)

**Files:**
exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/docs/superpowers/specs/2026-03-15-bugfix-ux-features-design.md" in /home/manchine/dev/Panoptic succeeded in 0ms:
# Panoptic Bugfix, UX Polish & Missing Features — Design Spec

## Goal

Fix all identified bugs, improve terminal UX, and add missing features expected in a modern LFI scanner. Organized by priority: critical bugs first, then UX, then features.

## Scope

23 items across 8 source files. No new modules — all changes are within existing files.

---

## Critical Bugs

### 1. Regex bug in param auto-detection

**File:** `cli.py:281,291`

The param auto-detection regex uses `[^=&]+` for the value group, which breaks on base64-encoded values containing `=` padding. CLAUDE.md explicitly documents this gotcha. The ext-param validation at line 291 has the same bug.

exec
/bin/bash -lc "sed -n '520,900p' /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md" in /home/manchine/dev/Panoptic succeeded in 0ms:

`_mark_completed` writes checkpoint JSON for every single case. With 1024+ cases, this creates 1024 file writes. Fix: throttle to every 5 seconds with a dedicated lock, make writes atomic, and flush on shutdown.

- [ ] **Step 1: Write tests for atomic checkpoint writes**

In `tests/test_core.py`, add:

```python
import json
import os
import tempfile

class TestAtomicCheckpoint:
    def test_save_checkpoint_atomic(self, tmp_path: Path) -> None:
        """Checkpoint writes must be atomic (temp file + rename)."""
        filepath = str(tmp_path / "checkpoint.json")
        save_checkpoint(filepath, {"id1", "id2"})

        # File should exist and be valid JSON
        with open(filepath) as f:
exec
/bin/bash -lc "sed -n '261,520p' /home/manchine/dev/Panoptic/docs/superpowers/specs/2026-03-15-bugfix-ux-features-design.md" in /home/manchine/dev/Panoptic succeeded in 0ms:

## Missing Features

### 9. `--quiet` / `-q` flag

Suppress non-actionable output. Precise behavior contract:

| Method | Quiet Mode | Rationale |
|--------|-----------|-----------|
| `write_banner` | Suppressed | Decorative |
| `write_info` | Suppressed | Informational |
| Progress bar | Suppressed | Visual noise |
| `write_summary` | Suppressed | Informational |
| `write_found` | **Shown** | Primary actionable output |
| `write_warning` | **Shown** | Indicates scan issues |
| `write_verbose` | Suppressed | Already gated by `--verbose` |

**Files:** `cli.py` (add arg), `models.py` (add field), `output.py` (check flag), `core.py` (pass through)

**Implementation:**
codex
I have the full scope now. Next I’m checking the actual implementations around the sections the plan calls out, because several proposed fixes depend on precise current behavior in `cli.py`, `core.py`, `network.py`, `config.py`, and the tests.
exec
/bin/bash -lc "sed -n '1,240p' /home/manchine/dev/Panoptic/panoptic/models.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Shared data models for Panoptic."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from dataclasses import replace as _dc_replace
from datetime import datetime
from enum import Enum
from typing import Any


class FileType(Enum):
    """Type of file being tested."""

    CONF = "conf"
    LOG = "log"
    OTHER = "other"


exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/panoptic/core.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Async scanner orchestrator for Panoptic.

Uses asyncio.Queue + worker pool for concurrent scanning with
dynamic case injection (passwd users, binlog files).
"""

from __future__ import annotations

import asyncio
import base64
import json
import os
import random
import re
import time
from pathlib import Path
from typing import TextIO
from urllib.parse import urlsplit

import httpx
exec
/bin/bash -lc "sed -n '1,240p' /home/manchine/dev/Panoptic/panoptic/network.py" in /home/manchine/dev/Panopticexec
/bin/bash -lc "sed -n '1,240p' /home/manchine/dev/Panoptic/panoptic/output.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Output formatters for Panoptic scan results.

Supports text (rich), JSON, and CSV output formats.
"""

from __future__ import annotations

import csv
import json
import sys
from typing import TextIO

from rich.console import Console

from panoptic.models import ScanResult


class TeeWriter:
    """Write to two streams simultaneously (e.g., stderr + log file)."""

 succeeded in 0ms:
"""Async HTTP client for Panoptic.

Wraps httpx with retry, timeout, proxy support, and header validation.
"""

from __future__ import annotations

import asyncio
import ssl
from types import TracebackType

import httpx

from panoptic.models import ScanConfig
from panoptic.utils import validate_header


class NetworkClient:
    """Async HTTP client with concurrency control and error handling.

exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/panoptic/cli.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Command-line interface for Panoptic.

Handles argument parsing, validation, and dispatch to scan/list/update modes.
"""

from __future__ import annotations

import argparse
import sys
from typing import Any

from rich_argparse import RawDescriptionRichHelpFormatter

from panoptic.utils import normalize_url, validate_header, validate_url_scheme

EXAMPLES = """
Examples:
  panoptic --url "http://localhost/include.php?file=test.txt"
  panoptic --url "http://localhost/include.php?file=test.txt&id=1" --param file
  panoptic --url "http://localhost/include.php" --data "file=test.txt&id=1" --param file
exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/panoptic/config.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Configuration loading and merging for Panoptic.

Supports TOML config files with CLI argument overrides.
Merge priority: CLI args > config file > built-in defaults.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from panoptic.models import OutputFormat, ScanConfig

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
codex
I’m down to validating the risky sections now: payload construction, checkpointing, first-found flow, file writing, and list/output handling. Those are where the plan is most likely to miss behavior or propose the wrong tests.
exec
/bin/bash -lc "sed -n '260,560p' /home/manchine/dev/Panoptic/panoptic/core.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
                await asyncio.gather(*worker_tasks, return_exceptions=True)

        found_results = [r for r in self.results if r.found]

        if not found_results:
            text_out.write_info("No files found!")
        else:
            text_out.write_summary(found_results, self.total_processed)

        text_out.write_info(f"Finishing scan at: {time.strftime('%X')}")

        if self.config.output_format != OutputFormat.TEXT or self.config.output_file:
            import sys

            def _write_output(stream: TextIO) -> None:
                match self.config.output_format:
                    case OutputFormat.JSON:
                        JsonFormatter(stream).write_results(found_results)
                    case OutputFormat.CSV:
                        CsvFormatter(stream).write_results(found_results)
exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/tests/test_cli.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Tests for panoptic.cli — argument parsing and validation."""

import pytest

from panoptic.cli import parse_args, validate_args


class TestParseArgs:
    def test_url_required_for_scan(self) -> None:
        args = parse_args(["--url", "http://example.com/test.php?file=x"])
        assert args["url"] == "http://example.com/test.php?file=x"

    def test_url_normalized(self) -> None:
        args = parse_args(["--url", "example.com/test.php?file=x"])
        assert args["url"].startswith("http://")

    def test_short_flags(self) -> None:
        args = parse_args(["-u", "http://example.com", "-v", "-a"])
        assert args["url"] == "http://example.com"
        assert args["verbose"] is True
exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/tests/test_network.py" in /home/manchine/dev/Panopticexec
/bin/bash -lc "sed -n '1,220p' /home/manchine/dev/Panoptic/tests/test_models.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Tests for panoptic.network — async HTTP client."""

import httpx
import pytest
from pytest_httpx import HTTPXMock

from panoptic.models import ScanConfig
from panoptic.network import NetworkClient


class TestNetworkClient:
    @pytest.fixture
    def config(self) -> ScanConfig:
        return ScanConfig(
            url="http://example.com",
            timeout=5.0,
            retries=1,
            concurrency=2,
        )

 succeeded in 0ms:
"""Tests for panoptic.models."""

import pytest

from panoptic.models import Case, FileType, OutputFormat, ScanConfig, ScanResult


class TestCase:
    def test_immutable(self) -> None:
        case = Case(location="/etc/passwd", os="*NIX")
        with pytest.raises(AttributeError):
            case.location = "/etc/shadow"  # type: ignore[misc]

    def test_hashable(self) -> None:
        case = Case(location="/etc/passwd", os="*NIX")
        hash(case)  # Should not raise

    def test_case_id_deterministic(self) -> None:
        """case_id must be stable across calls (not Python hash)."""
        case = Case(location="/etc/passwd", os="*NIX", category="OS", software="Linux")
exec
/bin/bash -lc "sed -n '1,280p' /home/manchine/dev/Panoptic/tests/test_core.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
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
exec
/bin/bash -lc "sed -n '1,240p' /home/manchine/dev/Panoptic/tests/test_output.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Tests for panoptic.output — text, JSON, CSV formatters."""

import csv
import io
import json

import pytest

from panoptic.models import Case, FileType, ScanResult
from panoptic.output import CsvFormatter, JsonFormatter, TextFormatter


@pytest.fixture
def sample_results() -> list[ScanResult]:
    return [
        ScanResult(
            case=Case(location="/etc/passwd", os="*NIX", category="OS", software="Linux", file_type=FileType.CONF),
            found=True,
            url="http://example.com/?file=/etc/passwd",
            status_code=200,
exec
/bin/bash -lc "sed -n '900,1320p' /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md" in /home/manchine/dev/Panopticexec
/bin/bash -lc 'wc -l /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md' in /home/manchine/dev/Panoptic succeeded in 0ms:
1869 /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md
 succeeded in 0ms:
            ) as progress:
```

- [ ] **Step 2: Add scan duration and req/s to summary**

Before the Progress block (around line 227), add:

```python
            scan_start = time.monotonic()
```

After the Progress block exits (around line 262), before the found_results check, add:

```python
        elapsed = time.monotonic() - scan_start
        rps = self.total_processed / elapsed if elapsed > 0 else 0
        text_out.write_info(f"Scan completed in {elapsed:.1f}s ({rps:.0f} req/s)")
```

- [ ] **Step 3: Run full suite + type check**
exec
/bin/bash -lc 'rg -n "''^## |''^### Task" /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md' in /home/manchine/dev/Panoptic succeeded in 0ms:
19:## Chunk 1: Critical Bugfixes
21:### Task 1: Fix regex in param auto-detection (spec item 1)
111:### Task 2: Fix param replacement substring corruption (spec item 3b)
194:### Task 3: Redact credentials in JSON/CSV output (spec item 3d)
278:### Task 4: Remove dead code — `except httpx.HTTPStatusError` (spec item 3e)
331:### Task 5: Fix `--write-files` filename collisions (spec item 3f)
424:## Chunk 2: Concurrency Fixes
426:### Task 6: Fix race condition on `first_found` flag (spec item 2)
515:### Task 7: Fix checkpoint write storm (spec item 3)
664:## Chunk 3: Validation & UX
666:### Task 8: Add validation for `--delay`, `--timeout`, and `--random-delay` (spec items 6, 7)
806:### Task 9: Remove redundant semaphore (spec item 4)
867:### Task 10: Add elapsed time and ETA to progress bar (spec item 5)
933:### Task 11: Improve `--list` output with header and count (spec item 8)
965:## Chunk 4: New Features — Simple
967:### Task 12: Add `--quiet` / `-q` flag (spec item 9)
1199:### Task 13: Add `--follow-redirects` flag (spec item 12)
1271:## Chunk 5: New Features — Complex
1273:### Task 14: Add `--match-string` (spec item 10)
1358:### Task 15: Add `--match-code` and `--filter-code` (spec item 11)
codex
The remaining sections are feature-heavy. I’m scanning those now because the highest-risk gaps usually show up in config normalization, backward compatibility, and test strategy rather than in the code snippets themselves.
exec
/bin/bash -lc "sed -n '1665,1869p' /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md" in /home/manchine/dev/Panopticexec
/bin/bash -lc "sed -n '1273,1665p' /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md" in /home/manchine/dev/Panoptic succeeded in 0ms:

In `panoptic/cli.py`, replace the `--list` handler (lines 251-261):

```python
    if args.get("list"):
        import json as json_mod

        from panoptic.cases import list_values
        from panoptic.config import load_config, merge_config

        _file_config = load_config(args.get("config_file"))
        _config = merge_config({k: v for k, v in args.items() if v is not None}, _file_config)
        values = list_values(args["list"], config=_config)
        fmt = args.get("output_format") or "text"

        if fmt == "json":
            print(json_mod.dumps(sorted(values), indent=2))
        elif fmt == "csv":
            print(args["list"])
            for val in sorted(values):
 succeeded in 0ms:
### Task 14: Add `--match-string` (spec item 10)

**Files:**
- Modify: `panoptic/models.py` (add field)
- Modify: `panoptic/cli.py` (add arg)
- Modify: `panoptic/core.py:339-365` (gate both positive paths)
- Test: `tests/test_core.py`

Critical: `match_string` must gate ALL positive result paths, including the Content-Length fast path.

- [ ] **Step 1: Add field to `ScanConfig`**

In `panoptic/models.py`, add after `bad_string` (line 93):

```python
    bad_string: str | None = None
    match_string: str | None = None
```

- [ ] **Step 2: Add CLI argument**
exec
/bin/bash -lc 'rg -n "header|output_format|list_all_files|match_code|filter_code|match_string|follow_redirects|quiet" /home/manchine/dev/Panoptic/tests /home/manchine/dev/Panoptic/panoptic' in /home/manchine/dev/Panoptic succeeded in 0ms:
/home/manchine/dev/Panoptic/tests/test_cli.py:45:        assert args["output_format"] == "json"
/home/manchine/dev/Panoptic/tests/test_cli.py:64:                    "list_all_files": False,
/home/manchine/dev/Panoptic/tests/test_cli.py:66:                    "header": None,
/home/manchine/dev/Panoptic/tests/test_cli.py:70:    def test_rejects_crlf_header(self) -> None:
/home/manchine/dev/Panoptic/tests/test_cli.py:77:                    "list_all_files": False,
/home/manchine/dev/Panoptic/tests/test_cli.py:79:                    "header": "X-Foo: bar\r\nInjected: yes",
/home/manchine/dev/Panoptic/tests/test_cli.py:90:                "list_all_files": False,
/home/manchine/dev/Panoptic/tests/test_cli.py:92:                "header": None,
/home/manchine/dev/Panoptic/panoptic/models.py:104:    output_format: OutputFormat = OutputFormat.TEXT
/home/manchine/dev/Panoptic/panoptic/models.py:111:    # HTTP headers
/home/manchine/dev/Panoptic/panoptic/models.py:115:    header: str | None = None
/home/manchine/dev/Panoptic/panoptic/utils.py:21:def validate_header(header: str) -> tuple[str, str]:
/home/manchine/dev/Panoptic/panoptic/utils.py:22:    """Parse and validate a custom HTTP header string.
/home/manchine/dev/Panoptic/panoptic/utils.py:24:    Expected format: 'Name: Value' (standard HTTP header format).
/home/manchine/dev/Panoptic/panoptic/utils.py:25:    Rejects headers containing CRLF characters (header injection prevention).
/home/manchine/dev/Panoptic/panoptic/utils.py:29:    if ":" not in header:
/home/manchine/dev/Panoptic/panoptic/utils.py:31:        if "=" in header:
/home/manchine/dev/Panoptic/panoptic/utils.py:35:                "[!] Warning: header format 'Name=Value' is deprecated, use 'Name: Value'",
/home/manchine/dev/Panoptic/panoptic/utils.py:38:            name, _, value = header.partition("=")
/home/manchine/dev/Panoptic/panoptic/utils.py:42:        name, _, value = header.partition(":")
exec
/bin/bash -lc "sed -n '1,220p' /home/manchine/dev/Panoptic/tests/test_config.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Tests for panoptic.config — TOML config loading and merge."""

from pathlib import Path

from panoptic.config import load_config, merge_config
from panoptic.models import OutputFormat


class TestLoadConfig:
    def test_returns_dict(self, tmp_path: Path) -> None:
        config_file = tmp_path / "config.toml"
        config_file.write_text("[defaults]\nconcurrency = 16\ntimeout = 30.0\n")
        result = load_config(str(config_file))
        assert result["defaults"]["concurrency"] == 16

    def test_missing_file_returns_empty(self) -> None:
        result = load_config("/nonexistent/config.toml")
        assert result == {}

    def test_invalid_toml_returns_empty(self, tmp_path: Path) -> None:
exec
/bin/bash -lc "sed -n '260,360p' /home/manchine/dev/Panoptic/panoptic/cli.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
            print(val)
        return

    # Load config and merge
    from panoptic.config import load_config, merge_config

    file_config = load_config(args.pop("config_file", None))
    config = merge_config(args, file_config)

    # Shared URL parsing for param detection and ext-param validation
    import re
    from urllib.parse import urlsplit

    parsed = urlsplit(config.url)
    params = config.data if config.data else parsed.query

    # Check if FUZZ marker is used in any injectable position
    has_fuzz = "FUZZ" in (config.data or "") or "FUZZ" in (config.header or "")

    # Auto-detect vulnerable parameter if not specified (ported from original)
exec
/bin/bash -lc "sed -n '1,220p' /home/manchine/dev/Panoptic/panoptic/utils.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
"""Utility functions for Panoptic."""

from __future__ import annotations

import random
import secrets
from importlib.resources import files
from urllib.parse import urlsplit


def validate_url_scheme(url: str) -> None:
    """Validate that a URL uses http:// or https:// scheme.

    Raises ValueError if the scheme is invalid (prevents SSRF via file://, ftp://, etc.).
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Only http:// and https:// URLs are supported, got '{parsed.scheme}://'")


codex
I’ve identified several concrete plan problems. I’m pulling exact line references from the plan now so the review can point to the sections and the specific steps that need to change.
exec
/bin/bash -lc "nl -ba /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md | sed -n '20,110p'" in /home/manchine/dev/Panoptic succeeded in 0ms:
    20	
    21	### Task 1: Fix regex in param auto-detection (spec item 1)
    22	
    23	**Files:**
    24	- Modify: `panoptic/cli.py:281,291`
    25	- Test: `tests/test_cli.py`
    26	
    27	The param auto-detection regex uses `[^=&]+` for the value group, which breaks on base64-encoded values containing `=` (e.g., `file=dGVzdC50eHQ=&id=1` fails to detect `file` as the param). The ext-param validation regex at line 291 has the same bug.
    28	
    29	- [ ] **Step 1: Write failing integration test**
    30	
    31	The param auto-detection happens inside `cli.run()`, which is async and dispatches to the scanner. To test the regex without mocking the entire scan, we test `cli.run()` up to the point where it would create the scanner. The cleanest approach: call `run()` with a base64 URL and mock `Scanner` to capture the config it receives.
    32	
    33	In `tests/test_cli.py`, add:
    34	
    35	```python
    36	from unittest.mock import AsyncMock, patch
    37	
    38	class TestParamAutodetection:
    39	    async def test_base64_param_autodetect(self) -> None:
exec
/bin/bash -lc "nl -ba /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md | sed -n '426,520p'" in /home/manchine/dev/Panopticexec
/bin/bash -lc "nl -ba /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md | sed -n '520,663p'" in /home/manchine/dev/Panoptic succeeded in 0ms:
   426	### Task 6: Fix race condition on `first_found` flag (spec item 2)
   427	
   428	**Files:**
   429	- Modify: `panoptic/core.py:377-397`
   430	- Test: `tests/test_core.py`
   431	
   432	Multiple async workers can see `first_found == False` simultaneously and all enter the OS-restriction block. The fix moves the check-and-set inside `_pause_lock`.
   433	
   434	- [ ] **Step 1: Write test for the race condition**
   435	
   436	In `tests/test_core.py`, add:
   437	
   438	```python
   439	import asyncio
   440	
   441	class TestFirstFoundRace:
   442	    async def test_only_one_worker_enters_first_found_block(self) -> None:
   443	        """Verify first_found flag prevents multiple workers from entering the block."""
   444	        config = ScanConfig(
   445	            url="http://target.test/include.php?file=test.txt",
exec
/bin/bash -lc "nl -ba /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md | sed -n '1199,1665p'" in /home/manchine/dev/Panoptic succeeded in 0ms:
   520	
   521	`_mark_completed` writes checkpoint JSON for every single case. With 1024+ cases, this creates 1024 file writes. Fix: throttle to every 5 seconds with a dedicated lock, make writes atomic, and flush on shutdown.
   522	
   523	- [ ] **Step 1: Write tests for atomic checkpoint writes**
   524	
   525	In `tests/test_core.py`, add:
   526	
   527	```python
   528	import json
   529	import os
   530	import tempfile
   531	
   532	class TestAtomicCheckpoint:
   533	    def test_save_checkpoint_atomic(self, tmp_path: Path) -> None:
   534	        """Checkpoint writes must be atomic (temp file + rename)."""
   535	        filepath = str(tmp_path / "checkpoint.json")
   536	        save_checkpoint(filepath, {"id1", "id2"})
   537	
   538	        # File should exist and be valid JSON
   539	        with open(filepath) as f:
 succeeded in 0ms:
  1199	### Task 13: Add `--follow-redirects` flag (spec item 12)
  1200	
  1201	**Files:**
  1202	- Modify: `panoptic/models.py` (add field)
  1203	- Modify: `panoptic/cli.py` (add arg)
  1204	- Modify: `panoptic/network.py:56` (use config flag)
  1205	- Test: `tests/test_network.py`
  1206	
  1207	- [ ] **Step 1: Write failing test**
  1208	
  1209	In `tests/test_network.py`, add:
  1210	
  1211	```python
  1212	    async def test_follow_redirects_when_enabled(self, httpx_mock: HTTPXMock) -> None:
  1213	        config = ScanConfig(url="http://example.com", follow_redirects=True)
  1214	        httpx_mock.add_response(url="http://example.com/final", text="followed")
  1215	        async with NetworkClient(config) as client:
  1216	            # The client should be configured to follow redirects
  1217	            assert client._client is not None
  1218	            assert client._client._follow_redirects is True
exec
/bin/bash -lc "nl -ba /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md | sed -n '331,423p'" in /home/manchine/dev/Panoptic succeeded in 0ms:
   331	### Task 5: Fix `--write-files` filename collisions (spec item 3f)
   332	
   333	**Files:**
   334	- Modify: `panoptic/core.py:451-465`
   335	- Test: `tests/test_core.py`
   336	
   337	`sanitize_filename()` collapses paths that differ only in traversal depth: `../../etc/passwd` and `../../../etc/passwd` both become `etc_passwd` after `..` removal. This causes file overwrites.
   338	
   339	- [ ] **Step 1: Write failing test**
   340	
   341	In `tests/test_core.py`, add:
   342	
   343	```python
   344	class TestWriteFile:
   345	    def test_no_filename_collision(self, tmp_path: Path) -> None:
   346	        """Paths differing only in traversal depth must not overwrite each other."""
   347	        config = ScanConfig(
   348	            url="http://example.com/test.php?file=x",
   349	            param="file",
   350	            write_files=True,
exec
/bin/bash -lc "nl -ba /home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md | sed -n '1665,1815p'" in /home/manchine/dev/Panoptic succeeded in 0ms:
  1665	
  1666	In `panoptic/cli.py`, replace the `--list` handler (lines 251-261):
  1667	
  1668	```python
  1669	    if args.get("list"):
  1670	        import json as json_mod
  1671	
  1672	        from panoptic.cases import list_values
  1673	        from panoptic.config import load_config, merge_config
  1674	
  1675	        _file_config = load_config(args.get("config_file"))
  1676	        _config = merge_config({k: v for k, v in args.items() if v is not None}, _file_config)
  1677	        values = list_values(args["list"], config=_config)
  1678	        fmt = args.get("output_format") or "text"
  1679	
  1680	        if fmt == "json":
  1681	            print(json_mod.dumps(sorted(values), indent=2))
  1682	        elif fmt == "csv":
  1683	            print(args["list"])
  1684	            for val in sorted(values):
codex
Plan coverage is broad, but these sections need revision before implementation.

- SECTION: Task 1: Fix regex in param auto-detection ([2026-03-15-bugfix-ux-features.md#L21](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L21))
  SEVERITY: HIGH
  ISSUE: The proposed test patches `panoptic.cli.Scanner`, but `run()` imports `Scanner` inside the function from `panoptic.core`. That patch target will not intercept construction, so the test plan is incorrect.
  SUGGESTION: Patch `panoptic.core.Scanner`, or better, extract param auto-detection into a small helper and unit test it directly.

- SECTION: Task 1: Fix regex in param auto-detection ([2026-03-15-bugfix-ux-features.md#L27](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L27))
  SEVERITY: MEDIUM
  ISSUE: The plan treats `--ext-param` validation as broken by an earlier base64 `=` in another parameter, but the current `re.search(...)` still finds `type=txt` in `file=...=&type=txt`. That second “expected fail” is not supported by the current code path.
  SUGGESTION: Narrow this task to the auto-detect regex, or prove a real `ext_param` failure case first and add a test for that exact case.

- SECTION: Task 5: Fix `--write-files` filename collisions ([2026-03-15-bugfix-ux-features.md#L378](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L378))
  SEVERITY: HIGH
  ISSUE: Collision handling based on `filepath.exists()` is not deterministic. A second run of the same scan will generate suffixed duplicates instead of updating the same logical output file.
  SUGGESTION: Make the filename deterministic up front, e.g. `sanitize_filename(location) + "_" + case.case_id[:8]`, or track collisions by logical case rather than filesystem existence.

- SECTION: Task 6: Fix race condition on `first_found` flag ([2026-03-15-bugfix-ux-features.md#L434](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L434))
  SEVERITY: HIGH
  ISSUE: The proposed test does not exercise `_process_case()` or the current buggy path. It manually uses the new locking pattern and is expected to pass before the fix, so it will not catch regressions.
  SUGGESTION: Add a regression test around `_process_case()` with concurrent matching cases, patched `is_match`, and mocked prompt behavior, then assert the prompt/restriction logic runs once.

- SECTION: Task 7: Fix checkpoint write storm ([2026-03-15-bugfix-ux-features.md#L523](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L523))
  SEVERITY: HIGH
  ISSUE: The checkpoint tests only prove that normal writes still produce valid JSON. They do not verify throttling, final flush, cancellation handling, or true atomic replacement, so most of the risky behavior remains untested.
  SUGGESTION: Add tests that monkeypatch `save_checkpoint` and `time.monotonic()` to assert write throttling, and tests that trigger the `finally` path to verify dirty checkpoints are flushed on shutdown/cancel.

- SECTION: Task 13: Add `--follow-redirects` flag ([2026-03-15-bugfix-ux-features.md#L1207](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1207))
  SEVERITY: MEDIUM
  ISSUE: The test asserts against `client._client._follow_redirects`, a private httpx attribute, instead of verifying redirect behavior. That is brittle and can pass even if request handling is wrong.
  SUGGESTION: Add a behavioral test with a 302 followed by a final response, then assert the returned status/body changes when `follow_redirects=True`.

- SECTION: Task 14: Add `--match-string` ([2026-03-15-bugfix-ux-features.md#L1301](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1301))
  SEVERITY: MEDIUM
  ISSUE: The “failing test” only checks that `ScanConfig.match_string` exists. It does not validate filtering behavior and will not protect the critical fast-path change the section calls out.
  SUGGESTION: Test actual scan behavior with mocked responses: one where content-length fast path would have matched but body lacks the string, and one where body contains the string.

- SECTION: Task 15: Add `--match-code` and `--filter-code` ([2026-03-15-bugfix-ux-features.md#L1358](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1358))
  SEVERITY: MEDIUM
  ISSUE: The plan omits `config.py` work, but `merge_config()` currently passes file-config values through unchanged. That means TOML-sourced `match_codes`/`filter_codes` will not be normalized and may silently misbehave.
  SUGGESTION: Add `config.py` normalization plus `tests/test_config.py` coverage for string and list forms from config files.

- SECTION: Task 16: Add multiple `--header` support ([2026-03-15-bugfix-ux-features.md#L1461](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1461))
  SEVERITY: MEDIUM
  ISSUE: Renaming `ScanConfig.header` to `headers` creates broad API churn for a feature that can be implemented compatibly. It is more invasive than necessary and increases migration risk for Python callers.
  SUGGESTION: Keep `header` as a deprecated alias and normalize to an internal list, or support both fields during a transition instead of hard-renaming immediately.

- SECTION: Task 17: Add `--output-format` for `--list` and `--list-all-files` ([2026-03-15-bugfix-ux-features.md#L1643](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1643))
  SEVERITY: MEDIUM
  ISSUE: The proposed test does not exercise the CLI handlers at all; it just serializes `list_values("os")` directly. That will not catch mistakes in `run()`, CSV formatting, or `--list-all-files`.
  SUGGESTION: Test `run([...])` with `capsys` and patched list functions, and assert exact stdout for text, JSON, and CSV in both list modes.

- SECTION: Task 18: URL-encode payloads for GET requests ([2026-03-15-bugfix-ux-features.md#L1776](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1776))
  SEVERITY: HIGH
  ISSUE: The proposed single encoding strategy is wrong for POST form bodies. Leaving `+` unescaped under `application/x-www-form-urlencoded` can decode as space and corrupt base64 payloads.
  SUGGESTION: Use different encoding rules for GET query strings and POST form bodies, preferably via parsed parameter replacement plus `urllib.parse.urlencode`, and add tests covering base64 values containing `+` as well as `&`.
tokens used
70,379
Plan coverage is broad, but these sections need revision before implementation.

- SECTION: Task 1: Fix regex in param auto-detection ([2026-03-15-bugfix-ux-features.md#L21](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L21))
  SEVERITY: HIGH
  ISSUE: The proposed test patches `panoptic.cli.Scanner`, but `run()` imports `Scanner` inside the function from `panoptic.core`. That patch target will not intercept construction, so the test plan is incorrect.
  SUGGESTION: Patch `panoptic.core.Scanner`, or better, extract param auto-detection into a small helper and unit test it directly.

- SECTION: Task 1: Fix regex in param auto-detection ([2026-03-15-bugfix-ux-features.md#L27](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L27))
  SEVERITY: MEDIUM
  ISSUE: The plan treats `--ext-param` validation as broken by an earlier base64 `=` in another parameter, but the current `re.search(...)` still finds `type=txt` in `file=...=&type=txt`. That second “expected fail” is not supported by the current code path.
  SUGGESTION: Narrow this task to the auto-detect regex, or prove a real `ext_param` failure case first and add a test for that exact case.

- SECTION: Task 5: Fix `--write-files` filename collisions ([2026-03-15-bugfix-ux-features.md#L378](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L378))
  SEVERITY: HIGH
  ISSUE: Collision handling based on `filepath.exists()` is not deterministic. A second run of the same scan will generate suffixed duplicates instead of updating the same logical output file.
  SUGGESTION: Make the filename deterministic up front, e.g. `sanitize_filename(location) + "_" + case.case_id[:8]`, or track collisions by logical case rather than filesystem existence.

- SECTION: Task 6: Fix race condition on `first_found` flag ([2026-03-15-bugfix-ux-features.md#L434](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L434))
  SEVERITY: HIGH
  ISSUE: The proposed test does not exercise `_process_case()` or the current buggy path. It manually uses the new locking pattern and is expected to pass before the fix, so it will not catch regressions.
  SUGGESTION: Add a regression test around `_process_case()` with concurrent matching cases, patched `is_match`, and mocked prompt behavior, then assert the prompt/restriction logic runs once.

- SECTION: Task 7: Fix checkpoint write storm ([2026-03-15-bugfix-ux-features.md#L523](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L523))
  SEVERITY: HIGH
  ISSUE: The checkpoint tests only prove that normal writes still produce valid JSON. They do not verify throttling, final flush, cancellation handling, or true atomic replacement, so most of the risky behavior remains untested.
  SUGGESTION: Add tests that monkeypatch `save_checkpoint` and `time.monotonic()` to assert write throttling, and tests that trigger the `finally` path to verify dirty checkpoints are flushed on shutdown/cancel.

- SECTION: Task 13: Add `--follow-redirects` flag ([2026-03-15-bugfix-ux-features.md#L1207](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1207))
  SEVERITY: MEDIUM
  ISSUE: The test asserts against `client._client._follow_redirects`, a private httpx attribute, instead of verifying redirect behavior. That is brittle and can pass even if request handling is wrong.
  SUGGESTION: Add a behavioral test with a 302 followed by a final response, then assert the returned status/body changes when `follow_redirects=True`.

- SECTION: Task 14: Add `--match-string` ([2026-03-15-bugfix-ux-features.md#L1301](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1301))
  SEVERITY: MEDIUM
  ISSUE: The “failing test” only checks that `ScanConfig.match_string` exists. It does not validate filtering behavior and will not protect the critical fast-path change the section calls out.
  SUGGESTION: Test actual scan behavior with mocked responses: one where content-length fast path would have matched but body lacks the string, and one where body contains the string.

- SECTION: Task 15: Add `--match-code` and `--filter-code` ([2026-03-15-bugfix-ux-features.md#L1358](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1358))
  SEVERITY: MEDIUM
  ISSUE: The plan omits `config.py` work, but `merge_config()` currently passes file-config values through unchanged. That means TOML-sourced `match_codes`/`filter_codes` will not be normalized and may silently misbehave.
  SUGGESTION: Add `config.py` normalization plus `tests/test_config.py` coverage for string and list forms from config files.

- SECTION: Task 16: Add multiple `--header` support ([2026-03-15-bugfix-ux-features.md#L1461](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1461))
  SEVERITY: MEDIUM
  ISSUE: Renaming `ScanConfig.header` to `headers` creates broad API churn for a feature that can be implemented compatibly. It is more invasive than necessary and increases migration risk for Python callers.
  SUGGESTION: Keep `header` as a deprecated alias and normalize to an internal list, or support both fields during a transition instead of hard-renaming immediately.

- SECTION: Task 17: Add `--output-format` for `--list` and `--list-all-files` ([2026-03-15-bugfix-ux-features.md#L1643](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1643))
  SEVERITY: MEDIUM
  ISSUE: The proposed test does not exercise the CLI handlers at all; it just serializes `list_values("os")` directly. That will not catch mistakes in `run()`, CSV formatting, or `--list-all-files`.
  SUGGESTION: Test `run([...])` with `capsys` and patched list functions, and assert exact stdout for text, JSON, and CSV in both list modes.

- SECTION: Task 18: URL-encode payloads for GET requests ([2026-03-15-bugfix-ux-features.md#L1776](/home/manchine/dev/Panoptic/docs/superpowers/plans/2026-03-15-bugfix-ux-features.md#L1776))
  SEVERITY: HIGH
  ISSUE: The proposed single encoding strategy is wrong for POST form bodies. Leaving `+` unescaped under `application/x-www-form-urlencoded` can decode as space and corrupt base64 payloads.
  SUGGESTION: Use different encoding rules for GET query strings and POST form bodies, preferably via parsed parameter replacement plus `urllib.parse.urlencode`, and add tests covering base64 values containing `+` as well as `&`.
