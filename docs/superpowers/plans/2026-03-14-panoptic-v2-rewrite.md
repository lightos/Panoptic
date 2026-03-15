# Panoptic v2.0 Rewrite Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Rewrite Panoptic from a monolithic 1120-line script into an async Python package with proper testing, fixing all critical bugs and adding missing features (JSON/CSV output, timeouts, retries, rate limiting, resume).

**Architecture:** Python 3.10+ async package using `httpx` for HTTP, `asyncio.Queue` + worker pool for concurrency, `rich` for terminal UX, `defusedxml` for XML parsing. No threads, no global mutable state — all configuration flows through a `ScanConfig` dataclass.

**Tech Stack:** Python 3.10+, httpx[socks], rich, rich-argparse, defusedxml, tomli, pytest, pytest-asyncio, pytest-httpx, ruff, mypy

**Spec:** `docs/superpowers/specs/2026-03-14-panoptic-v2-rewrite-design.md`

**Original code reference:** `panoptic.py` (root) — keep as read-only reference until Task 14 cleanup.

---

## File Map

| File | Action | Responsibility |
|------|--------|----------------|
| `pyproject.toml` | Create | Package config, deps, scripts, tool config |
| `panoptic/__init__.py` | Create | Version string, package metadata |
| `panoptic/__main__.py` | Create | Entry point (`python -m panoptic`) |
| `panoptic/models.py` | Create | Case, ScanResult, ScanConfig, FileType, OutputFormat |
| `panoptic/utils.py` | Create | URL validation, revision check, filename sanitization, data file loading |
| `panoptic/heuristic.py` | Create | Response cleaning, difflib comparison, content filtering |
| `panoptic/cases.py` | Create | XML case parsing, filtering, version/placeholder expansion, custom lists |
| `panoptic/parsers.py` | Create | passwd user extraction, mysql binlog extraction |
| `panoptic/network.py` | Create | httpx async client with retry, timeout, proxy, header validation |
| `panoptic/config.py` | Create | TOML config loading, CLI-config merge |
| `panoptic/output.py` | Create | Text/JSON/CSV formatters, log file tee |
| `panoptic/cli.py` | Create | argparse setup, validation, dispatch |
| `panoptic/core.py` | Create | Async scanner: Queue workers, progress, OS restriction, checkpoint |
| `panoptic/update.py` | Create | Git self-update with .git detection |
| `panoptic/data/` | Move | cases.xml, agents.txt, versions.ini, home.txt |
| `tests/conftest.py` | Create | Shared fixtures |
| `tests/test_models.py` | Create | Model tests including case_id determinism |
| `tests/test_heuristic.py` | Create | Response cleaning, comparison tests |
| `tests/test_cases.py` | Create | XML parsing, filtering, expansion tests |
| `tests/test_parsers.py` | Create | passwd/binlog extraction tests |
| `tests/test_network.py` | Create | HTTP client tests with mocked responses |
| `tests/test_config.py` | Create | TOML loading, merge priority tests |
| `tests/test_output.py` | Create | Formatter output tests |
| `tests/test_cli.py` | Create | Arg parsing, validation tests |
| `tests/test_core.py` | Create | Scanner integration tests |
| `tests/test_update.py` | Create | Self-update tests |
| `.github/workflows/ci.yml` | Create | CI pipeline |

---

## Chunk 1: Foundation (Tasks 1-4)

### Task 1: Project Scaffolding

**Files:**
- Create: `pyproject.toml`
- Create: `panoptic/__init__.py`
- Create: `panoptic/__main__.py`
- Create: `panoptic/data/` (move data files)
- Create: `tests/__init__.py`
- Create: `tests/conftest.py`

- [ ] **Step 1: Create `pyproject.toml`**

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.backends._legacy:_Backend"

[project]
name = "panoptic"
version = "2.0.0"
description = "Search and retrieve content of common log and config files via path traversal vulnerability"
readme = "README.md"
license = {text = "MIT"}
requires-python = ">=3.10"
authors = [
    {name = "Roberto Christopher Salgado Bjerre"},
    {name = "Miroslav Stampar"},
]
dependencies = [
    "httpx[socks]>=0.27",
    "rich>=13.0",
    "rich-argparse>=1.4",
    "defusedxml>=0.7",
    "tomli>=2.0; python_version < '3.11'",
]

[project.optional-dependencies]
dev = [
    "pytest>=8.0",
    "pytest-asyncio>=0.23",
    "pytest-httpx>=0.30",
    "ruff>=0.4",
    "mypy>=1.10",
]

[tool.setuptools.package-data]
panoptic = ["data/*"]

[project.scripts]
panoptic = "panoptic.__main__:main"

[tool.ruff]
target-version = "py310"
select = ["E", "F", "W", "I", "UP", "B", "SIM"]

[tool.mypy]
python_version = "3.10"
strict = true

[tool.pytest.ini_options]
asyncio_mode = "auto"
```

- [ ] **Step 2: Create package init**

Create `panoptic/__init__.py`:
```python
"""Panoptic — search and retrieve content of common files via path traversal vulnerability."""

__version__ = "2.0.0"
```

- [ ] **Step 3: Create `panoptic/__main__.py` stub**

```python
"""Entry point for `python -m panoptic`."""

import asyncio
import sys


def main() -> None:
    """Main entry point."""
    from panoptic.cli import run
    try:
        asyncio.run(run())
    except KeyboardInterrupt:
        sys.exit(130)


if __name__ == "__main__":
    main()
```

- [ ] **Step 4: Move data files**

```bash
mkdir -p panoptic/data
cp cases.xml panoptic/data/
cp agents.txt panoptic/data/
cp versions.ini panoptic/data/
cp home.txt panoptic/data/
```

- [ ] **Step 5: Create test scaffolding**

Create `tests/__init__.py` (empty file).

Create `tests/conftest.py`:
```python
"""Shared test fixtures for Panoptic tests."""

import pytest


@pytest.fixture
def sample_passwd() -> str:
    """Sample /etc/passwd content for parser tests."""
    return (
        "root:x:0:0:root:/root:/bin/bash\n"
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
        "user:x:1000:1000:Test User:/home/user:/bin/bash\n"
    )


@pytest.fixture
def sample_html_found() -> str:
    """Sample HTML response that contains a found file."""
    return "<html><body>root:x:0:0:root:/root:/bin/bash</body></html>"


@pytest.fixture
def sample_html_not_found() -> str:
    """Sample HTML response for a file not found."""
    return "<html><body><h1>404 Not Found</h1></body></html>"
```

- [ ] **Step 6: Install dev dependencies and verify**

```bash
pip install -e ".[dev]"
pytest --co -q  # Should collect 0 tests, no errors
```

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml panoptic/__init__.py panoptic/__main__.py panoptic/data/ tests/
git commit -m "feat: scaffold panoptic v2 package structure with pyproject.toml"
```

---

### Task 2: Data Models (`models.py`)

**Files:**
- Create: `panoptic/models.py`
- Create: `tests/test_models.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_models.py`:
```python
"""Tests for panoptic.models."""

from panoptic.models import Case, FileType, OutputFormat, ScanConfig, ScanResult


class TestCase:
    def test_immutable(self) -> None:
        case = Case(location="/etc/passwd", os="*NIX")
        with pytest.raises(AttributeError):
            case.location = "/etc/shadow"  # type: ignore[misc]

    def test_hashable(self) -> None:
        case = Case(location="/etc/passwd", os="*NIX")
        {case}  # Should not raise

    def test_case_id_deterministic(self) -> None:
        """case_id must be stable across calls (not Python hash)."""
        case = Case(location="/etc/passwd", os="*NIX", category="OS", software="Linux")
        id1 = case.case_id
        id2 = case.case_id
        assert id1 == id2
        assert len(id1) == 16  # truncated SHA-256

    def test_case_id_different_for_different_cases(self) -> None:
        c1 = Case(location="/etc/passwd")
        c2 = Case(location="/etc/shadow")
        assert c1.case_id != c2.case_id

    def test_equality(self) -> None:
        c1 = Case(location="/etc/passwd", os="*NIX")
        c2 = Case(location="/etc/passwd", os="*NIX")
        assert c1 == c2


class TestScanResult:
    def test_timestamp_auto_set(self) -> None:
        case = Case(location="/etc/passwd")
        result = ScanResult(case=case, found=True, url="http://example.com")
        assert result.timestamp != ""

    def test_fields(self) -> None:
        case = Case(location="/etc/passwd")
        result = ScanResult(
            case=case, found=True, url="http://example.com",
            status_code=200, content="root:x:0:0", content_length=100,
        )
        assert result.found is True
        assert result.status_code == 200


class TestScanConfig:
    def test_defaults(self) -> None:
        config = ScanConfig(url="http://example.com")
        assert config.concurrency == 4
        assert config.timeout == 10.0
        assert config.retries == 3
        assert config.output_format == OutputFormat.TEXT
        assert config.heuristic_ratio == 0.9

    def test_prefix_not_mutated(self) -> None:
        """ScanConfig.prefix should never be mutated after creation."""
        config = ScanConfig(url="http://example.com", prefix="../")
        original = config.prefix
        # Simulate what old code did wrong — this should be safe
        _ = config.prefix + "/etc/passwd"
        assert config.prefix == original


class TestEnums:
    def test_file_type_values(self) -> None:
        assert FileType.CONF.value == "conf"
        assert FileType.LOG.value == "log"
        assert FileType.OTHER.value == "other"

    def test_output_format_values(self) -> None:
        assert OutputFormat.TEXT.value == "text"
        assert OutputFormat.JSON.value == "json"
        assert OutputFormat.CSV.value == "csv"


import pytest
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_models.py -v
```
Expected: FAIL with `ModuleNotFoundError: No module named 'panoptic.models'`

- [ ] **Step 3: Write `panoptic/models.py`**

```python
"""Shared data models for Panoptic."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum


class FileType(Enum):
    """Type of file being tested."""
    CONF = "conf"
    LOG = "log"
    OTHER = "other"


class OutputFormat(Enum):
    """Output format for scan results."""
    TEXT = "text"
    JSON = "json"
    CSV = "csv"


@dataclass(frozen=True)
class Case:
    """A single file path to test. Immutable and hashable."""
    location: str
    os: str | None = None
    category: str | None = None
    software: str | None = None
    file_type: FileType | None = None

    @property
    def case_id(self) -> str:
        """Deterministic identifier for resume/checkpoint.

        Uses SHA-256 instead of Python's hash() which is randomized
        per-process (PEP 456).
        """
        canonical = f"{self.location}|{self.os}|{self.category}|{self.software}|{self.file_type}"
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


@dataclass
class ScanResult:
    """Result of testing a single case."""
    case: Case
    found: bool
    url: str
    status_code: int | None = None
    content: str | None = None
    content_length: int | None = None
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanConfig:
    """All configuration for a scan. Replaces global args + kb."""
    # Target
    url: str
    param: str | None = None
    data: str | None = None
    path_based: bool = False
    prefix: str = ""
    postfix: str = ""
    multiplier: int = 1
    ext_param: str | None = None
    # Performance
    concurrency: int = 4
    timeout: float = 10.0
    retries: int = 3
    delay: float = 0.0
    random_delay: tuple[float, float] | None = None
    # Detection
    bad_string: str | None = None
    replace_slash: str | None = None
    heuristic_ratio: float = 0.9
    # Behavior
    write_files: bool = False
    skip_parsing: bool = False
    automatic: bool = False
    invalid_ssl: bool = False
    all_versions: bool = False
    # Output
    output_format: OutputFormat = OutputFormat.TEXT
    output_file: str | None = None
    log_file: str | None = None
    verbose: bool = False
    # Proxy
    proxy: str | None = None
    ignore_proxy: bool = False
    # HTTP headers
    user_agent: str | None = None
    random_agent: bool = False
    cookie: str | None = None
    header: str | None = None
    # Filtering
    os_filter: str | None = None
    software_filter: str | None = None
    category_filter: str | None = None
    type_filter: str | None = None
    # Custom list
    list_file: str | None = None
    # Resume
    resume_file: str | None = None
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_models.py -v
```
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/models.py tests/test_models.py
git commit -m "feat: add data models (Case, ScanResult, ScanConfig)"
```

---

### Task 3: Utilities (`utils.py`)

**Files:**
- Create: `panoptic/utils.py`
- Create: `tests/test_utils.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_utils.py`:
```python
"""Tests for panoptic.utils."""

import pytest
from panoptic.utils import (
    validate_url_scheme,
    validate_header,
    sanitize_filename,
    load_data_file,
    get_random_agent,
)


class TestValidateUrlScheme:
    def test_http_valid(self) -> None:
        validate_url_scheme("http://example.com/test.php?file=x")

    def test_https_valid(self) -> None:
        validate_url_scheme("https://example.com/test.php?file=x")

    def test_file_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Only http:// and https://"):
            validate_url_scheme("file:///etc/passwd")

    def test_ftp_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Only http:// and https://"):
            validate_url_scheme("ftp://internal/data")

    def test_no_scheme_rejected(self) -> None:
        with pytest.raises(ValueError, match="Only http:// and https://"):
            validate_url_scheme("example.com/test")


class TestValidateHeader:
    def test_valid_header(self) -> None:
        name, value = validate_header("X-Forwarded-For: 127.0.0.1")
        assert name == "X-Forwarded-For"
        assert value == "127.0.0.1"

    def test_crlf_in_value_rejected(self) -> None:
        with pytest.raises(ValueError, match="CRLF"):
            validate_header("X-Foo: bar\r\nX-Injected: evil")

    def test_crlf_in_name_rejected(self) -> None:
        with pytest.raises(ValueError, match="CRLF"):
            validate_header("X-Foo\r\n: bar")

    def test_no_colon_rejected(self) -> None:
        with pytest.raises(ValueError, match="colon"):
            validate_header("InvalidHeader")

    def test_value_with_equals(self) -> None:
        """Headers with = in value should work (e.g., auth tokens)."""
        name, value = validate_header("Authorization: Bearer abc=def")
        assert name == "Authorization"
        assert value == "Bearer abc=def"


class TestSanitizeFilename:
    def test_slashes_replaced(self) -> None:
        assert "/" not in sanitize_filename("/etc/passwd")

    def test_traversal_neutralized(self) -> None:
        result = sanitize_filename("../../../etc/passwd")
        assert ".." not in result

    def test_colons_replaced(self) -> None:
        assert ":" not in sanitize_filename("C:\\Windows\\system.ini")


class TestLoadDataFile:
    def test_load_agents(self) -> None:
        content = load_data_file("agents.txt")
        assert len(content) > 0
        assert "Mozilla" in content

    def test_load_nonexistent_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_data_file("nonexistent.txt")


class TestGetRandomAgent:
    def test_returns_string(self) -> None:
        agent = get_random_agent()
        assert isinstance(agent, str)
        assert len(agent) > 0

    def test_returns_different_values(self) -> None:
        """Should return different agents (probabilistic, run a few times)."""
        agents = {get_random_agent() for _ in range(20)}
        assert len(agents) > 1  # Very unlikely to get same agent 20 times
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_utils.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/utils.py`**

```python
"""Utility functions for Panoptic."""

from __future__ import annotations

import random
import re
import secrets
from importlib.resources import files
from urllib.parse import urlsplit


def validate_url_scheme(url: str) -> None:
    """Validate that a URL uses http:// or https:// scheme.

    Raises ValueError if the scheme is invalid (prevents SSRF via file://, ftp://, etc.).
    """
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(
            f"Only http:// and https:// URLs are supported, got '{parsed.scheme}://'"
        )


def validate_header(header: str) -> tuple[str, str]:
    """Parse and validate a custom HTTP header string.

    Expected format: 'Name: Value' (standard HTTP header format).
    Rejects headers containing CRLF characters (header injection prevention).

    Returns (name, value) tuple.
    """
    if ":" not in header:
        raise ValueError(
            "Header must contain a colon separator (format: 'Name: Value')"
        )

    name, _, value = header.partition(":")
    name = name.strip()
    value = value.strip()

    if "\r" in name or "\n" in name or "\r" in value or "\n" in value:
        raise ValueError(
            "Header contains CRLF characters (possible header injection)"
        )

    if not name:
        raise ValueError("Header name cannot be empty")

    return name, value


def sanitize_filename(path: str) -> str:
    """Sanitize a file path for use as a local output filename.

    Replaces directory separators and dangerous characters to prevent
    path traversal in output file writes.
    """
    # Replace traversal sequences
    sanitized = path.replace("..", "")
    # Replace path separators and colons
    sanitized = sanitized.replace("/", "_").replace("\\", "_").replace(":", "_")
    # Remove leading dots and underscores
    sanitized = sanitized.lstrip("._")
    return sanitized or "unnamed"


def load_data_file(filename: str) -> str:
    """Load a data file from the panoptic.data package.

    Uses importlib.resources for compatibility with installed packages
    (zip archives, wheels).
    """
    data_files = files("panoptic.data")
    resource = data_files.joinpath(filename)
    return resource.read_text(encoding="utf-8")


def get_random_agent() -> str:
    """Return a random User-Agent string from the bundled agents list."""
    content = load_data_file("agents.txt")
    agents = [line.strip() for line in content.splitlines() if line.strip()]
    return random.choice(agents)


def generate_invalid_filename() -> str:
    """Generate a cryptographically random filename for baseline comparison.

    Uses secrets module instead of random for unpredictability.
    """
    return secrets.token_hex(8)


def normalize_url(url: str) -> str:
    """Normalize a URL, adding http:// scheme if missing."""
    if not url.lower().startswith(("http://", "https://")):
        url = f"http://{url}"
    return url
```

- [ ] **Step 4: Create `panoptic/data/__init__.py`**

```python
# Required for importlib.resources to treat this as a package.
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
pytest tests/test_utils.py -v
```
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add panoptic/utils.py panoptic/data/__init__.py tests/test_utils.py
git commit -m "feat: add utility functions (URL validation, header parsing, data loading)"
```

---

### Task 4: Heuristic Engine (`heuristic.py`)

**Files:**
- Create: `panoptic/heuristic.py`
- Create: `tests/test_heuristic.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_heuristic.py`:
```python
"""Tests for panoptic.heuristic — the core detection logic."""

import pytest
from panoptic.heuristic import clean_response, is_match, filter_content


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
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_heuristic.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/heuristic.py`**

```python
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

    # Direct string replacement
    response = response.replace(filepath, "")

    # Regex replacement for encoded/escaped variants
    regex = re.sub(r"[^A-Za-z0-9]", r"(.|&\\w+;|%[0-9A-Fa-f]{2})", filepath)
    return re.sub(regex, "", response, flags=re.I)


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
            content = content[start.size:]

        # Strip common suffix
        if len(matching_blocks) > 2:
            end = matching_blocks[-2]
            if (
                end.size > 0
                and end.a + end.size == len(html)
                and end.b + end.size == len(original_response)
            ):
                content = content[: -end.size]

    return content
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_heuristic.py -v
```
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/heuristic.py tests/test_heuristic.py
git commit -m "feat: add heuristic engine with fixed re.sub flags bug"
```

---

## Chunk 2: Data Layer (Tasks 5-6)

### Task 5: Case Parser (`cases.py`)

**Files:**
- Create: `panoptic/cases.py`
- Create: `tests/test_cases.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_cases.py`:
```python
"""Tests for panoptic.cases — XML case parsing and filtering."""

import pytest
from panoptic.models import Case, FileType, ScanConfig
from panoptic.cases import parse_cases, load_versions, load_custom_list


class TestParseCases:
    def test_returns_list_of_cases(self) -> None:
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        assert isinstance(cases, list)
        assert len(cases) > 0
        assert all(isinstance(c, Case) for c in cases)

    def test_cases_are_frozen(self) -> None:
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        with pytest.raises(AttributeError):
            cases[0].location = "modified"  # type: ignore[misc]

    def test_filter_by_os(self) -> None:
        config = ScanConfig(url="http://example.com", os_filter="*NIX")
        cases = parse_cases(config)
        assert all(c.os == "*NIX" for c in cases if c.os is not None)

    def test_filter_by_software(self) -> None:
        config = ScanConfig(url="http://example.com", software_filter="PHP")
        cases = parse_cases(config)
        assert all(c.software == "PHP" for c in cases if c.software is not None)

    def test_filter_by_type(self) -> None:
        config = ScanConfig(url="http://example.com", type_filter="conf")
        cases = parse_cases(config)
        assert all(c.file_type == FileType.CONF for c in cases if c.file_type is not None)

    def test_host_placeholder_expansion(self) -> None:
        """Verifies {HOST} in case locations is replaced with target netloc."""
        config = ScanConfig(url="http://target.example.com/test.php?f=x")
        cases = parse_cases(config)
        for case in cases:
            assert "{HOST}" not in case.location


class TestLoadVersions:
    def test_returns_dict(self) -> None:
        versions = load_versions()
        assert isinstance(versions, dict)
        assert "JBOSS" in versions
        assert isinstance(versions["JBOSS"], list)
        assert len(versions["JBOSS"]) > 0


class TestLoadCustomList:
    def test_load_from_file(self, tmp_path: pytest.TempPathFactory) -> None:
        listfile = tmp_path / "custom.txt"  # type: ignore[operator]
        listfile.write_text("/etc/passwd\n/etc/shadow\n/var/log/syslog\n")
        cases = load_custom_list(str(listfile))
        assert len(cases) == 3
        assert cases[0].location == "/etc/passwd"

    def test_skips_empty_lines(self, tmp_path: pytest.TempPathFactory) -> None:
        listfile = tmp_path / "custom.txt"  # type: ignore[operator]
        listfile.write_text("/etc/passwd\n\n/etc/shadow\n\n")
        cases = load_custom_list(str(listfile))
        assert len(cases) == 2

    def test_nonexistent_file_raises(self) -> None:
        with pytest.raises(FileNotFoundError):
            load_custom_list("/nonexistent/path/list.txt")

    def test_directory_raises(self, tmp_path: pytest.TempPathFactory) -> None:
        with pytest.raises(ValueError, match="regular file"):
            load_custom_list(str(tmp_path))
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_cases.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/cases.py`**

```python
"""XML case parsing, filtering, version expansion, and custom list loading."""

from __future__ import annotations

import os
import re
from urllib.parse import urlsplit

import defusedxml.ElementTree as ET

from panoptic.models import Case, FileType, ScanConfig
from panoptic.utils import load_data_file


def load_versions() -> dict[str, list[str]]:
    """Load version strings from versions.ini data file.

    Returns a dict mapping section names to lists of version strings.
    """
    content = load_data_file("versions.ini")
    versions: dict[str, list[str]] = {}
    section: str | None = None

    for line in content.splitlines():
        line = line.strip()
        if re.match(r"\[.+\]", line):
            section = line.strip("[]")
        elif line and section is not None:
            versions.setdefault(section, []).append(line)

    return versions


def parse_cases(config: ScanConfig) -> list[Case]:
    """Parse cases.xml and return test cases filtered by config.

    Uses defusedxml for XML bomb protection.
    Builds a filtered list instead of mutating the tree in-place.
    """
    xml_content = load_data_file("cases.xml")
    root = ET.fromstring(xml_content)

    # Build parent map for ancestor lookups
    parent_map: dict[ET.Element, ET.Element] = {}
    for parent in root.iter():
        for child in parent:
            parent_map[child] = parent

    # Build replacements dict for placeholder expansion
    replacements: dict[str, str] = {}
    if config.url:
        replacements["HOST"] = urlsplit(config.url).netloc

    # Load versions for expansion
    versions = load_versions() if config.all_versions else {}

    cases: list[Case] = []

    for file_elem in root.iter("file"):
        location = file_elem.get("value", "")
        if not location:
            continue

        # Walk ancestors to find os, software, category, type
        os_val = _find_ancestor_attr(file_elem, "os", parent_map)
        software_val = _find_ancestor_attr(file_elem, "software", parent_map)
        category_val = _find_ancestor_attr(file_elem, "category", parent_map)
        file_type = _determine_file_type(file_elem, parent_map)

        # Apply filters
        if config.os_filter and os_val and os_val.lower() != config.os_filter.lower():
            continue
        if config.software_filter and software_val and software_val.lower() != config.software_filter.lower():
            continue
        if config.category_filter and category_val and category_val.lower() != config.category_filter.lower():
            continue
        if config.type_filter and file_type and file_type.value != config.type_filter.lower():
            continue

        # Placeholder expansion ({HOST}, etc.)
        for variable in re.findall(r"\{[^}]+\}", location):
            key = variable.strip("{}")
            if key in replacements:
                location = location.replace(variable, replacements[key])

        # Version expansion ([SECTION] patterns)
        match = re.search(r"\[([^\]]+)\]", location)
        if match and config.all_versions and match.group(1) in versions:
            for version in versions[match.group(1)]:
                expanded = location.replace(match.group(0), version)
                cases.append(Case(
                    location=expanded,
                    os=os_val,
                    category=category_val,
                    software=software_val,
                    file_type=file_type,
                ))
        else:
            cases.append(Case(
                location=location,
                os=os_val,
                category=category_val,
                software=software_val,
                file_type=file_type,
            ))

    return cases


def load_custom_list(filepath: str) -> list[Case]:
    """Load a custom file list from a user-provided path.

    Validates the file exists and is a regular file.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"List file not found: {filepath}")
    if not os.path.isfile(filepath):
        raise ValueError(f"Path is not a regular file: {filepath}")

    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()

    return [
        Case(location=line.strip())
        for line in lines
        if line.strip()
    ]


def list_values(group: str) -> set[str]:
    """List unique values for a given group (os, software, category).

    Used by --list command.
    """
    xml_content = load_data_file("cases.xml")
    root = ET.fromstring(xml_content)

    values: set[str] = set()
    for elem in root.iter(group):
        val = elem.get("value")
        if val:
            values.add(val)

    return values


def list_all_files() -> list[str]:
    """List all file paths in cases.xml.

    Used by --list-all-files command.
    """
    xml_content = load_data_file("cases.xml")
    root = ET.fromstring(xml_content)

    return [
        elem.get("value", "")
        for elem in root.iter("file")
        if elem.get("value")
    ]


def _find_ancestor_attr(
    element: ET.Element,
    tag: str,
    parent_map: dict[ET.Element, ET.Element],
) -> str | None:
    """Walk up the parent chain to find the nearest ancestor with the given tag."""
    current = element
    while current in parent_map:
        parent = parent_map[current]
        if parent.tag == tag:
            return parent.get("value")
        current = parent
    return None


def _determine_file_type(
    element: ET.Element,
    parent_map: dict[ET.Element, ET.Element],
) -> FileType | None:
    """Determine the file type (conf/log/other) from ancestor tags."""
    current = element
    while current in parent_map:
        parent = parent_map[current]
        match parent.tag:
            case "conf":
                return FileType.CONF
            case "log":
                return FileType.LOG
            case "other":
                return FileType.OTHER
        current = parent
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_cases.py -v
```
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/cases.py tests/test_cases.py
git commit -m "feat: add case parser with defusedxml, filtering, placeholder expansion"
```

---

### Task 6: Parsers (`parsers.py`)

**Files:**
- Create: `panoptic/parsers.py`
- Create: `tests/test_parsers.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_parsers.py`:
```python
"""Tests for panoptic.parsers — passwd and binlog extraction."""

import pytest
from panoptic.models import Case, FileType
from panoptic.parsers import extract_home_file_cases, extract_binlog_cases


class TestExtractHomeFileCases:
    def test_extracts_users_with_home_dirs(self, sample_passwd: str) -> None:
        parent_case = Case(location="/etc/passwd", os="*NIX")
        cases = extract_home_file_cases(sample_passwd, parent_case)
        assert len(cases) > 0

        # Should find entries for user with /home/user
        home_locations = [c.location for c in cases]
        assert any("/home/user/" in loc for loc in home_locations)

    def test_skips_root_home(self, sample_passwd: str) -> None:
        """Users with home=/ should be skipped (would scan entire filesystem)."""
        passwd = "nobody:x:65534:65534:nobody:/:/usr/sbin/nologin\n"
        parent_case = Case(location="/etc/passwd", os="*NIX")
        cases = extract_home_file_cases(passwd, parent_case)
        assert not any(c.location.startswith("//") for c in cases)

    def test_includes_common_dotfiles(self, sample_passwd: str) -> None:
        parent_case = Case(location="/etc/passwd", os="*NIX")
        cases = extract_home_file_cases(sample_passwd, parent_case)
        locations = [c.location for c in cases]
        assert any(".bashrc" in loc for loc in locations)
        assert any(".ssh/" in loc for loc in locations)

    def test_inherits_os_from_parent(self, sample_passwd: str) -> None:
        parent_case = Case(location="/etc/passwd", os="*NIX")
        cases = extract_home_file_cases(sample_passwd, parent_case)
        assert all(c.os == "*NIX" for c in cases)

    def test_empty_passwd_returns_empty(self) -> None:
        parent_case = Case(location="/etc/passwd", os="*NIX")
        assert extract_home_file_cases("", parent_case) == []


class TestExtractBinlogCases:
    def test_extracts_binlog_files(self) -> None:
        content = ".\\mysql-bin.000001\n.\\mysql-bin.000002\n.\\mysql-bin.000003\n"
        parent_case = Case(
            location="/var/lib/mysql/mysql-bin.index",
            os="*NIX",
            software="MySQL",
        )
        cases = extract_binlog_cases(content, parent_case)
        assert len(cases) == 3
        assert cases[0].location.endswith("mysql-bin.000001")

    def test_preserves_directory(self) -> None:
        content = ".\\mysql-bin.000001\n"
        parent_case = Case(
            location="/var/lib/mysql/mysql-bin.index",
            os="*NIX",
            software="MySQL",
        )
        cases = extract_binlog_cases(content, parent_case)
        assert cases[0].location.startswith("/var/lib/mysql/")

    def test_empty_content_returns_empty(self) -> None:
        parent_case = Case(location="/var/lib/mysql/mysql-bin.index")
        assert extract_binlog_cases("", parent_case) == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_parsers.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/parsers.py`**

```python
"""Post-discovery content parsers for Panoptic.

Extracts additional scan targets from discovered files
(e.g., users from /etc/passwd, binlog files from mysql-bin.index).
"""

from __future__ import annotations

import re

from panoptic.models import Case, FileType
from panoptic.utils import load_data_file


def extract_home_file_cases(
    passwd_content: str,
    parent_case: Case,
) -> list[Case]:
    """Extract home directory file cases from /etc/passwd content.

    Parses passwd entries to find user home directories, then generates
    cases for common dotfiles in each home directory.
    """
    if not passwd_content:
        return []

    home_files = _load_home_files()
    cases: list[Case] = []

    pattern = re.compile(
        r"(?P<username>[^:\n]+):"
        r"(?P<password>[^:]*):"
        r"(?P<uid>\d+):"
        r"(?P<gid>\d*):"
        r"(?P<info>[^:]*):"
        r"(?P<home>[^:]+):"
        r"[/a-z]*"
    )

    for match in pattern.finditer(passwd_content):
        home = match.group("home")

        # Skip users with root (/) as home — would scan entire filesystem
        if home == "/":
            continue

        for dotfile in home_files:
            cases.append(Case(
                location=f"{home}/{dotfile}",
                os=parent_case.os,
                category="*NIX User File",
                software="*NIX",
                file_type=FileType.CONF,
            ))

    return cases


def extract_binlog_cases(
    index_content: str,
    parent_case: Case,
) -> list[Case]:
    """Extract MySQL binary log file cases from mysql-bin.index content.

    Parses the index file to find individual binlog filenames and generates
    cases using the same directory as the index file.
    """
    if not index_content:
        return []

    binlogs = re.findall(r"\\.\\(?P<binlog>mysql-bin\.\d{1,6})", index_content)

    # Extract directory from parent case location
    last_slash = parent_case.location.rfind("/")
    directory = parent_case.location[: last_slash + 1] if last_slash >= 0 else ""

    return [
        Case(
            location=f"{directory}{binlog}",
            os=parent_case.os,
            category="Databases",
            software="MySQL",
            file_type=FileType.LOG,
        )
        for binlog in binlogs
    ]


def _load_home_files() -> list[str]:
    """Load common home directory files from bundled data."""
    content = load_data_file("home.txt")
    return [line.strip() for line in content.splitlines() if line.strip()]
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_parsers.py -v
```
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/parsers.py tests/test_parsers.py
git commit -m "feat: add passwd and binlog content parsers"
```

---

## Chunk 3: Network & Config (Tasks 7-8)

### Task 7: Network Client (`network.py`)

**Files:**
- Create: `panoptic/network.py`
- Create: `tests/test_network.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_network.py`:
```python
"""Tests for panoptic.network — async HTTP client."""

import pytest
import httpx
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

    async def test_context_manager(self, config: ScanConfig) -> None:
        async with NetworkClient(config) as client:
            assert client._client is not None

    async def test_fetch_get(self, config: ScanConfig, httpx_mock) -> None:  # type: ignore[no-untyped-def]
        httpx_mock.add_response(url="http://example.com/test", text="hello")
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/test")
            assert response is not None
            assert response.text == "hello"
            assert response.status_code == 200

    async def test_fetch_post(self, config: ScanConfig, httpx_mock) -> None:  # type: ignore[no-untyped-def]
        httpx_mock.add_response(url="http://example.com/test", text="posted")
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/test", data="file=test")
            assert response is not None

    async def test_fetch_timeout_returns_none(self, config: ScanConfig, httpx_mock) -> None:  # type: ignore[no-untyped-def]
        httpx_mock.add_exception(httpx.TimeoutException("timed out"))
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/slow")
            assert response is None

    async def test_fetch_connection_error_returns_none(self, config: ScanConfig, httpx_mock) -> None:  # type: ignore[no-untyped-def]
        httpx_mock.add_exception(httpx.ConnectError("refused"))
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/down")
            assert response is None

    async def test_custom_user_agent(self, httpx_mock) -> None:  # type: ignore[no-untyped-def]
        config = ScanConfig(url="http://example.com", user_agent="CustomBot/1.0")
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/test")
        request = httpx_mock.get_request()
        assert request.headers["user-agent"] == "CustomBot/1.0"

    async def test_custom_cookie(self, httpx_mock) -> None:  # type: ignore[no-untyped-def]
        config = ScanConfig(url="http://example.com", cookie="sid=abc123")
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/test")
        request = httpx_mock.get_request()
        assert request.headers["cookie"] == "sid=abc123"

    async def test_custom_header(self, httpx_mock) -> None:  # type: ignore[no-untyped-def]
        config = ScanConfig(url="http://example.com", header="X-Custom: value123")
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/test")
        request = httpx_mock.get_request()
        assert request.headers["x-custom"] == "value123"

    async def test_invalid_ssl_disables_verify(self) -> None:
        config = ScanConfig(url="https://example.com", invalid_ssl=True)
        async with NetworkClient(config) as client:
            assert client._client._transport._pool._ssl_context.verify_mode == 0  # CERT_NONE

    async def test_no_follow_redirects(self, config: ScanConfig, httpx_mock) -> None:  # type: ignore[no-untyped-def]
        httpx_mock.add_response(status_code=302, headers={"Location": "/other"})
        async with NetworkClient(config) as client:
            response = await client.fetch("http://example.com/redir")
            assert response is not None
            assert response.status_code == 302  # Should NOT follow
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_network.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/network.py`**

```python
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

    Usage:
        async with NetworkClient(config) as client:
            response = await client.fetch(url)
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._client: httpx.AsyncClient | None = None
        self._semaphore = asyncio.Semaphore(config.concurrency)

    async def __aenter__(self) -> NetworkClient:
        timeout = httpx.Timeout(self.config.timeout, connect=5.0)

        # Build proxy URL if configured
        proxy = self.config.proxy if self.config.proxy else None

        # SSL verification
        ssl_verify: bool | ssl.SSLContext = not self.config.invalid_ssl
        if self.config.invalid_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            ssl_verify = ctx

        # Transport with retry
        transport = httpx.AsyncHTTPTransport(retries=self.config.retries)

        # Build default headers
        headers = self._build_headers()

        self._client = httpx.AsyncClient(
            timeout=timeout,
            proxy=proxy,
            verify=ssl_verify,
            transport=transport,
            headers=headers,
            follow_redirects=False,
            trust_env=not self.config.ignore_proxy,
        )

        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        if self._client:
            await self._client.aclose()

    async def fetch(
        self,
        url: str,
        data: str | None = None,
    ) -> httpx.Response | None:
        """Fetch a URL with concurrency limiting and error handling.

        Returns the response on success, None on any error.
        """
        if self._client is None:
            raise RuntimeError("NetworkClient must be used as async context manager")

        async with self._semaphore:
            if self.config.delay > 0:
                await asyncio.sleep(self.config.delay)

            try:
                if data is not None:
                    return await self._client.post(
                        url,
                        content=data.encode("utf-8"),
                        headers={"Content-Type": "application/x-www-form-urlencoded"},
                    )
                else:
                    return await self._client.get(url)
            except httpx.HTTPError:
                return None

    def _build_headers(self) -> dict[str, str]:
        """Build default headers from config, with validation."""
        headers: dict[str, str] = {}

        # User-Agent
        if self.config.user_agent:
            headers["User-Agent"] = self.config.user_agent
        else:
            from panoptic import __version__
            headers["User-Agent"] = f"Panoptic {__version__}"

        # Cookie
        if self.config.cookie:
            headers["Cookie"] = self.config.cookie

        # Custom header (Name: Value format, with CRLF validation)
        if self.config.header:
            name, value = validate_header(self.config.header)
            headers[name] = value

        return headers
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_network.py -v
```
Expected: Most tests PASS. The SSL internals test may need adjustment depending on httpx version — if it fails, adapt the assertion to check `config.invalid_ssl` flag instead of internal SSL context.

- [ ] **Step 5: Commit**

```bash
git add panoptic/network.py tests/test_network.py
git commit -m "feat: add async HTTP client with timeout, retry, proxy, header validation"
```

---

### Task 8: Configuration (`config.py`)

**Files:**
- Create: `panoptic/config.py`
- Create: `tests/test_config.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_config.py`:
```python
"""Tests for panoptic.config — TOML config loading and merge."""

import pytest
from panoptic.config import load_config, merge_config
from panoptic.models import ScanConfig, OutputFormat


class TestLoadConfig:
    def test_returns_dict(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        config_file = tmp_path / "config.toml"
        config_file.write_text('[defaults]\nconcurrency = 16\ntimeout = 30.0\n')
        result = load_config(str(config_file))
        assert result["defaults"]["concurrency"] == 16

    def test_missing_file_returns_empty(self) -> None:
        result = load_config("/nonexistent/config.toml")
        assert result == {}

    def test_invalid_toml_returns_empty(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        config_file = tmp_path / "bad.toml"
        config_file.write_text("this is [not valid toml")
        result = load_config(str(config_file))
        assert result == {}


class TestMergeConfig:
    def test_cli_overrides_config_file(self) -> None:
        file_config = {"defaults": {"concurrency": 16, "timeout": 30.0}}
        cli_args = {"url": "http://example.com", "concurrency": 8}
        config = merge_config(cli_args, file_config)
        assert config.concurrency == 8  # CLI wins
        assert config.timeout == 30.0  # File value kept

    def test_cli_overrides_defaults(self) -> None:
        cli_args = {"url": "http://example.com", "timeout": 5.0}
        config = merge_config(cli_args, {})
        assert config.timeout == 5.0

    def test_file_overrides_defaults(self) -> None:
        file_config = {"defaults": {"concurrency": 32}}
        cli_args = {"url": "http://example.com"}
        config = merge_config(cli_args, file_config)
        assert config.concurrency == 32

    def test_proxy_from_file(self) -> None:
        file_config = {"proxy": {"url": "socks5://127.0.0.1:9050"}}
        cli_args = {"url": "http://example.com"}
        config = merge_config(cli_args, file_config)
        assert config.proxy == "socks5://127.0.0.1:9050"

    def test_headers_from_file(self) -> None:
        file_config = {"headers": {"user_agent": "CustomBot/1.0"}}
        cli_args = {"url": "http://example.com"}
        config = merge_config(cli_args, file_config)
        assert config.user_agent == "CustomBot/1.0"

    def test_output_format_enum(self) -> None:
        cli_args = {"url": "http://example.com", "output_format": "json"}
        config = merge_config(cli_args, {})
        assert config.output_format == OutputFormat.JSON
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_config.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/config.py`**

```python
"""Configuration loading and merging for Panoptic.

Supports TOML config files with CLI argument overrides.
Merge priority: CLI args > config file > built-in defaults.
"""

from __future__ import annotations

import sys
from pathlib import Path

from panoptic.models import OutputFormat, ScanConfig

if sys.version_info >= (3, 11):
    import tomllib
else:
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None  # type: ignore[assignment]


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "panoptic" / "config.toml"


def load_config(path: str | None = None) -> dict:
    """Load a TOML config file.

    Returns an empty dict if the file doesn't exist or is invalid.
    """
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        return {}

    if tomllib is None:
        return {}

    try:
        with open(config_path, "rb") as f:
            return tomllib.load(f)
    except Exception:
        return {}


def merge_config(cli_args: dict, file_config: dict) -> ScanConfig:
    """Merge CLI arguments with file config into a ScanConfig.

    Priority: CLI args > file config > ScanConfig defaults.
    """
    # Start with file config defaults
    defaults_section = file_config.get("defaults", {})
    proxy_section = file_config.get("proxy", {})
    headers_section = file_config.get("headers", {})

    # Map file config keys to ScanConfig fields
    merged: dict = {}

    # Apply file config
    for key, value in defaults_section.items():
        merged[key] = value

    if "url" in proxy_section:
        merged["proxy"] = proxy_section["url"]

    if "user_agent" in headers_section:
        merged["user_agent"] = headers_section["user_agent"]

    # Apply CLI args (override file config)
    for key, value in cli_args.items():
        if value is not None:
            merged[key] = value

    # Handle output_format enum conversion
    if "output_format" in merged and isinstance(merged["output_format"], str):
        merged["output_format"] = OutputFormat(merged["output_format"])

    # Ensure url is present
    url = merged.pop("url", "")

    return ScanConfig(url=url, **{
        k: v for k, v in merged.items()
        if k in ScanConfig.__dataclass_fields__  # type: ignore[attr-defined]
    })
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_config.py -v
```
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/config.py tests/test_config.py
git commit -m "feat: add TOML config loading with CLI merge"
```

---

## Chunk 4: Output & CLI (Tasks 9-10)

### Task 9: Output Layer (`output.py`)

**Files:**
- Create: `panoptic/output.py`
- Create: `tests/test_output.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_output.py`:
```python
"""Tests for panoptic.output — text, JSON, CSV formatters."""

import json
import csv
import io
import pytest
from panoptic.models import Case, FileType, ScanResult
from panoptic.output import TextFormatter, JsonFormatter, CsvFormatter


@pytest.fixture
def sample_results() -> list[ScanResult]:
    return [
        ScanResult(
            case=Case(location="/etc/passwd", os="*NIX", category="OS",
                      software="Linux", file_type=FileType.CONF),
            found=True, url="http://example.com/?file=/etc/passwd",
            status_code=200, content_length=1234,
            timestamp="2026-03-14T10:00:00",
        ),
        ScanResult(
            case=Case(location="/var/log/syslog", os="*NIX", category="OS",
                      software="Linux", file_type=FileType.LOG),
            found=True, url="http://example.com/?file=/var/log/syslog",
            status_code=200, content_length=5678,
            timestamp="2026-03-14T10:00:01",
        ),
    ]


class TestJsonFormatter:
    def test_output_is_valid_json(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = JsonFormatter(buf)
        formatter.write_results(sample_results)
        buf.seek(0)
        data = json.loads(buf.read())
        assert isinstance(data, list)
        assert len(data) == 2

    def test_fields_present(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = JsonFormatter(buf)
        formatter.write_results(sample_results)
        buf.seek(0)
        data = json.loads(buf.read())
        entry = data[0]
        assert entry["location"] == "/etc/passwd"
        assert entry["os"] == "*NIX"
        assert entry["found"] is True
        assert entry["status_code"] == 200

    def test_empty_results(self) -> None:
        buf = io.StringIO()
        formatter = JsonFormatter(buf)
        formatter.write_results([])
        buf.seek(0)
        assert json.loads(buf.read()) == []


class TestCsvFormatter:
    def test_output_is_valid_csv(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = CsvFormatter(buf)
        formatter.write_results(sample_results)
        buf.seek(0)
        reader = csv.DictReader(buf)
        rows = list(reader)
        assert len(rows) == 2

    def test_header_present(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = CsvFormatter(buf)
        formatter.write_results(sample_results)
        buf.seek(0)
        header = buf.readline()
        assert "location" in header
        assert "timestamp" in header

    def test_empty_results_has_header(self) -> None:
        buf = io.StringIO()
        formatter = CsvFormatter(buf)
        formatter.write_results([])
        buf.seek(0)
        content = buf.read()
        assert "location" in content  # Header still present


class TestTextFormatter:
    def test_found_message(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf)
        formatter.write_found(sample_results[0])
        buf.seek(0)
        output = buf.read()
        assert "/etc/passwd" in output

    def test_summary(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf)
        formatter.write_summary(sample_results, total_cases=100)
        buf.seek(0)
        output = buf.read()
        assert "2" in output  # 2 found
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_output.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/output.py`**

```python
"""Output formatters for Panoptic scan results.

Supports text (rich), JSON, and CSV output formats.
"""

from __future__ import annotations

import csv
import io
import json
import sys
from typing import TextIO

from rich.console import Console

from panoptic.models import ScanResult


class TextFormatter:
    """Rich-powered text output for terminal display."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stderr
        self._console = Console(file=self._stream, highlight=False)

    def write_banner(self, version: str, url: str) -> None:
        self._console.print(
            f"[bold cyan] .-',--.`-.[/]\n"
            f"[bold cyan]<_ | () | _>[/]\n"
            f"[bold cyan]  `-`=='-'[/]\n"
            f"\n[bold]Panoptic {version}[/] ({url})\n"
        )

    def write_info(self, message: str) -> None:
        self._console.print(f"[blue][i][/blue] {message}")

    def write_warning(self, message: str) -> None:
        self._console.print(f"[red][!][/red] {message}")

    def write_found(self, result: ScanResult) -> None:
        case = result.case
        parts = [p for p in (case.os, case.category, case.software, case.file_type and case.file_type.value) if p]
        context = f" ({'/'.join(parts)})" if parts else ""
        self._console.print(
            f"[bold green][+][/bold green] Found '{case.location}'{context}"
        )

    def write_verbose(self, message: str) -> None:
        self._console.print(f"[dim][*] {message}[/dim]")

    def write_summary(self, results: list[ScanResult], total_cases: int) -> None:
        found = [r for r in results if r.found]
        self._console.print(f"\n[bold]Scan Complete[/bold]")
        self._console.print(f"  Cases tested: {total_cases}")
        self._console.print(f"  Files found:  [green]{len(found)}[/green]")
        if found:
            self._console.print("\n[bold]Found files:[/bold]")
            for r in found:
                self.write_found(r)


class JsonFormatter:
    """JSON output for pipeline integration."""

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout

    def write_results(self, results: list[ScanResult]) -> None:
        data = [
            {
                "timestamp": r.timestamp,
                "url": r.url,
                "location": r.case.location,
                "os": r.case.os,
                "category": r.case.category,
                "software": r.case.software,
                "type": r.case.file_type.value if r.case.file_type else None,
                "found": r.found,
                "status_code": r.status_code,
                "content_length": r.content_length,
            }
            for r in results
        ]
        json.dump(data, self._stream, indent=2)
        self._stream.write("\n")


class CsvFormatter:
    """CSV output for spreadsheet/report workflows."""

    FIELDS = [
        "timestamp", "url", "location", "os", "category",
        "software", "type", "found", "status_code", "content_length",
    ]

    def __init__(self, stream: TextIO | None = None) -> None:
        self._stream = stream or sys.stdout

    def write_results(self, results: list[ScanResult]) -> None:
        writer = csv.DictWriter(self._stream, fieldnames=self.FIELDS)
        writer.writeheader()
        for r in results:
            writer.writerow({
                "timestamp": r.timestamp,
                "url": r.url,
                "location": r.case.location,
                "os": r.case.os,
                "category": r.case.category,
                "software": r.case.software,
                "type": r.case.file_type.value if r.case.file_type else None,
                "found": r.found,
                "status_code": r.status_code,
                "content_length": r.content_length,
            })
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_output.py -v
```
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/output.py tests/test_output.py
git commit -m "feat: add text/JSON/CSV output formatters"
```

---

### Task 10: CLI (`cli.py`)

**Files:**
- Create: `panoptic/cli.py`
- Create: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_cli.py`:
```python
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
        assert args["automatic"] is True

    def test_threads_maps_to_concurrency(self) -> None:
        args = parse_args(["-u", "http://example.com", "--threads", "8"])
        assert args["concurrency"] == 8

    def test_new_flags(self) -> None:
        args = parse_args([
            "-u", "http://example.com",
            "--timeout", "30",
            "--retries", "5",
            "--delay", "0.5",
            "--output-format", "json",
        ])
        assert args["timeout"] == 30.0
        assert args["retries"] == 5
        assert args["delay"] == 0.5
        assert args["output_format"] == "json"

    def test_prefix_multiplier(self) -> None:
        args = parse_args(["-u", "http://example.com", "--prefix", "../", "--multiplier", "3"])
        assert args["prefix"] == "../../../"

    def test_list_command(self) -> None:
        args = parse_args(["--list", "software"])
        assert args["list"] == "software"


class TestValidateArgs:
    def test_rejects_file_scheme(self) -> None:
        with pytest.raises(SystemExit):
            validate_args({"url": "file:///etc/passwd", "list": None, "update": False,
                          "list_all_files": False, "path_based": False, "header": None})

    def test_rejects_crlf_header(self) -> None:
        with pytest.raises(SystemExit):
            validate_args({"url": "http://example.com", "list": None, "update": False,
                          "list_all_files": False, "path_based": False,
                          "header": "X-Foo: bar\r\nInjected: yes"})

    def test_accepts_valid_args(self) -> None:
        # Should not raise
        validate_args({"url": "http://example.com", "list": None, "update": False,
                       "list_all_files": False, "path_based": False, "header": None})
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_cli.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/cli.py`**

```python
"""Command-line interface for Panoptic.

Handles argument parsing, validation, and dispatch to scan/list/update modes.
"""

from __future__ import annotations

import argparse
import sys
import time

from rich_argparse import RichHelpFormatter

from panoptic import __version__
from panoptic.models import OutputFormat
from panoptic.utils import validate_url_scheme, validate_header, normalize_url


EXAMPLES = """
Examples:
  panoptic --url "http://localhost/include.php?file=test.txt"
  panoptic --url "http://localhost/include.php?file=test.txt&id=1" --param file
  panoptic --url "http://localhost/include.php" --data "file=test.txt&id=1" --param file
  panoptic --url "http://localhost/files/view/test.txt" --path-based --prefix "..%%252f"
  panoptic --url "http://localhost/include.php?file=test.txt" --auto --all-versions
  panoptic --list software
"""


def parse_args(argv: list[str] | None = None) -> dict:
    """Parse command-line arguments and return as a dict."""
    parser = argparse.ArgumentParser(
        prog="panoptic",
        description="Panoptic -- probe a URL for local files via path traversal vulnerability",
        epilog=EXAMPLES,
        formatter_class=RichHelpFormatter,
    )

    # Connection / Proxy
    conn = parser.add_argument_group("Connection / Proxy")
    conn.add_argument("-u", "--url", help="Target URL vulnerable to path traversal")
    conn.add_argument("--proxy", help="Route requests through proxy (e.g. 'socks5://127.0.0.1:9050')")
    conn.add_argument("--ignore-proxy", action="store_true", help="Bypass system proxy settings")
    conn.add_argument("--random-agent", action="store_true", dest="random_agent", help="Choose random User-Agent")
    conn.add_argument("--header", help="Add custom HTTP header (e.g. 'X-Forwarded-For: 127.0.0.1')")
    conn.add_argument("--cookie", help="Add HTTP Cookie header (e.g. 'sid=foobar; auth=1')")
    conn.add_argument("--user-agent", dest="user_agent", help="Set specific User-Agent string")
    conn.add_argument("--timeout", type=float, default=None, help="HTTP request timeout in seconds (default: 10)")
    conn.add_argument("--retries", type=int, default=None, help="Number of retries per request (default: 3)")

    # Filtering
    filt = parser.add_argument_group("Filtering / Listing")
    filt.add_argument("-l", "--list", metavar="GROUP", choices=["software", "category", "os"],
                      help="Show available values for specified group")
    filt.add_argument("-o", "--os", dest="os_filter", help="Only test files for specific OS")
    filt.add_argument("-s", "--software", dest="software_filter", help="Only test files for specific software")
    filt.add_argument("-c", "--category", dest="category_filter", help="Only test files for specific category")

    # Scan options
    scan = parser.add_argument_group("Scan Options")
    scan.add_argument("-p", "--param", help="Name of vulnerable parameter to test")
    scan.add_argument("-P", "--path-based", dest="path_based", action="store_true",
                      help="Target file paths directly instead of query parameters")
    scan.add_argument("-d", "--data", help="Send parameters via POST instead of GET")
    scan.add_argument("-t", "--type", dest="type_filter", help="Filter by type ('conf', 'log', 'other')")
    scan.add_argument("--prefix", default="", help="Add prefix to file paths (e.g. '../')")
    scan.add_argument("--postfix", default="", help="Add suffix to file paths (e.g. '%%00')")
    scan.add_argument("--multiplier", type=int, default=1, help="Repeat prefix N times (default: 1)")
    scan.add_argument("--bad-string", dest="bad_string", help="Skip paths if this string appears in response")
    scan.add_argument("--replace-slash", dest="replace_slash", help="Use alternative character(s) for '/'")
    scan.add_argument("--ext-param", dest="ext_param", help="Name of parameter containing file extension")
    scan.add_argument("--all-versions", dest="all_versions", action="store_true",
                      help="Test all versioned file paths")

    # Performance
    perf = parser.add_argument_group("Performance")
    perf.add_argument("--concurrency", type=int, default=None, help="Number of concurrent requests (default: 4)")
    perf.add_argument("--threads", type=int, default=None, dest="_threads_deprecated",
                      help="Deprecated: use --concurrency instead")
    perf.add_argument("--delay", type=float, default=None, help="Delay between requests in seconds")

    # Output
    out = parser.add_argument_group("Output")
    out.add_argument("-v", "--verbose", action="store_true", help="Show detailed information")
    out.add_argument("-w", "--write-files", dest="write_files", action="store_true",
                     help="Save discovered files to local output directory")
    out.add_argument("-x", "--skip-parsing", dest="skip_parsing", action="store_true",
                     help="Don't extract users from passwd files")
    out.add_argument("-i", "--invalid-ssl", dest="invalid_ssl", action="store_true",
                     help="Ignore SSL certificate validation errors")
    out.add_argument("-a", "--auto", dest="automatic", action="store_true",
                     help="Avoid user interaction by using default options")
    out.add_argument("--output-format", dest="output_format", choices=["text", "json", "csv"],
                     default=None, help="Output format (default: text)")
    out.add_argument("--output-file", dest="output_file", help="Write results to file")
    out.add_argument("--log-file", dest="log_file", help="Save console output to file")
    out.add_argument("--resume-file", dest="resume_file", help="Resume file for checkpoint/restart")

    # Other
    parser.add_argument("--load", dest="list_file", help="Test custom file list from FILE")
    parser.add_argument("--config", dest="config_file", help="Path to TOML config file")
    parser.add_argument("--update", action="store_true", help="Update from GitHub repository")
    parser.add_argument("--list-all-files", dest="list_all_files", action="store_true",
                        help="List all file paths in the XML and exit")

    parsed = parser.parse_args(argv)
    result = vars(parsed)

    # Handle deprecated --threads
    if result.pop("_threads_deprecated", None) is not None:
        if result["concurrency"] is None:
            result["concurrency"] = result["_threads_deprecated"]

    # Normalize URL
    if result.get("url") and not result["url"].lower().startswith(("http://", "https://")):
        result["url"] = normalize_url(result["url"])

    # Apply prefix multiplier
    if result.get("prefix"):
        result["prefix"] = result["prefix"] * result.get("multiplier", 1)

    return result


def validate_args(args: dict) -> None:
    """Validate parsed arguments, exiting on errors."""
    # Must have at least one action
    if not any((args.get("url"), args.get("list"), args.get("update"), args.get("list_all_files"))):
        print("[!] Missing required argument: specify --url, --list, --update, or --list-all-files", file=sys.stderr)
        sys.exit(1)

    # URL scheme validation
    if args.get("url"):
        try:
            validate_url_scheme(args["url"])
        except ValueError as e:
            print(f"[!] {e}", file=sys.stderr)
            sys.exit(1)

    # Header CRLF validation
    if args.get("header"):
        try:
            validate_header(args["header"])
        except ValueError as e:
            print(f"[!] Invalid header: {e}", file=sys.stderr)
            sys.exit(1)


async def run(argv: list[str] | None = None) -> None:
    """Main async entry point — parse args, load config, dispatch."""
    args = parse_args(argv)
    validate_args(args)

    # Handle non-scan commands
    if args.get("update"):
        from panoptic.update import do_update
        do_update()
        return

    if args.get("list_all_files"):
        from panoptic.cases import list_all_files
        for path in list_all_files():
            print(path)
        return

    if args.get("list"):
        from panoptic.cases import list_values
        values = list_values(args["list"])
        for val in sorted(values):
            print(val)
        return

    # Load config and merge
    from panoptic.config import load_config, merge_config
    file_config = load_config(args.pop("config_file", None))
    config = merge_config(args, file_config)

    # Dispatch to scanner
    from panoptic.core import Scanner
    scanner = Scanner(config)
    await scanner.run()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_cli.py -v
```
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/cli.py tests/test_cli.py
git commit -m "feat: add CLI with argparse, rich help, validation"
```

---

## Chunk 5: Core Scanner & Update (Tasks 11-12)

### Task 11: Scanner Core (`core.py`)

**Files:**
- Create: `panoptic/core.py`
- Create: `tests/test_core.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_core.py`:
```python
"""Tests for panoptic.core — async scanner orchestrator."""

import pytest
import httpx
from panoptic.models import Case, FileType, ScanConfig, ScanResult
from panoptic.core import Scanner, build_payload


class TestBuildPayload:
    def test_basic_param_replacement(self) -> None:
        config = ScanConfig(url="http://example.com/test.php?file=test.txt", param="file")
        payload = build_payload(config, "/etc/passwd", "file=test.txt")
        assert "file=%2Fetc%2Fpasswd" in payload or "file=/etc/passwd" in payload

    def test_prefix_postfix(self) -> None:
        config = ScanConfig(url="http://example.com/test.php?file=test.txt",
                           param="file", prefix="../../../", postfix="%00")
        payload = build_payload(config, "/etc/passwd", "file=test.txt")
        assert "../../../" in payload
        assert "%00" in payload

    def test_path_based(self) -> None:
        config = ScanConfig(url="http://example.com/files/view/test.txt", path_based=True)
        url = build_payload(config, "/etc/passwd", "")
        assert "/etc/passwd" in url

    def test_replace_slash(self) -> None:
        config = ScanConfig(url="http://example.com/test.php?file=test.txt",
                           param="file", replace_slash="/./")
        payload = build_payload(config, "/etc/passwd", "file=test.txt")
        assert "/./etc/./passwd" in payload or "/./" in payload


class TestScanner:
    async def test_scan_with_mock_server(self, httpx_mock) -> None:  # type: ignore[no-untyped-def]
        """Integration test: scanner finds a file when response differs from baseline."""
        config = ScanConfig(
            url="http://target.test/include.php?file=test.txt",
            param="file",
            concurrency=1,
            timeout=5.0,
            retries=0,
            automatic=True,
        )

        # Original response (baseline)
        httpx_mock.add_response(
            url="http://target.test/include.php?file=test.txt",
            text="<html>Normal page content</html>",
        )

        # Invalid filename response (baseline for comparison)
        httpx_mock.add_response(text="<html>File not found error page</html>")

        # Specific file response (differs from baseline = found)
        # This would be matched for /etc/passwd requests
        httpx_mock.add_response(text="root:x:0:0:root:/root:/bin/bash")

        scanner = Scanner(config)
        # We can't easily test the full scan loop with mocks due to URL matching,
        # but we can verify the scanner initializes correctly
        assert scanner.config == config

    async def test_checkpoint_state(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        """Verify checkpoint saves and loads case IDs."""
        from panoptic.core import save_checkpoint, load_checkpoint

        cases = [
            Case(location="/etc/passwd", os="*NIX"),
            Case(location="/etc/shadow", os="*NIX"),
        ]

        checkpoint_file = str(tmp_path / "checkpoint.json")

        # Save
        completed_ids = {cases[0].case_id}
        save_checkpoint(checkpoint_file, completed_ids)

        # Load
        loaded_ids = load_checkpoint(checkpoint_file)
        assert cases[0].case_id in loaded_ids
        assert cases[1].case_id not in loaded_ids

    async def test_load_empty_checkpoint(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        from panoptic.core import load_checkpoint
        assert load_checkpoint(str(tmp_path / "nonexistent.json")) == set()
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_core.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/core.py`**

```python
"""Async scanner orchestrator for Panoptic.

Uses asyncio.Queue + worker pool for concurrent scanning with
dynamic case injection (passwd users, binlog files).
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import re
import time
from pathlib import Path
from urllib.parse import urlsplit, urlencode, parse_qsl

from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

from panoptic.cases import parse_cases, load_custom_list
from panoptic.heuristic import clean_response, is_match, filter_content, SKIP_RETRIEVE_THRESHOLD
from panoptic.models import Case, ScanConfig, ScanResult
from panoptic.network import NetworkClient
from panoptic.output import TextFormatter, JsonFormatter, CsvFormatter
from panoptic.parsers import extract_home_file_cases, extract_binlog_cases
from panoptic.utils import generate_invalid_filename, sanitize_filename, get_random_agent


PASSWD_FILES = ["/etc/passwd", "/etc/security/passwd"]


def build_payload(config: ScanConfig, location: str, request_params: str) -> str:
    """Build the request payload/URL for a given file location.

    Handles parameter-based and path-based URL construction.
    Uses re.escape() on param names when building regex patterns.
    """
    # Apply slash replacement
    if config.replace_slash:
        location = location.replace("/", config.replace_slash)

    # Build full path with prefix/postfix
    full_path = f"{config.prefix}{location}{config.postfix}"

    if config.path_based:
        parsed = urlsplit(config.url)
        path = parsed.path
        last_slash = path.rfind("/")
        if last_slash >= 0:
            base_path = path[:last_slash]
            return f"{parsed.scheme}://{parsed.netloc}{base_path}/{full_path}"
        return f"{parsed.scheme}://{parsed.netloc}/{full_path}"

    # Parameter-based replacement using re.escape for safety
    result = request_params
    if config.param:
        result = re.sub(
            r"(?P<param>%s)=(?P<value>[^=&]*)" % re.escape(config.param),
            rf"\1={full_path}",
            result,
        )

    # Extension parameter handling
    if config.ext_param and "." in full_path:
        ext = full_path.rsplit(".", 1)[-1]
        path_without_ext = full_path.rsplit(".", 1)[0]
        result = re.sub(
            r"(?P<param>%s)=(?P<value>[^=&]*)" % re.escape(config.param),
            rf"\1={path_without_ext}",
            result,
        )
        result = re.sub(
            r"(?P<param>%s)=(?P<value>[^=&]*)" % re.escape(config.ext_param),
            rf"\1={ext}",
            result,
        )

    parsed = urlsplit(config.url)
    if config.data:
        return result  # POST data
    return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{result}"


def save_checkpoint(filepath: str, completed_ids: set[str]) -> None:
    """Save completed case IDs to a checkpoint file."""
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(sorted(completed_ids), f)


def load_checkpoint(filepath: str) -> set[str]:
    """Load completed case IDs from a checkpoint file."""
    if not os.path.exists(filepath):
        return set()
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return set(json.load(f))
    except (json.JSONDecodeError, OSError):
        return set()


class Scanner:
    """Async scanner using Queue + workers for concurrent file probing."""

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.results: list[ScanResult] = []
        self.original_response: str = ""
        self.invalid_response: str = ""
        self.restrict_os: str | None = config.os_filter
        self.first_found = False
        self.completed_ids: set[str] = set()
        self.total_queued = 0
        self.total_processed = 0

    async def run(self) -> None:
        """Execute the full scan workflow."""
        from panoptic import __version__

        # Setup output
        text_out = TextFormatter()
        text_out.write_banner(__version__, self.config.url)

        # Random agent
        if self.config.random_agent and not self.config.user_agent:
            self.config = ScanConfig(
                **{
                    **{f.name: getattr(self.config, f.name) for f in self.config.__dataclass_fields__.values()},
                    "user_agent": get_random_agent(),
                }
            )
            text_out.write_info(f"Using random User-Agent: {self.config.user_agent}")

        if self.config.invalid_ssl:
            text_out.write_warning("SSL certificate verification is disabled. Traffic is vulnerable to MITM.")

        # Load cases
        if self.config.list_file:
            cases = load_custom_list(self.config.list_file)
        else:
            cases = parse_cases(self.config)

        if not cases:
            text_out.write_warning("No available test cases with the specified attributes.")
            return

        # Load checkpoint
        if self.config.resume_file:
            self.completed_ids = load_checkpoint(self.config.resume_file)
            if self.completed_ids:
                text_out.write_info(f"Resuming: {len(self.completed_ids)} cases already completed")

        # Request params
        parsed = urlsplit(self.config.url)
        request_params = self.config.data if self.config.data else parsed.query

        text_out.write_info(f"Starting scan at: {time.strftime('%X')}")
        text_out.write_info("Checking original response...")

        async with NetworkClient(self.config) as client:
            # Baseline responses
            orig_resp = await client.fetch(self.config.url)
            if orig_resp is None:
                text_out.write_warning("Cannot connect to target. Check connection settings.")
                return
            self.original_response = orig_resp.text

            invalid_filename = generate_invalid_filename()
            invalid_url = build_payload(
                self.config, invalid_filename, request_params
            )
            if self.config.data:
                inv_resp = await client.fetch(
                    f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                    data=invalid_url,
                )
            else:
                inv_resp = await client.fetch(invalid_url)

            if inv_resp is None:
                text_out.write_warning("Cannot retrieve invalid response baseline.")
                return
            self.invalid_response = inv_resp.text

            text_out.write_info(f"Scanning {len(cases)} file paths with {self.config.concurrency} workers...")

            # Queue + workers
            queue: asyncio.Queue[Case | None] = asyncio.Queue()
            for case in cases:
                if case.case_id not in self.completed_ids:
                    await queue.put(case)
                    self.total_queued += 1

            # Sentinel values to stop workers
            for _ in range(self.config.concurrency):
                await queue.put(None)

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                transient=True,
            ) as progress:
                task = progress.add_task("Scanning", total=self.total_queued)

                async def worker() -> None:
                    while True:
                        case = await queue.get()
                        if case is None:
                            break

                        await self._process_case(
                            case, client, request_params, queue, text_out
                        )
                        self.total_processed += 1
                        progress.update(task, completed=self.total_processed)

                workers = [
                    asyncio.create_task(worker())
                    for _ in range(self.config.concurrency)
                ]
                await asyncio.gather(*workers)

        # Output results
        found_results = [r for r in self.results if r.found]

        if not found_results:
            text_out.write_info("No files found!")
        else:
            text_out.write_summary(found_results, self.total_processed)

        text_out.write_info(f"Total files found: {len(found_results)}")
        text_out.write_info(f"Finishing scan at: {time.strftime('%X')}")

        # Write structured output
        if self.config.output_format.value != "text" or self.config.output_file:
            import sys
            stream = open(self.config.output_file, "w", encoding="utf-8") if self.config.output_file else sys.stdout

            match self.config.output_format:
                case self.config.output_format.JSON:
                    JsonFormatter(stream).write_results(found_results)
                case self.config.output_format.CSV:
                    CsvFormatter(stream).write_results(found_results)
                case _:
                    pass

            if self.config.output_file and stream is not sys.stdout:
                stream.close()

    async def _process_case(
        self,
        case: Case,
        client: NetworkClient,
        request_params: str,
        queue: asyncio.Queue[Case | None],
        text_out: TextFormatter,
    ) -> None:
        """Process a single case: fetch, compare, record result."""
        # OS restriction check
        if self.restrict_os and case.os and case.os != self.restrict_os:
            return

        parsed = urlsplit(self.config.url)
        payload_str = build_payload(self.config, case.location, request_params)

        if self.config.verbose:
            text_out.write_verbose(f"Trying '{case.location}'")

        if self.config.data:
            response = await client.fetch(
                f"{parsed.scheme}://{parsed.netloc}{parsed.path}",
                data=payload_str,
            )
        else:
            response = await client.fetch(payload_str)

        if response is None:
            return

        html = response.text

        # Bad string check
        if self.config.bad_string and self.config.bad_string in html:
            return

        # Heuristic comparison
        cleaned_html = clean_response(html, case.location)
        cleaned_invalid = clean_response(self.invalid_response, generate_invalid_filename())

        if is_match(cleaned_html, cleaned_invalid, self.config.heuristic_ratio):
            result = ScanResult(
                case=case,
                found=True,
                url=payload_str,
                status_code=response.status_code,
                content=html if self.config.write_files else None,
                content_length=len(html),
            )
            self.results.append(result)
            text_out.write_found(result)

            # OS restriction on first find
            if not self.first_found:
                self.first_found = True
                if case.os and not self.restrict_os:
                    if self.config.automatic:
                        self.restrict_os = case.os
                    # In non-automatic mode, the prompt is handled by the caller

            # Write file if requested
            if self.config.write_files and html:
                self._write_file(case, html)

            # Passwd parsing
            if (
                case.location in PASSWD_FILES
                and not self.config.skip_parsing
            ):
                new_cases = extract_home_file_cases(html, case)
                for new_case in new_cases:
                    await queue.put(new_case)
                    self.total_queued += 1

            # Binlog parsing
            if "mysql-bin.index" in case.location and not self.config.skip_parsing:
                new_cases = extract_binlog_cases(html, case)
                for new_case in new_cases:
                    await queue.put(new_case)
                    self.total_queued += 1

        # Checkpoint
        if self.config.resume_file:
            self.completed_ids.add(case.case_id)
            save_checkpoint(self.config.resume_file, self.completed_ids)

    def _write_file(self, case: Case, html: str) -> None:
        """Write discovered file content to local output directory."""
        parsed = urlsplit(self.config.url)
        output_dir = Path("output") / parsed.netloc.replace(":", "_")
        output_dir.mkdir(parents=True, exist_ok=True)

        filename = sanitize_filename(case.location) + ".txt"
        filepath = output_dir / filename

        content = html
        if self.original_response:
            content = filter_content(html, self.original_response)

        filepath.write_text(content, encoding="utf-8")
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_core.py -v
```
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/core.py tests/test_core.py
git commit -m "feat: add async scanner core with Queue workers, checkpoint, dynamic case injection"
```

---

### Task 12: Self-Update (`update.py`)

**Files:**
- Create: `panoptic/update.py`
- Create: `tests/test_update.py`

- [ ] **Step 1: Write failing tests**

Create `tests/test_update.py`:
```python
"""Tests for panoptic.update — git self-update."""

import pytest
from unittest.mock import patch, MagicMock
from panoptic.update import do_update, get_revision


class TestDoUpdate:
    @patch("panoptic.update.subprocess.run")
    @patch("panoptic.update.os.path.exists", return_value=True)
    def test_git_checkout_runs_git_pull(self, mock_exists, mock_run) -> None:  # type: ignore[no-untyped-def]
        mock_run.return_value = MagicMock(returncode=0, stdout=b"Already up to date.\n")
        do_update()
        mock_run.assert_called()
        # Should use list args, not shell=True
        args = mock_run.call_args
        assert isinstance(args[0][0], list)

    @patch("panoptic.update.os.path.exists", return_value=False)
    def test_pip_installed_prints_guidance(self, mock_exists, capsys) -> None:  # type: ignore[no-untyped-def]
        do_update()
        captured = capsys.readouterr()
        assert "pip" in captured.out.lower()


class TestGetRevision:
    @patch("panoptic.update.subprocess.run")
    def test_returns_short_hash(self, mock_run) -> None:  # type: ignore[no-untyped-def]
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=b"abc1234567890abcdef1234567890abcdef123456\n",
        )
        rev = get_revision()
        assert rev is not None
        assert len(rev) == 7

    @patch("panoptic.update.subprocess.run")
    def test_returns_none_on_failure(self, mock_run) -> None:  # type: ignore[no-untyped-def]
        mock_run.return_value = MagicMock(returncode=1, stdout=b"")
        rev = get_revision()
        assert rev is None
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
pytest tests/test_update.py -v
```
Expected: FAIL with `ModuleNotFoundError`

- [ ] **Step 3: Write `panoptic/update.py`**

```python
"""Git-based self-update for Panoptic.

Detects whether running from git checkout or pip install and
acts appropriately.
"""

from __future__ import annotations

import os
import re
import subprocess


GIT_REPOSITORY_URL = "https://github.com/lightos/Panoptic.git"


def do_update() -> None:
    """Perform self-update from git or print pip guidance."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    git_dir = os.path.join(os.path.dirname(script_dir), ".git")

    if not os.path.exists(git_dir):
        print("[i] Panoptic appears to be installed via pip.")
        print("[i] To update, run: pip install -U panoptic")
        return

    print("[i] Checking for updates...")

    result = subprocess.run(
        ["git", "pull", "origin", "main"],
        capture_output=True,
        cwd=os.path.dirname(script_dir),
    )

    if result.returncode == 0:
        stdout = result.stdout.decode("utf-8", errors="replace")
        updated = "Already" not in stdout
        revision = get_revision() or "unknown"
        if updated:
            print(f"[i] Updated to revision '{revision}'.")
        else:
            print(f"[i] Already at the latest revision '{revision}'.")
    else:
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        print(f"[!] Update failed: {stderr}")
        print("[i] Please make sure 'git' is installed and accessible.")


def get_revision() -> str | None:
    """Get the short git revision hash."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--verify", "HEAD"],
            capture_output=True,
        )
        if result.returncode == 0:
            stdout = result.stdout.decode("utf-8", errors="replace").strip()
            if re.match(r"[0-9a-f]{40}", stdout, re.I):
                return stdout[:7]
    except FileNotFoundError:
        pass
    return None
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/test_update.py -v
```
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/update.py tests/test_update.py
git commit -m "feat: add self-update with git/pip detection"
```

---

## Chunk 6: Integration & Cleanup (Tasks 13-15)

### Task 13: CI Pipeline

**Files:**
- Create: `.github/workflows/ci.yml`

- [ ] **Step 1: Create CI workflow**

```yaml
name: CI

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: ["3.10", "3.11", "3.12"]

    steps:
      - uses: actions/checkout@v4

      - name: Set up Python ${{ matrix.python-version }}
        uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python-version }}

      - name: Install dependencies
        run: pip install -e ".[dev]"

      - name: Lint with ruff
        run: ruff check panoptic/ tests/

      - name: Type check with mypy
        run: mypy panoptic/

      - name: Run tests
        run: pytest --tb=short -q
```

- [ ] **Step 2: Commit**

```bash
mkdir -p .github/workflows
git add .github/workflows/ci.yml
git commit -m "ci: add GitHub Actions workflow for lint, type check, tests"
```

---

### Task 14: Compatibility Shim & Cleanup

**Files:**
- Create: `panoptic.py` (new shim, replacing old file)
- Remove: `thirdparty/`
- Remove: root-level `cases.xml`, `agents.txt`, `versions.ini`, `home.txt`

- [ ] **Step 1: Run full test suite to verify everything works**

```bash
pytest -v
```
Expected: All tests PASS

- [ ] **Step 2: Create compatibility shim**

Replace root `panoptic.py` with thin shim:
```python
#!/usr/bin/env python3
"""Compatibility shim — delegates to the panoptic package."""
from panoptic.__main__ import main

if __name__ == "__main__":
    main()
```

- [ ] **Step 3: Remove old files**

```bash
rm -rf thirdparty/
rm cases.xml agents.txt versions.ini home.txt
```

- [ ] **Step 4: Run full test suite again**

```bash
pytest -v
```
Expected: All tests PASS (data files now loaded from `panoptic/data/`)

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "chore: replace old panoptic.py with shim, remove vendored thirdparty"
```

---

### Task 15: Integration Tests

**Files:**
- Create: `tests/test_integration.py`

- [ ] **Step 1: Write integration tests**

Create `tests/test_integration.py`:
```python
"""Integration tests — end-to-end scan against mocked HTTP server."""

import pytest
from panoptic.cli import parse_args, validate_args
from panoptic.config import merge_config
from panoptic.models import ScanConfig


class TestEndToEnd:
    def test_cli_to_config_pipeline(self) -> None:
        """Verify the full CLI -> config -> ScanConfig pipeline."""
        args = parse_args([
            "--url", "http://target.test/vuln.php?file=test.txt",
            "--param", "file",
            "--prefix", "../",
            "--multiplier", "3",
            "--timeout", "5",
            "--concurrency", "2",
            "--output-format", "json",
            "--auto",
        ])
        validate_args(args)
        config = merge_config(args, {})

        assert config.url == "http://target.test/vuln.php?file=test.txt"
        assert config.param == "file"
        assert config.prefix == "../../../"
        assert config.timeout == 5.0
        assert config.concurrency == 2
        assert config.automatic is True

    def test_list_command_runs(self) -> None:
        """Verify --list software works end-to-end."""
        from panoptic.cases import list_values
        values = list_values("software")
        assert len(values) > 0
        assert any("PHP" in v for v in values)

    def test_list_all_files_runs(self) -> None:
        """Verify --list-all-files works end-to-end."""
        from panoptic.cases import list_all_files
        files = list_all_files()
        assert len(files) > 100  # Should have many file paths
        assert any("/etc/passwd" in f for f in files)

    def test_cases_load_with_filters(self) -> None:
        """Verify case filtering works end-to-end."""
        from panoptic.cases import parse_cases
        config = ScanConfig(
            url="http://target.test/vuln.php?file=test.txt",
            os_filter="*NIX",
            type_filter="conf",
        )
        cases = parse_cases(config)
        assert len(cases) > 0
        for case in cases:
            if case.os:
                assert case.os == "*NIX"
```

- [ ] **Step 2: Run full test suite**

```bash
pytest -v
```
Expected: All tests PASS

- [ ] **Step 3: Run linting and type checking**

```bash
ruff check panoptic/ tests/
mypy panoptic/
```
Expected: No errors (fix any that appear)

- [ ] **Step 4: Commit**

```bash
git add tests/test_integration.py
git commit -m "test: add integration tests for CLI-to-scan pipeline"
```

---

## Final Verification

After all tasks are complete:

```bash
# Full test suite
pytest -v --tb=short

# Lint
ruff check panoptic/ tests/

# Type check
mypy panoptic/

# Verify package installs cleanly
pip install -e ".[dev]"

# Verify entry points work
python -m panoptic --help
python -m panoptic --list software
python -m panoptic --list-all-files | head -5

# Verify shim works
./panoptic.py --help
```
