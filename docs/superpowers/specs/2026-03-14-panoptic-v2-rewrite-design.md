# Panoptic v2.0 Rewrite Design Spec

## Overview

Complete rewrite of Panoptic from a monolithic single-file script into a modern Python package. Fixes all critical bugs identified in the codebase audit, adds missing features expected of a professional security tool, and establishes a proper testing/CI foundation.

**Approach:** Clean rewrite into new package structure, porting logic function-by-function from the original `panoptic.py`. Old file stays as reference until new version passes all tests.

## Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Architecture | Python package (`panoptic/`) | Testable, maintainable, pip-installable |
| Python version | 3.10+ | Best asyncio support, match/case, union types |
| HTTP client | `httpx` (async) | Native async, SOCKS support, HTTP/2, granular timeouts |
| Concurrency | `asyncio` with `Queue` + worker pool | No threads, no locks, no race conditions by design. Queue enables dynamic case injection. |
| Terminal UX | `rich` | Progress bars, colors, tables, cross-platform |
| Output formats | Text + JSON + CSV | Pipeline integration via `--output-format` |
| Config | TOML file (`~/.config/panoptic/config.toml`) | Persistent defaults, CLI overrides |
| Testing | pytest + CI (GitHub Actions) | Python 3.10/3.11/3.12 matrix, ruff, mypy |
| SOCKS proxy | `httpx[socks]` | Eliminates vendored `thirdparty/socks` |

## Critical Bugs Being Fixed

1. **`re.sub` passes `re.I` as `count` arg** (line 488) — heuristic comparison broken for every scan
2. **`kb.invalid_response` can be `None`** (line 535) — `AttributeError` crash on network errors
3. **`args.prefix` mutated in threaded hot path** (lines 508-509) — race condition
4. **SOCKS `connect()` never establishes TCP** (socks.py:418-426) — proxy support completely broken
5. **`ROTATOR_CHARS` reassigned outside lock** (lines 524-527) — thread data race
6. **No HTTP timeout** (line 1049) — hung threads block forever
7. **Regex injection via `--param`/`--ext-param`** (lines 433,445,448) — no `re.escape()`
8. **Header injection** (line 1046) — split on `=` not `:`, no CRLF validation
9. **SSRF via unrestricted URL scheme** (lines 734-735) — `file://`, `ftp://` pass through
10. **`shell=True` in subprocess** (lines 329,361,369) — command injection risk
11. **Bare `except:`** (line 1021) — swallows `SystemExit`/`KeyboardInterrupt`
12. **Multiple race conditions** (lines 614-615, 627-629, 574-576) — globals without locks

All of these are eliminated by the new architecture: asyncio removes threading bugs, `httpx` handles timeouts/connections properly, dataclasses replace mutable globals, and all input is validated.

## Package Structure

```
panoptic/
  __init__.py          # Version, package metadata
  __main__.py          # Entry point: python -m panoptic
  cli.py               # Argument parsing (argparse + rich), config file loading
  config.py            # ScanConfig dataclass, TOML loading, CLI-config merge
  core.py              # Scanner orchestrator: async Queue + worker pool, progress
  cases.py             # XML case parser, filtering, version expansion, custom list loading
  network.py           # httpx async client: retry, timeout, proxy, header validation
  heuristic.py         # Response comparison: cleaning, difflib matching, threshold logic
  output.py            # Formatters: text (rich), JSON, CSV. Result serialization.
  models.py            # Shared dataclasses: Case, ScanResult, ScanConfig, enums
  parsers.py           # Post-discovery: passwd user extraction, mysql binlog extraction
  update.py            # Git self-update (subprocess list args, no shell=True)
  utils.py             # URL validation, scheme checks, revision, filename sanitization
  data/                # Static data files (moved from repo root)
    cases.xml
    agents.txt
    versions.ini
    home.txt
tests/
  conftest.py          # Shared fixtures: mock HTTP server, sample cases, tmp dirs
  test_cases.py        # Case parsing, filtering, version expansion
  test_heuristic.py    # Response cleaning, comparison, re.sub correctness
  test_network.py      # HTTP client with mocked responses
  test_cli.py          # Argument parsing, config merge, validation
  test_output.py       # JSON/CSV/text formatter correctness
  test_parsers.py      # passwd/binlog extraction
  test_integration.py  # End-to-end scans against local test server
pyproject.toml         # Package config, deps, console script, tool config
.github/
  workflows/
    ci.yml             # pytest + ruff + mypy on 3.10/3.11/3.12
```

## Data Models (`models.py`)

```python
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

class FileType(Enum):
    CONF = "conf"
    LOG = "log"
    OTHER = "other"

class OutputFormat(Enum):
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
        """Deterministic identifier for resume/checkpoint (not Python hash, which is randomized per-process)."""
        import hashlib
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

## Network Layer (`network.py`)

Async HTTP client wrapping `httpx`:

- Concurrency controlled via worker pool consuming from `asyncio.Queue` (same semaphore-like limit, but supports dynamic case injection)
- `httpx.AsyncHTTPTransport(retries=N)` for transport-level retry
- `httpx.Timeout(config.timeout, connect=5.0)` for granular timeouts
- `httpx[socks]` for native SOCKS4/5 proxy support — eliminates vendored socks module
- `follow_redirects=False` — critical for LFI; redirects mask findings
- Context manager ensures client cleanup (fixes socket leaks)
- CRLF validation on all headers before setting (fixes header injection)
- Header parsing uses `Name: Value` format (standard HTTP), not `Name=Value`
- URL scheme validation: only `http://` and `https://` accepted (fixes SSRF)
- Client created with `trust_env=not config.ignore_proxy` (proper `--ignore-proxy` support)

## Scanner Core (`core.py`)

The main scan orchestrator:

```
async scan(config, cases, client):
    1. Fetch original response (baseline)
    2. Fetch invalid response (with random filename)
    3. Guard: if either is None, abort with clear error
    4. Load all initial cases into asyncio.Queue
    5. Spawn N worker tasks (N = config.concurrency):
       Each worker loops:
       a. Dequeue a case from the queue
       b. Check OS restriction — if restricted and case.os doesn't match, skip
       c. Build payload (prefix + location + postfix), applying re.escape(config.param) at regex site only
       d. If bad_string set and present in response, skip (not found)
       e. If response Content-Length exceeds threshold and write_files is false, mark found by status alone
       f. Fetch via client
       g. Compare with heuristic
       h. If found: record ScanResult, trigger OS restriction prompt if first find
       i. If passwd found + not skip_parsing: extract users, enqueue new home file cases
       j. If mysql-bin.index found: extract binlogs, enqueue new cases
       k. Report progress via rich progress bar
       l. If delay configured, await asyncio.sleep(delay)
       m. Save case to checkpoint if resume_file configured
    6. Workers exit when queue is empty
    7. Output results via selected formatter
```

Key improvements over original:

- No mutable global state — `ScanConfig` passed explicitly
- No race conditions — single async event loop, no shared mutable state
- `asyncio.Queue` enables dynamic case injection (passwd users, binlog files) without pre-committing all work
- OS restriction checked per-case inside workers, not via shared global flag
- Progress bar shows `[current/total]` with ETA instead of useless spinner
- `bad_string` filtering and large-response size threshold integrated into scan flow

## Heuristic Engine (`heuristic.py`)

Extracted and fixed:

- `clean_response(response, filepath)` — the `re.sub` call fixed: `flags=re.I` instead of positional arg
- `is_match(html, invalid_response, ratio)` — wraps `difflib.SequenceMatcher.quick_ratio()`
- `filter_content(html, original_response)` — matching block extraction for `--write-files`
- All functions are pure (no side effects, no globals) — trivially testable

## Case Parser (`cases.py`)

Ported from `get_cases()` with improvements:

- Uses `defusedxml.ElementTree` instead of stdlib `ET` (XML bomb protection)
- Returns `list[Case]` (frozen dataclasses, not mutable AttribDicts)
- Filtering logic unchanged but cleaner: build filtered list, don't mutate tree in-place
- Version expansion from `versions.ini` integrated
- Token expansion for `{HOST}` and any future `{...}` placeholders, using the same replacement dictionary pattern as the original (extracts netloc from target URL)
- `load_custom_list(path)` validates file exists and is regular file before reading
- Data files loaded via `importlib.resources.files("panoptic.data")` for compatibility with installed packages (zip archives, wheels)

## Output Layer (`output.py`)

Three formatters behind a common interface:

- **TextFormatter** — uses `rich.console.Console` for colored `[+]`/`[!]`/`[i]` output, rich tables for summary
- **JsonFormatter** — writes `list[ScanResult]` as JSON array, one object per finding
- **CsvFormatter** — writes CSV with headers: `timestamp,url,location,os,category,software,type,status_code,content_length`

All write to stdout by default, or to `--output-file` path. Console progress/status always goes to stderr when output is redirected to file.

## CLI (`cli.py`)

Argparse with `rich_argparse.RichHelpFormatter` for styled help output:

- All existing flags preserved for backwards compatibility
- New flags: `--timeout`, `--retries`, `--delay`, `--random-delay`, `--output-format`, `--output-file`, `--concurrency` (replaces `--threads`), `--resume-file`, `--config`
- `--threads` kept as deprecated alias for `--concurrency`
- Validation: URL scheme check, header CRLF check — all before scan starts
- `re.escape()` for `--param`/`--ext-param` applied only at regex construction site (in core.py/network.py), NOT during CLI validation — raw param names stored in ScanConfig to preserve URL construction
- Non-scan commands: `--list` and `--list-all-files` call `cases.py` and exit before scanning. `--log-file` handled in `output.py` as a tee to file alongside normal output

## Configuration (`config.py`)

TOML config at `~/.config/panoptic/config.toml`:

```toml
[defaults]
concurrency = 8
timeout = 10.0
retries = 3
output_format = "text"
verbose = false

[proxy]
url = "socks5://127.0.0.1:9050"

[headers]
user_agent = "Mozilla/5.0 ..."
```

Merge priority: CLI args > config file > built-in defaults. Loaded via `tomli` (Python 3.10) or `tomllib` (3.11+).

## Self-Update (`update.py`)

- Checks for `.git` directory presence before attempting git operations
- If git checkout: `subprocess.run(["git", "pull", "origin", "main"], ...)` — list args, no `shell=True`
- If pip-installed (no `.git`): prints guidance `"Installed via pip. Run: pip install -U panoptic"`
- `subprocess.run(["git", "rev-parse", "--verify", "HEAD"], ...)` — same list-arg pattern
- Clear error messages on failure

## Resume/Checkpoint

- If `--resume-file` specified, completed `case_id` values (deterministic SHA-256, not Python `hash()`) are serialized to JSON after each case
- On restart with same resume file, already-completed cases are skipped by matching `case_id`
- Python's built-in `hash()` is randomized per-process (PEP 456), so we use the `Case.case_id` property which produces stable identifiers across runs

## Dependencies (`pyproject.toml`)

```toml
[project]
name = "panoptic"
version = "2.0.0"
requires-python = ">=3.10"
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

## CI Pipeline (`.github/workflows/ci.yml`)

- Trigger: push + PR to main
- Matrix: Python 3.10, 3.11, 3.12
- Steps: install deps, ruff check, mypy, pytest with coverage
- Coverage report uploaded as artifact

## Migration Path

1. New `panoptic/` package built alongside old `panoptic.py`
2. Data files (`cases.xml`, etc.) moved to `panoptic/data/`
3. Old `panoptic.py`, `thirdparty/`, root data files removed after integration tests pass
4. A thin `panoptic.py` shim kept at repo root for backwards compatibility (`./panoptic.py` invocation):

   ```python
   #!/usr/bin/env python3
   """Compatibility shim — delegates to the panoptic package."""
   from panoptic.__main__ import main
   if __name__ == "__main__":
       main()
   ```

5. `agents.txt`, `versions.ini`, `home.txt`, `cases.xml` content unchanged — only location moves

## What's NOT Changing

- `cases.xml` format and content — the test case library is the tool's core value
- `versions.ini`, `agents.txt`, `home.txt` content
- Core detection algorithm (difflib heuristic comparison)
- CLI flag names for existing features (backwards compatible)
- MIT license

## Compatibility Notes

- **Header format change:** Original used `Name=Value` for `--header`, new uses standard HTTP `Name: Value` format. Accept both during migration with deprecation warning for `=` syntax.
- **Parameter autodetection:** Original auto-detects the vulnerable parameter from URL query string when `--param` is not specified. This behavior is preserved in v2.
- **`--ext-param` validation:** Original validates that the extension parameter exists in the query/POST data. This is preserved in v2.

## Review Findings (2026-03-14)

Plan was reviewed by deep manual analysis + Codex (gpt-5.4). Key architectural fixes applied:

1. **Queue termination:** Sentinel-based worker stop replaced with drain-check pattern to support dynamic case injection from passwd/binlog parsing
2. **Heuristic baseline consistency:** Invalid filename stored and reused (not regenerated per-case)
3. **POST baseline parity:** Baseline fetch uses same HTTP method as scan requests
4. **Resume for dynamic cases:** Checkpoint IDs checked before enqueueing derived cases
5. **Rate limiting:** `--random-delay MIN-MAX` implemented with `random.uniform()` in scan loop
6. **Parameter autodetection:** Ported from original — auto-detects `--param` from URL query string

See implementation plan appendix for full findings table.
