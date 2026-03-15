# Panoptic v2

LFI (Local File Inclusion) scanner. Probes URLs for path traversal vulnerabilities
using a database of known file paths (cases.xml).

## Commands

```bash
pip install -e ".[dev]"          # Install with dev deps
python3 -m pytest tests/ -x -q   # Run tests (112 tests, <1s)
python3 -m mypy panoptic/        # Type check (strict mode)
python3 -m ruff check panoptic/  # Lint
python3 -m panoptic --help       # CLI usage
```

## Architecture

```
panoptic/
  cli.py       → Argument parsing, validation, dispatch
  config.py    → TOML config loading, CLI/config merge (CLI > file > defaults)
  core.py      → Scanner: async queue + worker pool, build_payload(), FUZZ marker
  models.py    → ScanConfig (frozen dataclass), Case, ScanResult, enums
  network.py   → httpx async client with retry, proxy, SSL, concurrency control
  heuristic.py → Response comparison (difflib SequenceMatcher), clean_response()
  output.py    → Text/JSON/CSV formatters, TeeWriter for log files
  cases.py     → XML case parser with filtering (os/software/category/type)
  parsers.py   → Dynamic case extraction (passwd → home dirs, binlog index)
  utils.py     → URL normalization, header validation, redact_url
  update.py    → Git-based self-update with remote URL verification
  data/        → cases.xml, agents.txt, home.txt, versions.ini
```

## Code Quality

- **DRY** — Extract repeated logic into helpers (e.g. `process_path()`, `_fetch()`).
  Don't duplicate transformation chains or request patterns.
- **KISS** — Prefer simple string operations and stdlib over abstractions. No ORMs,
  no plugin systems, no class hierarchies deeper than one level.
- **YAGNI** — Don't add flags, config options, or encoding modes until there's a
  real test case. Every feature must have a working integration test.
- **SRP** — Each module has one job (see Architecture). Don't put network logic in
  core.py or CLI logic in config.py.
- **Type safety** — `mypy --strict` must pass. Use `from __future__ import annotations`
  in every module. Frozen dataclasses for immutable data (ScanConfig, Case).
- **Security first** — Validate all user input at CLI boundary (CRLF injection,
  URL schemes, proxy schemes). Use `defusedxml` for XML. Verify git remote before
  self-update. Redact credentials from output.

## Key Patterns

- **ScanConfig is frozen** — use `config.replace(field=value)` to create modified copies
- **FUZZ marker** — `FUZZ` in `--data` or `--header` values enables arbitrary injection
  point placement (cookies, JSON bodies, custom headers). Overrides `--param` regex.
- **build_payload()** constructs URLs/data per-case. `process_path()` applies
  prefix/postfix/replace_slash/base64 transformations.
- **Heuristic matching** — responses compared against invalid-file baseline via
  difflib ratio. `clean_response()` strips filepath from both before comparison.
- **Status code filtering** — 4xx/5xx responses with different status class than
  baseline are skipped (prevents false positives from web server error pages).
- **asyncio.to_thread** for checkpoint writes to avoid blocking the event loop.

## Gotchas

- `[^&]*` not `[^=&]*` in param regex — values can contain `=` (base64 padding)
- Tests use `pytest-httpx` for mocking; `asyncio_mode = "auto"` in pyproject.toml
- `tomli` is a fallback for Python <3.11 (3.11+ has `tomllib` in stdlib)
- The original `panoptic.py` monolith is kept but excluded from mypy via pyproject.toml
- `defusedxml` is used for XML parsing (security)
