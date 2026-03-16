# Panoptic v2

LFI (Local File Inclusion) scanner. Probes URLs for path traversal vulnerabilities
using a database of known file paths (cases.csv).

## Commands

```bash
pip install -e ".[dev]"          # Install with dev deps
python3 -m pytest tests/ -x -q   # Run tests (<1s)
python3 -m mypy panoptic/        # Type check (strict mode)
python3 -m ruff check panoptic/  # Lint
python3 -m panoptic --help       # CLI usage
```

## Architecture

```text
panoptic/
  cli.py       → Argument parsing, validation, dispatch
  config.py    → TOML config loading, CLI/config merge (CLI > file > defaults)
  core.py      → Scanner: async queue + worker pool, build_payload(), FUZZ marker
  models.py    → ScanConfig (frozen dataclass), Case, ScanResult, enums
  network.py   → httpx async client with retry, proxy, SSL
  heuristic.py → Response comparison (difflib SequenceMatcher), clean_response()
  output.py    → Text/JSON/CSV formatters, TeeWriter for log files
  cases.py     → CSV case parser with validation and filtering (os/software/category/type)
  parsers.py   → Dynamic case extraction (passwd → home dirs, binlog index)
  utils.py     → URL normalization, header validation, redact_url
  update.py    → Git-based self-update with remote URL verification
  data/        → cases.csv, agents.txt, home.txt, versions.ini
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
  URL schemes, proxy schemes). Verify git remote before
  self-update. Redact credentials from output.

## Key Patterns

- **ScanConfig is frozen** — use `config.replace(field=value)` to create modified copies
- **FUZZ marker** — `FUZZ` in `--data` or `--header` values enables arbitrary injection
  point placement (cookies, JSON bodies, custom headers). Overrides `--param` regex.
- **build_payload()** constructs URLs/data per-case. `process_path()` applies
  prefix/postfix/replace_slash/base64 transformations. Payload values are URL-encoded
  for GET (safe: `=+/%`) and POST (safe: `=/%`); FUZZ mode skips encoding.
- **Heuristic matching** — responses compared against invalid-file baseline via
  difflib ratio. `clean_response()` strips filepath from both before comparison.
- **Status code filtering** — 4xx/5xx responses with different status class than
  baseline are skipped (prevents false positives from web server error pages).
  User-specified `--match-code` and `--filter-code` provide additional control.
- **Checkpoint throttling** — checkpoint writes are throttled to 5-second intervals
  with atomic file replacement (temp file + `os.replace`). Final flush on shutdown.
- **Quiet mode** — `--quiet` suppresses banner/info/progress/summary; findings and
  warnings always print.
- **Multiple headers** — `--header` is repeatable (`action="append"`). The field is
  `headers: list[str] | None` in ScanConfig. Config merge normalizes singular
  `header` (old TOML) to plural `headers`.

## Gotchas

- `[^&]*` not `[^=&]*` in param regex — values can contain `=` (base64 padding)
- Param regex uses `(?:^|(?<=&))` anchor to prevent substring matches (e.g. `id` in `userid`)
- Tests use `pytest-httpx` for mocking; `asyncio_mode = "auto"` in pyproject.toml
- `tomli` is a fallback for Python <3.11 (3.11+ has `tomllib` in stdlib)
- The original `panoptic.py` monolith is kept but excluded from mypy via pyproject.toml
- Case database is CSV (`cases.csv`) with validated columns: path, os, software, category, type
- JSON/CSV output applies `redact_url()` — downstream tools parsing the URL field
  will see redacted query params

## E2E Testing

Vulnerable test app at `~/dev/lfi-test-app/lfi-test-app/`. Requires Docker Desktop (WSL2 integration).

```bash
docker.exe compose -f ~/dev/lfi-test-app/lfi-test-app/docker-compose.yml up -d
```

App runs at `http://localhost:8080`. All endpoints should find 56 files with `--prefix "../../../" --os "*NIX" --auto`:

| Endpoint | Command |
|----------|---------|
| GET param | `--url "http://localhost:8080/classic.php?file=test.txt"` |
| Filter bypass | `--url "http://localhost:8080/filtered.php?file=test.txt" --prefix "....//....//....//....//"` |
| POST param | `--url "http://localhost:8080/post.php" --data "file=test.txt"` |
| Base64 | `--url "http://localhost:8080/base64.php?file=dGVzdC50eHQ=" --base64` |
| Cookie FUZZ | `--url "http://localhost:8080/cookie.php" --header "Cookie: lang=FUZZ"` |
| JSON FUZZ | `--url "http://localhost:8080/json_api.php" --data '{"file":"FUZZ"}'` |
| Extension param | `--url "http://localhost:8080/param.php?file=test&type=txt" --param file --ext-param type` |
| Path-based | `--url "http://localhost:8080/pathinfo.php/test.txt" --path-based` |

Note: path-based returned 0 results — may be a test app issue (needs investigation).
