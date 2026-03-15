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

**Fix:**

- Line 281: `r"(?P<param>[^=&]+)=(?P<value>[^=&]+)"` → `r"(?P<param>[^=&]+)=(?P<value>[^&]+)"`
- Line 291: `[^=&]*` → `[^&]*`

**Tests:** Add test with base64 URL like `file=dGVzdC50eHQ=&id=1` to verify param detection works.

### 2. Race condition on `first_found` flag

**File:** `core.py:377`

Multiple async workers can see `first_found == False` simultaneously and all enter the OS-restriction block. The `_pause_lock` only protects the prompt, not the flag check.

**Fix:** Move the `first_found` check-and-set inside the `_pause_lock` acquisition:

```python
async with self._pause_lock:
    if not self.first_found:
        self.first_found = True
        # ... prompt or auto-restrict logic
```

This ensures only one worker ever enters the first-found block. Other workers that were already past the `is_match` check will see `first_found == True` when they acquire the lock.

### 3. Checkpoint write storm

**File:** `core.py:432-440`

`_mark_completed` writes the full checkpoint JSON for every single case. With 1024+ cases, this creates 1024 file writes (each serializing an ever-growing set).

**Fix:** Track a dirty flag and last-write timestamp, protected by a dedicated async lock. Only write when:

- At least 5 seconds have passed since last write, OR
- Scan is complete (final flush in `_run_scan` after queue.join)

```python
self._checkpoint_dirty = False
self._last_checkpoint_time = 0.0
self._checkpoint_lock = asyncio.Lock()

async def _mark_completed(self, case: Case) -> None:
    self.completed_ids.add(case.case_id)
    if self.config.resume_file:
        self._checkpoint_dirty = True
        now = time.monotonic()
        if now - self._last_checkpoint_time >= 5.0:
            async with self._checkpoint_lock:
                # Re-check after acquiring lock (another worker may have flushed)
                if now - self._last_checkpoint_time >= 5.0:
                    await self._flush_checkpoint()

async def _flush_checkpoint(self) -> None:
    if self._checkpoint_dirty and self.config.resume_file:
        await asyncio.to_thread(save_checkpoint, self.config.resume_file, self.completed_ids.copy())
        self._checkpoint_dirty = False
        self._last_checkpoint_time = time.monotonic()
```

Call `_flush_checkpoint()` in a `try/finally` after `queue.join()` to ensure final state is saved even on Ctrl+C / cancellation:

```python
try:
    await queue.join()
finally:
    await self._flush_checkpoint()
    for task in worker_tasks:
        task.cancel()
```

Also make checkpoint writes atomic: write to a temp file, then `os.replace()` to the target path. This prevents corruption if the process is killed mid-write.

### 3b. Parameter replacement corrupts unrelated params

**File:** `core.py:88,92,98` (Codex finding)

The regex `re.sub(rf"(?P<param>{re.escape(config.param)})=...")` matches `id=` as a substring inside `userid=`. For URL `userid=1&id=2` with `--param id`, both parameters get replaced. The same bug affects `ext_param` substitution at line 92.

**Fix:** Add `(?:^|(?<=&))` anchor before the param name at all three regex sites in `build_payload()`:

```python
# Line 88 (ext_param — param part):
rf"(?:^|(?<=&)){re.escape(config.param)}=(?P<value>[^&]*)"
# Line 92 (ext_param — ext part):
rf"(?:^|(?<=&)){re.escape(config.ext_param)}=(?P<value>[^&]*)"
# Line 98 (normal param):
rf"(?:^|(?<=&)){re.escape(config.param)}=(?P<value>[^&]*)"
```

**Tests:** Add test with `userid=1&id=2` to verify only `id` is replaced. Add test with `content_type=html&type=txt` for ext_param.

### 3c. Payloads not URL-encoded for GET requests

**File:** `core.py:62,104`, `network.py:87` (Codex finding)

After base64 encoding or slash replacement, payloads can contain `+`, `=`, `&` and other reserved chars that aren't URL-encoded. GET URLs are constructed by string concatenation, not `urllib.parse.urlencode`. POST bodies sent as `application/x-www-form-urlencoded` are also raw strings.

**Fix:** For GET mode, URL-encode the payload value when substituting into the query string. For POST, encode the value within the form body. For FUZZ mode, leave encoding to the user (they control the template).

This is a targeted fix in `build_payload()` — after regex substitution, URL-encode the replaced value.

**Important:** Use `urllib.parse.quote(value, safe='=+/')` rather than full encoding. Many targets (e.g. PHP's `$_GET`) handle raw base64 natively — encoding `=` and `+` would break compatibility. Only encode chars that corrupt the query string structure: `&`, `#`, space. The exact `safe` set should be documented as a design decision.

### 3d. JSON/CSV output leaks credentials in URLs

**File:** `output.py:42` (Codex finding)

`ScanResult.url` is written raw to JSON/CSV output. If the original URL contains auth tokens in query params, they're preserved in reports. The banner already uses `redact_url()` but structured output doesn't.

**Fix:** Apply `redact_url()` in `_result_to_dict()`:

```python
"url": redact_url(r.url),
```

**Note:** This is a behavioral change for JSON/CSV consumers. If downstream tools re-parse the URL field for retesting, redacted URLs will break them. Document this as a breaking change in output format.

### 3e. Dead code: `except httpx.HTTPStatusError`

**File:** `network.py:99`

`httpx.HTTPStatusError` is only raised when `response.raise_for_status()` is called, which we never do. This except branch is dead code.

**Fix:** Remove the `except httpx.HTTPStatusError` branch.

### 3f. `--write-files` filename collisions

**File:** `core.py:460`, `utils.py:57` (Codex finding)

`sanitize_filename()` can produce collisions when traversal markers differ. The `while ".." in sanitized` stripping combined with `lstrip("._")` means `../../etc/passwd` and `../../../etc/passwd` both become `etc_passwd`. Note: the originally cited example (`/etc/php/php.ini` vs `/usr/lib/php/php.ini`) does NOT collide — they produce `etc_php_php.ini` vs `usr_lib_php_php.ini`.

**Fix:** Add collision detection in `_write_file()`. If the target path already exists, append a deterministic suffix (short hash of `case.case_id`) to disambiguate:

```python
filename = sanitize_filename(case.location) + ".txt"
filepath = output_dir / filename
if filepath.exists():
    filepath = output_dir / f"{filepath.stem}_{case.case_id[:8]}.txt"
```

**Tests:** Add test with paths that collide after sanitization (e.g., `../../etc/passwd` and `../../../etc/passwd`).

---

## UX Improvements

### 4. Remove redundant semaphore

**File:** `network.py:29,85`

The `NetworkClient` creates `asyncio.Semaphore(config.concurrency)` and wraps every fetch in `async with self._semaphore`. But the scanner already creates exactly `config.concurrency` workers, each doing one fetch at a time. The semaphore never actually blocks.

**Fix:** Remove `self._semaphore` from `__init__` and the `async with self._semaphore` wrapper from `fetch()`.

### 5. Add elapsed time and ETA to progress bar

**File:** `core.py:229-234`

Current progress bar: `⠋ Scanning ━━━━ 500/1024`
Desired: `⠋ Scanning ━━━━ 500/1024  0:00:12  0:00:15`

**Fix:** Add `TimeElapsedColumn` and `TimeRemainingColumn` to the Progress bar. Also add scan duration and requests/sec to the summary.

```python
from rich.progress import TimeElapsedColumn, TimeRemainingColumn

with Progress(
    SpinnerColumn(),
    TextColumn("[progress.description]{task.description}"),
    BarColumn(),
    MofNCompleteColumn(),
    TimeElapsedColumn(),
    TimeRemainingColumn(),
    console=Console(file=stderr_stream, highlight=False),
    transient=True,
) as progress:
```

For summary, track `scan_start = time.monotonic()` and compute duration:

```python
elapsed = time.monotonic() - scan_start
rps = self.total_processed / elapsed if elapsed > 0 else 0
text_out.write_info(f"Scan completed in {elapsed:.1f}s ({rps:.0f} req/s)")
```

### 6. Validate `--random-delay` range

**File:** `cli.py:175`

Currently accepts inverted ranges like `5.0-0.5` and negative values like `-1.0-0.5` without error. Negative delays cause `asyncio.sleep` to raise `ValueError`.

**Fix:** After parsing, validate non-negative and `min < max`:

```python
min_val, max_val = float(parts[0]), float(parts[1])
if min_val < 0 or max_val < 0:
    print("[!] --random-delay values must be non-negative", file=sys.stderr)
    sys.exit(1)
if min_val >= max_val:
    print("[!] --random-delay MIN must be less than MAX", file=sys.stderr)
    sys.exit(1)
```

Also add `random_delay` validation in `ScanConfig.__post_init__` for programmatic construction:

```python
if self.random_delay and (self.random_delay[0] < 0 or self.random_delay[1] < 0):
    raise ValueError("random_delay values must be non-negative")
if self.random_delay and self.random_delay[0] >= self.random_delay[1]:
    raise ValueError("random_delay min must be < max")
```

### 7. Validate `--delay` and `--timeout` are positive

**File:** `models.py:67-71`, `cli.py` (validate_args)

`ScanConfig.__post_init__` validates concurrency and heuristic_ratio but not timeout or delay.

**Fix:** Add to `__post_init__`:

```python
if self.timeout <= 0:
    raise ValueError(f"timeout must be > 0, got {self.timeout}")
if self.delay < 0:
    raise ValueError(f"delay must be >= 0, got {self.delay}")
```

**Important:** Also validate in `validate_args()` to give clean CLI errors. A bare `ValueError` from `__post_init__` during `merge_config()` would show a raw Python traceback. Either:

- (a) Add `if args.get("timeout") is not None and args["timeout"] <= 0:` checks in `validate_args()`, OR
- (b) Wrap the `merge_config()` call in `cli.run()` with `try/except ValueError` that prints a clean message and calls `sys.exit(1)`

Option (a) is preferred for consistency with other CLI validations (concurrency, proxy scheme, etc.).

### 8. `--list` output with header and count

**File:** `cli.py:251-261`

Currently `--list os` dumps bare values. Add a header and count.

**Fix:**

```python
values = list_values(args["list"], config=_config)
print(f"Available {args['list']} values ({len(values)}):")
for val in sorted(values):
    print(f"  {val}")
```

---

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

- Add `quiet: bool = False` to `ScanConfig`
- Add `-q, --quiet` to CLI
- In `TextFormatter`: accept `quiet` param, skip `write_banner`, `write_info`, `write_summary` when quiet
- `write_found` and `write_warning` always print
- When `--quiet` is set, also suppress the progress bar (don't create it)

**Tests:** Verify quiet mode suppresses banner/info/summary but still shows found/warning lines.

### 10. `--match-string` (inverse of `--bad-string`)

Only report findings when a specific string IS present in the response.

**Files:** `cli.py` (add arg), `models.py` (add field), `core.py` (add check)

**Implementation:**

- Add `match_string: str | None = None` to `ScanConfig`
- Add `--match-string` to CLI scan options
- **Critical:** `match_string` must gate ALL positive result paths, not just the heuristic match. The Content-Length fast path (`core.py:339-354`) emits `found=True` and returns before the heuristic block — placing `match_string` only after heuristic would miss these results entirely.

  **Fix:** When `match_string` is set, skip the Content-Length optimization (download the full body):

  ```python
  # Content-Length skip optimization — disabled when match_string requires body inspection
  if (
      not self.config.write_files
      and not self.config.match_string
      and content_length > 0
      and content_length - baseline_length > SKIP_RETRIEVE_THRESHOLD
  ):
      # ... existing fast path ...
  ```

  Then apply `match_string` check after reading the body, before both positive result paths:

  ```python
  html = response.text

  if self.config.bad_string and self.config.bad_string in html:
      await self._mark_completed(case)
      return

  if self.config.match_string and self.config.match_string not in html:
      await self._mark_completed(case)
      return

  # ... heuristic comparison follows ...
  ```

**Tests:** Test with Content-Length-heavy response to verify match_string is still checked.

### 11. Status code filtering (`--match-code`, `--filter-code`)

**Files:** `cli.py` (add args + parsing), `models.py` (add fields), `core.py` (add filtering)

**Implementation:**

- Add `match_codes: list[int] | None = None` and `filter_codes: list[int] | None = None` to `ScanConfig`
- Add `--match-code` (comma-separated, e.g. `200,301`) and `--filter-code` to CLI

- **CLI parsing** — parse comma-separated string to `list[int]` in `parse_args()`:

  ```python
  if result.get("match_codes") and isinstance(result["match_codes"], str):
      try:
          codes = [int(c.strip()) for c in result["match_codes"].split(",")]
          for code in codes:
              if not 100 <= code <= 599:
                  raise ValueError(f"Invalid HTTP status code: {code}")
          result["match_codes"] = codes
      except ValueError as e:
          print(f"[!] Invalid --match-code: {e}", file=sys.stderr)
          sys.exit(1)
  ```

  Same parsing for `--filter-code`.

- **Config merge** — normalize TOML-provided values (could be list of ints or comma-separated string) in `merge_config()`.

- In `_process_case`, after getting response (before Content-Length optimization):

  ```python
  if self.config.filter_codes and response.status_code in self.config.filter_codes:
      await self._mark_completed(case)
      return
  if self.config.match_codes and response.status_code not in self.config.match_codes:
      await self._mark_completed(case)
      return
  ```

**Tests:** Valid codes, invalid codes (0, 600, "abc"), empty string, single code, multiple codes.

### 12. `--follow-redirects` flag

**Files:** `cli.py` (add arg), `models.py` (add field), `network.py` (use flag)

**Implementation:**

- Add `follow_redirects: bool = False` to `ScanConfig`
- Add `--follow-redirects` to CLI
- In `NetworkClient.__aenter__`, use `follow_redirects=self.config.follow_redirects`

### 13. Multiple `--header` support

**Files:** `cli.py` (change to `action="append"` + update validation), `models.py` (change type), `network.py` (iterate), `core.py` (update FUZZ logic), `config.py` (normalize merge)

**Implementation:**

- Change `header: str | None` to `headers: list[str] | None = None` in `ScanConfig`
- CLI: `--header` with `action="append"` (allows multiple)
- `_build_headers` iterates over all headers
- `_fuzz_headers` checks each header for FUZZ marker
- Backward compatible: single header still works

**Migration plan** (required — renaming `header` → `headers` breaks 6 callsites):

1. **`cli.py:214-219`** (`validate_args`) — update to iterate `args.get("headers", [])` for CRLF validation
2. **`cli.py:277`** (`has_fuzz` check) — update to `any("FUZZ" in h for h in (config.headers or []))`
3. **`core.py:412`** (`_fuzz_headers`) — iterate `self.config.headers`, return merged dict with all FUZZ-substituted headers
4. **`network.py:124`** (`_build_headers`) — iterate `self.config.headers` instead of single `self.config.header`
5. **`config.py`** (`merge_config`) — accept both `header` (string, from old TOML) and `headers` (list) and normalize to `list[str]`
6. **All tests** using `ScanConfig(header=...)` → `ScanConfig(headers=[...])`

**Cookie conflict:** If user passes both `--cookie "sid=abc"` and `--header "Cookie: extra=1"`, Cookie entries conflict. Detect and warn, or merge Cookie values.

### 14. `--output-format` for `--list` commands

**File:** `cli.py:244-261`

**Implementation:**

- Check `output_format` in both the `--list` handler AND `--list-all-files` handler for consistency
- JSON: `json.dumps(sorted(values), indent=2)`
- CSV: one column with header
- Text: current behavior (with header/count from item 8)

### 15. `--list` count display

Already covered by item 8 above.

---

## Files Changed Summary

| File | Changes |
|------|---------|
| `cli.py` | Fix regex (1), add args (9-14), validate delay/timeout (6,7), parse match/filter codes (11), validate headers (13), list header (8,14) |
| `core.py` | Fix race (2), throttle checkpoint with lock (3), fix param anchoring (3b), progress bar (5), match-string gate (10), status codes (11) |
| `models.py` | Add fields (7,9,10,11,12,13), validate timeout/delay/random_delay (6,7) |
| `network.py` | Remove semaphore (4), follow-redirects (12), multi-header (13) |
| `output.py` | Quiet mode (9), redact URLs (3d) |
| `config.py` | Merge new fields from TOML, normalize header/headers (13), normalize code lists (11) |
| `utils.py` | Collision-safe filenames (3f) |
| `tests/` | Tests for each fix/feature (see targeted list below) |
| `CLAUDE.md` | Document new flags |

---

## Testing Strategy

- Each bug fix gets a regression test
- Each new feature gets positive + negative tests
- E2E verification against the Docker LFI test app for the full scan flow
- All existing 123 tests must continue to pass

### Targeted test cases for high-risk changes

| Area | Test |
|------|------|
| Race condition (2) | Concurrent workers with `first_found` — verify only one OS-restriction prompt |
| Checkpoint (3) | Verify throttled writes, atomic file replacement, flush-on-cancel |
| Param anchoring (3b) | `userid=1&id=2` with `--param id` — only `id` replaced |
| Param anchoring (3b) | `content_type=html&type=txt` with `--ext-param type` — only `type` replaced |
| match-string (10) | Response with large Content-Length + `--match-string` — verify body is checked |
| match-code (11) | Parsing: valid codes, invalid codes (0, 600, "abc"), empty string |
| Multiple headers (13) | FUZZ in different header positions, Cookie conflict detection |
| Quiet mode (9) | Verify banner/info/summary suppressed, found/warning shown |
| Filename collisions (3f) | Paths differing only in traversal depth produce distinct output files |
| List formatting (14) | JSON/CSV output for `--list` and `--list-all-files` |
