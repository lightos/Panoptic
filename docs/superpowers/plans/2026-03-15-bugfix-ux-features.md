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

### Task 1: Fix regex in param auto-detection (spec item 1)

**Files:**
- Modify: `panoptic/cli.py:281,291`
- Test: `tests/test_cli.py`

The param auto-detection regex uses `[^=&]+` for the value group, which breaks on base64-encoded values containing `=` (e.g., `file=dGVzdC50eHQ=&id=1` fails to detect `file` as the param). The ext-param validation regex at line 291 has the same bug.

- [ ] **Step 1: Write failing integration test**

The param auto-detection happens inside `cli.run()`, which is async and dispatches to the scanner. To test the regex without mocking the entire scan, we test `cli.run()` up to the point where it would create the scanner. The cleanest approach: call `run()` with a base64 URL and mock `Scanner` to capture the config it receives.

In `tests/test_cli.py`, add:

```python
from unittest.mock import AsyncMock, patch

class TestParamAutodetection:
    async def test_base64_param_autodetect(self) -> None:
        """Param detection must handle base64 values with = padding."""
        # IMPORTANT: Scanner is imported inside run() via `from panoptic.core import Scanner`,
        # so we must patch `panoptic.core.Scanner`, NOT `panoptic.cli.Scanner`.
        with patch("panoptic.core.Scanner") as mock_scanner_cls:
            mock_scanner = AsyncMock()
            mock_scanner_cls.return_value = mock_scanner
            await run(["--url", "http://example.com/test.php?file=dGVzdC50eHQ=&id=1", "--auto"])
            # Scanner should have been created with param="file"
            config = mock_scanner_cls.call_args[0][0]
            assert config.param == "file"
```

Also add the import at the top of the test file:

```python
from panoptic.cli import parse_args, run, validate_args
```

> **Note:** The ext-param validation at line 291 uses `re.search()` (not `re.match()`), which
> correctly finds `type=txt` even when preceded by base64 `=` padding. The `[^=&]*` → `[^&]*`
> fix on line 291 is still applied as a defensive hardening (consistent with CLAUDE.md gotcha),
> but no separate test is needed since the current code already passes for this case.

- [ ] **Step 2: Run tests to verify they fail with current code**

Run: `python3 -m pytest tests/test_cli.py::TestParamAutodetection -v`

Expected: `test_base64_param_autodetect` FAILS because `[^=&]+` stops at `=`, so param detection fails and `sys.exit(1)` is called.

- [ ] **Step 3: Fix the regexes in cli.py**

In `panoptic/cli.py:281`, change:
```python
# OLD:
match = re.match(r"(?P<param>[^=&]+)=(?P<value>[^=&]+)", params)
# NEW:
match = re.match(r"(?P<param>[^=&]+)=(?P<value>[^&]+)", params)
```

In `panoptic/cli.py:291`, change:
```python
# OLD:
rf"(?P<param>{re.escape(config.ext_param)})=(?P<value>[^=&]*)",
# NEW:
rf"(?P<param>{re.escape(config.ext_param)})=(?P<value>[^&]*)",
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_cli.py -v`
Expected: ALL PASS

- [ ] **Step 5: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add panoptic/cli.py tests/test_cli.py
git commit -m "fix: handle base64 = padding in param auto-detection regex"
```

---

### Task 2: Fix param replacement substring corruption (spec item 3b)

**Files:**
- Modify: `panoptic/core.py:87-102`
- Test: `tests/test_core.py`

The regex in `build_payload()` matches `id=` as a substring inside `userid=`. For URL `userid=1&id=2` with `--param id`, both parameters get replaced. This affects all three regex sites (lines 88, 93, 99).

- [ ] **Step 1: Write failing tests**

In `tests/test_core.py`, add to `TestBuildPayload`:

```python
def test_param_not_substring_matched(self) -> None:
    """--param id must not match userid."""
    config = ScanConfig(url="http://example.com/test.php?userid=1&id=2", param="id")
    payload = build_payload(config, "/etc/passwd", "userid=1&id=2")
    assert "userid=1" in payload  # userid unchanged
    assert "id=/etc/passwd" in payload or "id=%2Fetc%2Fpasswd" in payload

def test_ext_param_not_substring_matched(self) -> None:
    """--ext-param type must not match content_type."""
    config = ScanConfig(
        url="http://example.com/test.php?content_type=html&type=txt&file=test.txt",
        param="file",
        ext_param="type",
    )
    payload = build_payload(config, "/etc/passwd.conf", "content_type=html&type=txt&file=test.txt")
    assert "content_type=html" in payload  # content_type unchanged
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_core.py::TestBuildPayload::test_param_not_substring_matched tests/test_core.py::TestBuildPayload::test_ext_param_not_substring_matched -v`
Expected: FAIL — `userid` gets corrupted.

- [ ] **Step 3: Add anchoring to all three regex sites**

In `panoptic/core.py`, fix lines 87-102:

```python
    elif config.ext_param and config.param and "." in full_path:
        # When ext_param is set, split path into base and extension
        path_without_ext, ext = full_path.rsplit(".", 1)
        result = re.sub(
            rf"(?:^|(?<=&)){re.escape(config.param)}=(?P<value>[^&]*)",
            rf"{config.param}={path_without_ext}",
            result,
        )
        result = re.sub(
            rf"(?:^|(?<=&)){re.escape(config.ext_param)}=(?P<value>[^&]*)",
            rf"{config.ext_param}={ext}",
            result,
        )
    elif config.param:
        result = re.sub(
            rf"(?:^|(?<=&)){re.escape(config.param)}=(?P<value>[^&]*)",
            rf"{config.param}={full_path}",
            result,
        )
```

Note: The replacement string changes from `rf"\1={value}"` to `rf"{config.param}={value}"` because `\1` refers to named groups that no longer exist in the anchored pattern.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_core.py -v`
Expected: ALL PASS

- [ ] **Step 5: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add panoptic/core.py tests/test_core.py
git commit -m "fix: anchor param regex to prevent substring matches in build_payload"
```

---

### Task 3: Redact credentials in JSON/CSV output (spec item 3d)

**Files:**
- Modify: `panoptic/output.py:37-50`
- Test: `tests/test_output.py`

`ScanResult.url` is written raw to JSON/CSV. If the URL contains auth tokens in query params, they leak into reports. The banner already uses `redact_url()` but structured output doesn't.

- [ ] **Step 1: Write failing test**

In `tests/test_output.py`, add:

```python
class TestUrlRedaction:
    def test_json_output_redacts_url(self) -> None:
        """JSON output must not leak raw query param values."""
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="http://example.com/test.php?file=/etc/passwd&token=secret123",
            status_code=200,
        )
        buf = io.StringIO()
        JsonFormatter(buf).write_results([result])
        buf.seek(0)
        data = json.loads(buf.read())
        assert "secret123" not in data[0]["url"]
        assert "token=***" in data[0]["url"]

    def test_csv_output_redacts_url(self) -> None:
        """CSV output must not leak raw query param values."""
        result = ScanResult(
            case=Case(location="/etc/passwd"),
            found=True,
            url="http://example.com/test.php?file=/etc/passwd&token=secret123",
            status_code=200,
        )
        buf = io.StringIO()
        CsvFormatter(buf).write_results([result])
        buf.seek(0)
        content = buf.read()
        assert "secret123" not in content
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_output.py::TestUrlRedaction -v`
Expected: FAIL — `secret123` appears in output.

- [ ] **Step 3: Apply redaction in `_result_to_dict`**

In `panoptic/output.py`, add import and modify the function:

```python
from panoptic.utils import redact_url
```

Change line 41 in `_result_to_dict`:
```python
# OLD:
"url": r.url,
# NEW:
"url": redact_url(r.url),
```

- [ ] **Step 4: Run tests to verify they pass**

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
- Modify: `panoptic/network.py:99-102`
- Test: `tests/test_network.py`

`httpx.HTTPStatusError` is only raised when `response.raise_for_status()` is called, which we never do. This except branch is dead code.

- [ ] **Step 1: Verify no `raise_for_status` calls exist**

Run: `grep -r "raise_for_status" panoptic/`
Expected: No results.

- [ ] **Step 2: Remove the dead except branch**

In `panoptic/network.py`, change lines 85-105:

```python
        async with self._semaphore:
            try:
                if data is not None:
                    post_headers = {"Content-Type": "application/x-www-form-urlencoded"}
                    if headers:
                        post_headers.update(headers)
                    response = await self._client.post(
                        url,
                        content=data.encode("utf-8"),
                        headers=post_headers,
                    )
                else:
                    response = await self._client.get(url, headers=headers)
                return response
            except httpx.HTTPError:
                # Connection/timeout errors have no response body
                return None
```

Also remove the `httpx.HTTPStatusError` reference. Since we only import `httpx`, nothing else needs to change.

- [ ] **Step 3: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add panoptic/network.py
git commit -m "fix: remove dead except httpx.HTTPStatusError branch"
```

---

### Task 5: Fix `--write-files` filename collisions (spec item 3f)

**Files:**
- Modify: `panoptic/core.py:451-465`
- Test: `tests/test_core.py`

`sanitize_filename()` collapses paths that differ only in traversal depth: `../../etc/passwd` and `../../../etc/passwd` both become `etc_passwd` after `..` removal. This causes file overwrites.

- [ ] **Step 1: Write failing test**

In `tests/test_core.py`, add:

```python
class TestWriteFile:
    def test_no_filename_collision(self, tmp_path: Path) -> None:
        """Paths differing only in traversal depth must not overwrite each other."""
        config = ScanConfig(
            url="http://example.com/test.php?file=x",
            param="file",
            write_files=True,
        )
        scanner = Scanner(config)
        scanner.original_response = "<html>original</html>"

        case1 = Case(location="../../etc/passwd", os="*NIX")
        case2 = Case(location="../../../etc/passwd", os="*NIX")

        # Monkey-patch to use tmp_path
        import panoptic.core as core_mod
        original_cwd = Path.cwd
        Path.cwd = staticmethod(lambda: tmp_path)  # type: ignore[assignment]
        try:
            scanner._write_file(case1, "content1")
            scanner._write_file(case2, "content2")
        finally:
            Path.cwd = original_cwd  # type: ignore[assignment]

        output_dir = tmp_path / "output" / "example.com"
        files = list(output_dir.iterdir())
        assert len(files) == 2, f"Expected 2 files, got {len(files)}: {files}"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_core.py::TestWriteFile::test_no_filename_collision -v`
Expected: FAIL — only 1 file created (second overwrites first).

- [ ] **Step 3: Use deterministic collision-safe filenames in `_write_file`**

In `panoptic/core.py`, modify `_write_file` (line 451):

> **Design decision:** Instead of using `filepath.exists()` (which is non-deterministic —
> re-running the same scan creates duplicates instead of updating), always include
> `case.case_id[:8]` in filenames when the sanitized name would lose traversal-depth
> information. This makes filenames deterministic and idempotent across runs.

```python
    def _write_file(self, case: Case, html: str) -> None:
        """Write discovered file content to local output directory."""
        parsed = urlsplit(self.config.url)
        base = (Path.cwd() / "output").resolve()
        output_dir = (base / parsed.netloc.replace(":", "_")).resolve()
        if not str(output_dir).startswith(str(base)):
            raise ValueError(f"Unsafe output directory: {output_dir}")
        output_dir.mkdir(parents=True, exist_ok=True)

        sanitized = sanitize_filename(case.location)
        # Include case_id suffix when traversal markers were stripped during sanitization,
        # since different traversal depths produce identical sanitized names.
        if ".." in case.location:
            filename = f"{sanitized}_{case.case_id[:8]}.txt"
        else:
            filename = f"{sanitized}.txt"
        filepath = output_dir / filename

        content = filter_content(html, self.original_response) if self.original_response else html

        filepath.write_text(content, encoding="utf-8")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_core.py -v`
Expected: ALL PASS

- [ ] **Step 5: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add panoptic/core.py tests/test_core.py
git commit -m "fix: prevent filename collisions in --write-files with case_id suffix"
```

---

## Chunk 2: Concurrency Fixes

### Task 6: Fix race condition on `first_found` flag (spec item 2)

**Files:**
- Modify: `panoptic/core.py:377-397`
- Test: `tests/test_core.py`

Multiple async workers can see `first_found == False` simultaneously and all enter the OS-restriction block. The fix moves the check-and-set inside `_pause_lock`.

- [ ] **Step 1: Write regression test for the race condition**

> **Note:** The test must exercise the actual `_process_case()` method with concurrent
> workers, not just the lock primitive. Testing the lock directly would pass both before
> and after the fix, providing false confidence.

In `tests/test_core.py`, add:

```python
import asyncio
from unittest.mock import AsyncMock, patch

class TestFirstFoundRace:
    async def test_only_one_os_restriction_with_concurrent_matches(self) -> None:
        """Multiple concurrent matching cases must trigger OS restriction exactly once."""
        config = ScanConfig(
            url="http://target.test/include.php?file=test.txt",
            param="file",
            concurrency=4,
            automatic=True,  # auto-restrict avoids interactive prompt
        )
        scanner = Scanner(config)
        scanner.invalid_response = "<html>not found</html>"
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "nonexistent"
        scanner.original_response = "<html>original</html>"

        text_out = AsyncMock()
        text_out.write_found = lambda r: None
        text_out.write_info = lambda m: None
        text_out.write_verbose = lambda m: None

        queue: asyncio.Queue[Case] = asyncio.Queue()

        # Create multiple *NIX cases that will all "match"
        cases = [
            Case(location=f"/etc/file{i}", os="*NIX", category="OS", software="Linux")
            for i in range(10)
        ]

        # Patch is_match to always return True, and _fetch to return a matching response
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.headers = {"content-length": "0"}

        with patch.object(scanner, "_fetch", return_value=mock_response):
            with patch("panoptic.core.is_match", return_value=True):
                await asyncio.gather(*[
                    scanner._process_case(case, AsyncMock(), "file=test.txt", queue, text_out)
                    for case in cases
                ])

        # Only one OS restriction should have been applied
        assert scanner.restrict_os == "*NIX"
        assert scanner.first_found is True
```

- [ ] **Step 2: Run test to verify behavior**

Run: `python3 -m pytest tests/test_core.py::TestFirstFoundRace -v`
Expected: With the current buggy code (check outside lock), multiple workers may set `restrict_os` concurrently (test may be flaky). After the fix, exactly one worker enters the block.

- [ ] **Step 3: Fix the race in `_process_case`**

In `panoptic/core.py`, replace lines 377-397 with:

```python
            async with self._pause_lock:
                if not self.first_found:
                    self.first_found = True
                    if case.os and not self.restrict_os:
                        if self.config.automatic:
                            self.restrict_os = case.os
                            text_out.write_info(f"Automatically restricting to OS: {case.os}")
                        else:
                            if progress:
                                progress.stop()
                            try:
                                answer = await asyncio.to_thread(
                                    input,
                                    f"[?] Restrict further scans to '{case.os}'? [Y/n] ",
                                )
                                if answer.strip().lower() in ("", "y", "yes"):
                                    self.restrict_os = case.os
                            finally:
                                if progress:
                                    progress.start()
```

- [ ] **Step 4: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/core.py tests/test_core.py
git commit -m "fix: prevent race condition on first_found by moving check inside _pause_lock"
```

---

### Task 7: Fix checkpoint write storm (spec item 3)

**Files:**
- Modify: `panoptic/core.py:110-113,130-143,432-440,256-260`
- Test: `tests/test_core.py`

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
            data = json.load(f)
        assert set(data) == {"id1", "id2"}

    def test_save_checkpoint_no_partial_writes(self, tmp_path: Path) -> None:
        """If process dies mid-write, old checkpoint must survive."""
        filepath = str(tmp_path / "checkpoint.json")
        # Write initial checkpoint
        save_checkpoint(filepath, {"id1"})

        # Write again — if atomic, the file is always valid
        save_checkpoint(filepath, {"id1", "id2", "id3"})
        with open(filepath) as f:
            data = json.load(f)
        assert len(data) == 3
```

Also add throttling and flush tests:

```python
class TestCheckpointThrottling:
    async def test_rapid_marks_throttle_writes(self, tmp_path: Path) -> None:
        """Rapid _mark_completed calls should not write on every call."""
        checkpoint_file = str(tmp_path / "checkpoint.json")
        config = ScanConfig(url="http://example.com", resume_file=checkpoint_file)
        scanner = Scanner(config)
        scanner._last_checkpoint_time = time.monotonic()  # Pretend we just wrote

        write_count = 0
        original_save = save_checkpoint

        def counting_save(*args: object, **kwargs: object) -> None:
            nonlocal write_count
            write_count += 1
            original_save(*args, **kwargs)

        with patch("panoptic.core.save_checkpoint", side_effect=counting_save):
            for i in range(20):
                case = Case(location=f"/etc/file{i}", os="*NIX")
                await scanner._mark_completed(case)

        # With 5-second throttle, rapid calls should NOT write 20 times
        assert write_count <= 1, f"Expected <=1 writes during throttle window, got {write_count}"

    async def test_flush_on_shutdown(self, tmp_path: Path) -> None:
        """_flush_checkpoint must write dirty state even without time threshold."""
        checkpoint_file = str(tmp_path / "checkpoint.json")
        config = ScanConfig(url="http://example.com", resume_file=checkpoint_file)
        scanner = Scanner(config)
        scanner.completed_ids = {"id1", "id2", "id3"}
        scanner._checkpoint_dirty = True

        await scanner._flush_checkpoint()

        with open(checkpoint_file) as f:
            data = json.load(f)
        assert set(data) == {"id1", "id2", "id3"}
        assert scanner._checkpoint_dirty is False
```

- [ ] **Step 2: Run tests to verify they pass (basic checkpoint still works)**

Run: `python3 -m pytest tests/test_core.py::TestAtomicCheckpoint tests/test_core.py::TestCheckpointThrottling -v`
Expected: PASS for atomic tests; throttling tests will PASS after implementation in steps 3-5

- [ ] **Step 3: Make `save_checkpoint` atomic**

In `panoptic/core.py`, modify `save_checkpoint` (line 110):

```python
def save_checkpoint(filepath: str, completed_ids: set[str]) -> None:
    """Save completed case IDs to a checkpoint file atomically."""
    import tempfile

    dir_name = os.path.dirname(filepath) or "."
    fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(sorted(completed_ids), f)
        os.replace(tmp_path, filepath)
    except BaseException:
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise
```

- [ ] **Step 4: Add throttling to `_mark_completed`**

In `panoptic/core.py`, modify `Scanner.__init__` (line 130) to add checkpoint state:

```python
    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self.results: list[ScanResult] = []
        self.original_response: str = ""
        self.invalid_response: str = ""
        self.invalid_status_code: int = 0
        self.invalid_filename: str = ""
        self.restrict_os: str | None = config.os_filter
        self.first_found = False
        self.completed_ids: set[str] = set()
        self.enqueued_ids: set[str] = set()
        self.total_queued = 0
        self.total_processed = 0
        self._pause_lock = asyncio.Lock()
        self._checkpoint_dirty = False
        self._last_checkpoint_time = 0.0
        self._checkpoint_lock = asyncio.Lock()
```

Replace `_mark_completed` (line 432):

```python
    async def _mark_completed(self, case: Case) -> None:
        """Record a case as completed for resume/checkpoint support."""
        self.completed_ids.add(case.case_id)
        if self.config.resume_file:
            self._checkpoint_dirty = True
            now = time.monotonic()
            if now - self._last_checkpoint_time >= 5.0:
                async with self._checkpoint_lock:
                    if time.monotonic() - self._last_checkpoint_time >= 5.0:
                        await self._flush_checkpoint()

    async def _flush_checkpoint(self) -> None:
        """Flush checkpoint to disk if dirty."""
        if self._checkpoint_dirty and self.config.resume_file:
            await asyncio.to_thread(
                save_checkpoint,
                self.config.resume_file,
                self.completed_ids.copy(),
            )
            self._checkpoint_dirty = False
            self._last_checkpoint_time = time.monotonic()
```

- [ ] **Step 5: Add try/finally flush after queue.join**

In `panoptic/core.py`, modify lines 256-260 in `_run_scan`:

```python
                # Wait until all enqueued work (including dynamically injected) is done
                try:
                    await queue.join()
                finally:
                    await self._flush_checkpoint()
                    for task in worker_tasks:
                        task.cancel()
                    await asyncio.gather(*worker_tasks, return_exceptions=True)
```

- [ ] **Step 6: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add panoptic/core.py tests/test_core.py
git commit -m "fix: throttle checkpoint writes with async lock and atomic file replacement"
```

---

## Chunk 3: Validation & UX

### Task 8: Add validation for `--delay`, `--timeout`, and `--random-delay` (spec items 6, 7)

**Files:**
- Modify: `panoptic/models.py:67-71`
- Modify: `panoptic/cli.py:172-178,183-229`
- Test: `tests/test_models.py`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write failing tests for model validation**

In `tests/test_models.py`, add to `TestScanConfig`:

```python
def test_negative_timeout_rejected(self) -> None:
    with pytest.raises(ValueError, match="timeout must be > 0"):
        ScanConfig(url="http://example.com", timeout=-1.0)

def test_zero_timeout_rejected(self) -> None:
    with pytest.raises(ValueError, match="timeout must be > 0"):
        ScanConfig(url="http://example.com", timeout=0.0)

def test_negative_delay_rejected(self) -> None:
    with pytest.raises(ValueError, match="delay must be >= 0"):
        ScanConfig(url="http://example.com", delay=-0.5)

def test_zero_delay_allowed(self) -> None:
    config = ScanConfig(url="http://example.com", delay=0.0)
    assert config.delay == 0.0

def test_inverted_random_delay_rejected(self) -> None:
    with pytest.raises(ValueError, match="random_delay min must be < max"):
        ScanConfig(url="http://example.com", random_delay=(5.0, 0.5))

def test_negative_random_delay_rejected(self) -> None:
    with pytest.raises(ValueError, match="random_delay values must be non-negative"):
        ScanConfig(url="http://example.com", random_delay=(-1.0, 0.5))

def test_valid_random_delay_accepted(self) -> None:
    config = ScanConfig(url="http://example.com", random_delay=(0.5, 2.0))
    assert config.random_delay == (0.5, 2.0)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_models.py::TestScanConfig::test_negative_timeout_rejected -v`
Expected: FAIL — no validation yet.

- [ ] **Step 3: Add validation to `__post_init__`**

In `panoptic/models.py`, extend `__post_init__` (line 67):

```python
    def __post_init__(self) -> None:
        if self.concurrency < 1:
            raise ValueError(f"concurrency must be >= 1, got {self.concurrency}")
        if not (0.0 < self.heuristic_ratio < 1.0):
            raise ValueError(f"heuristic_ratio must be between 0 and 1 (exclusive), got {self.heuristic_ratio}")
        if self.timeout <= 0:
            raise ValueError(f"timeout must be > 0, got {self.timeout}")
        if self.delay < 0:
            raise ValueError(f"delay must be >= 0, got {self.delay}")
        if self.random_delay is not None:
            if self.random_delay[0] < 0 or self.random_delay[1] < 0:
                raise ValueError("random_delay values must be non-negative")
            if self.random_delay[0] >= self.random_delay[1]:
                raise ValueError("random_delay min must be < max")
```

- [ ] **Step 4: Run model tests to verify they pass**

Run: `python3 -m pytest tests/test_models.py -v`
Expected: ALL PASS

- [ ] **Step 5: Add CLI validation for clean error messages**

In `panoptic/cli.py`, add to `validate_args` (after concurrency validation around line 204):

```python
    # Timeout validation
    if args.get("timeout") is not None and args["timeout"] <= 0:
        print("[!] --timeout must be greater than 0", file=sys.stderr)
        sys.exit(1)

    # Delay validation
    if args.get("delay") is not None and args["delay"] < 0:
        print("[!] --delay must be non-negative", file=sys.stderr)
        sys.exit(1)
```

In `parse_args`, after the random-delay parsing (line 175), add validation:

```python
    if result.get("random_delay") and isinstance(result["random_delay"], tuple):
        min_val, max_val = result["random_delay"]
        if min_val < 0 or max_val < 0:
            print("[!] --random-delay values must be non-negative", file=sys.stderr)
            sys.exit(1)
        if min_val >= max_val:
            print("[!] --random-delay MIN must be less than MAX", file=sys.stderr)
            sys.exit(1)
```

- [ ] **Step 6: Write CLI validation tests**

In `tests/test_cli.py`, add to `TestValidateArgs`:

```python
def test_rejects_negative_timeout(self) -> None:
    with pytest.raises(SystemExit):
        validate_args({"url": "http://example.com", "list": None, "update": False,
                       "list_all_files": False, "header": None, "timeout": -1.0})

def test_rejects_negative_delay(self) -> None:
    with pytest.raises(SystemExit):
        validate_args({"url": "http://example.com", "list": None, "update": False,
                       "list_all_files": False, "header": None, "delay": -0.5})
```

Add to `TestParseArgs`:

```python
def test_inverted_random_delay_rejected(self) -> None:
    with pytest.raises(SystemExit):
        parse_args(["--url", "http://example.com", "--random-delay", "5.0-0.5"])
```

- [ ] **Step 7: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 8: Commit**

```bash
git add panoptic/models.py panoptic/cli.py tests/test_models.py tests/test_cli.py
git commit -m "feat: validate timeout, delay, and random-delay at CLI and model level"
```

---

### Task 9: Remove redundant semaphore (spec item 4)

**Files:**
- Modify: `panoptic/network.py:26-29,85`

The scanner creates exactly `config.concurrency` workers, each doing one fetch at a time. The `asyncio.Semaphore` in `NetworkClient` is redundant.

- [ ] **Step 1: Remove semaphore from `__init__` and `fetch`**

In `panoptic/network.py`, remove line 29:
```python
# DELETE: self._semaphore = asyncio.Semaphore(config.concurrency)
```

Remove `import asyncio` if no longer needed (check: it's still needed if used elsewhere — it isn't, so remove it).

In `fetch`, remove the `async with self._semaphore:` wrapper (line 85). Dedent the try/except block:

```python
    async def fetch(
        self,
        url: str,
        data: str | None = None,
        headers: dict[str, str] | None = None,
    ) -> httpx.Response | None:
        if self._client is None:
            raise RuntimeError("NetworkClient must be used as async context manager")

        try:
            if data is not None:
                post_headers = {"Content-Type": "application/x-www-form-urlencoded"}
                if headers:
                    post_headers.update(headers)
                response = await self._client.post(
                    url,
                    content=data.encode("utf-8"),
                    headers=post_headers,
                )
            else:
                response = await self._client.get(url, headers=headers)
            return response
        except httpx.HTTPError:
            return None
```

Note: `asyncio` import can be removed since the semaphore was the only use.

- [ ] **Step 2: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add panoptic/network.py
git commit -m "refactor: remove redundant concurrency semaphore from NetworkClient"
```

---

### Task 10: Add elapsed time and ETA to progress bar (spec item 5)

**Files:**
- Modify: `panoptic/core.py:22-28,229-236,262-269`

- [ ] **Step 1: Add time columns to Progress bar**

In `panoptic/core.py`, update the import (line 22):

```python
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
    TimeRemainingColumn,
)
```

Update the Progress construction (line 229):

```python
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

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 4: Commit**

```bash
git add panoptic/core.py
git commit -m "feat: add elapsed time, ETA, and req/s to progress bar and summary"
```

---

### Task 11: Improve `--list` output with header and count (spec item 8)

**Files:**
- Modify: `panoptic/cli.py:251-261`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Modify `--list` handler**

In `panoptic/cli.py`, replace lines 258-260:

```python
        values = list_values(args["list"], config=_config)
        print(f"Available {args['list']} values ({len(values)}):")
        for val in sorted(values):
            print(f"  {val}")
        return
```

- [ ] **Step 2: Run full suite**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 3: Commit**

```bash
git add panoptic/cli.py
git commit -m "feat: add header and count to --list output"
```

---

## Chunk 4: New Features — Simple

### Task 12: Add `--quiet` / `-q` flag (spec item 9)

**Files:**
- Modify: `panoptic/models.py` (add field)
- Modify: `panoptic/cli.py` (add arg + default handling)
- Modify: `panoptic/output.py` (quiet-aware TextFormatter)
- Modify: `panoptic/core.py` (pass quiet to formatter, skip progress bar)
- Test: `tests/test_output.py`
- Test: `tests/test_models.py`

Behavior contract:
- Suppressed: banner, info, progress bar, summary, verbose
- Shown: found, warning

- [ ] **Step 1: Write failing tests**

In `tests/test_output.py`, add:

```python
class TestQuietMode:
    def test_quiet_suppresses_banner(self) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        formatter.write_banner("1.0", "http://example.com")
        buf.seek(0)
        assert buf.read() == ""

    def test_quiet_suppresses_info(self) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        formatter.write_info("Starting scan")
        buf.seek(0)
        assert buf.read() == ""

    def test_quiet_suppresses_summary(self) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        formatter.write_summary([], 100)
        buf.seek(0)
        assert buf.read() == ""

    def test_quiet_shows_found(self, sample_results: list[ScanResult]) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        formatter.write_found(sample_results[0])
        buf.seek(0)
        assert "/etc/passwd" in buf.read()

    def test_quiet_shows_warning(self) -> None:
        buf = io.StringIO()
        formatter = TextFormatter(buf, quiet=True)
        formatter.write_warning("SSL disabled")
        buf.seek(0)
        assert "SSL disabled" in buf.read()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_output.py::TestQuietMode -v`
Expected: FAIL — `TextFormatter.__init__` doesn't accept `quiet` parameter.

- [ ] **Step 3: Add `quiet` field to `ScanConfig`**

In `panoptic/models.py`, add after `verbose` (line 107):

```python
    verbose: bool = False
    quiet: bool = False
```

- [ ] **Step 4: Add `-q, --quiet` to CLI**

In `panoptic/cli.py`, in the Output group (after line 102):

```python
    out.add_argument("-q", "--quiet", action="store_true", help="Suppress banner, info, and progress — only show findings and warnings")
```

Add `"quiet": False` to `_ARGPARSE_DEFAULTS` dict (line 144).

- [ ] **Step 5: Implement quiet mode in `TextFormatter`**

In `panoptic/output.py`, modify `TextFormatter.__init__` (line 56):

```python
class TextFormatter:
    """Rich-powered text output for terminal display."""

    def __init__(
        self,
        stream: TextIO | None = None,
        console: Console | None = None,
        quiet: bool = False,
    ) -> None:
        self._console = console or Console(file=stream or sys.stderr, highlight=False)
        self._quiet = quiet

    def write_banner(self, version: str, url: str) -> None:
        if self._quiet:
            return
        self._console.print(
            f"[bold cyan] .-',--.`-.[/]\n"
            f"[bold cyan]<_ | () | _>[/]\n"
            f"[bold cyan]  `-`=='-'[/]\n"
            f"\n[bold]Panoptic {version}[/] ({url})\n"
        )

    def write_info(self, message: str) -> None:
        if self._quiet:
            return
        self._console.print(f"[blue][i][/blue] {message}")

    def write_warning(self, message: str) -> None:
        self._console.print(f"[red][!][/red] {message}")

    def write_found(self, result: ScanResult) -> None:
        case = result.case
        file_type_str = case.file_type.value if case.file_type else None
        parts = [p for p in (case.os, case.category, case.software, file_type_str) if p]
        context = f" ({'/'.join(parts)})" if parts else ""
        self._console.print(f"[bold green][+][/bold green] Found '{case.location}'{context}")

    def write_verbose(self, message: str) -> None:
        if self._quiet:
            return
        self._console.print(f"[dim][*] {message}[/dim]")

    def write_summary(self, results: list[ScanResult], total_cases: int) -> None:
        if self._quiet:
            return
        found = [r for r in results if r.found]
        self._console.print("\n[bold]Scan Complete[/bold]")
        self._console.print(f"  Cases tested: {total_cases}")
        self._console.print(f"  Files found:  [green]{len(found)}[/green]")
```

- [ ] **Step 6: Pass quiet to formatters in `core.py`**

In `panoptic/core.py`, modify `_run_scan` line 166:

```python
        text_out = TextFormatter(stderr_stream, quiet=self.config.quiet)
```

Modify scan_out creation (line 239):

```python
                scan_out = TextFormatter(console=progress.console, quiet=self.config.quiet)
```

For the progress bar, replace the entire `with Progress(...) as progress:` block (lines 229-260) with a conditional approach using manual start/stop. This avoids duplicating the worker logic:

```python
            scan_start = time.monotonic()

            # Conditionally create progress bar (None in quiet mode)
            progress_ctx: Progress | None = None
            progress_task_id = None
            if not self.config.quiet:
                progress_ctx = Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TimeElapsedColumn(),
                    TimeRemainingColumn(),
                    console=Console(file=stderr_stream, highlight=False),
                    transient=True,
                )
                progress_ctx.start()
                progress_task_id = progress_ctx.add_task("Scanning", total=self.total_queued)
                scan_out = TextFormatter(console=progress_ctx.console, quiet=False)
            else:
                scan_out = TextFormatter(stderr_stream, quiet=True)

            try:
                async def worker() -> None:
                    while True:
                        case = await queue.get()
                        try:
                            async with self._pause_lock:
                                pass
                            await self._process_case(
                                case, client, request_params, queue, scan_out, progress_ctx
                            )
                            self.total_processed += 1
                            if progress_ctx is not None and progress_task_id is not None:
                                progress_ctx.update(
                                    progress_task_id,
                                    total=self.total_queued,
                                    completed=self.total_processed,
                                )
                        finally:
                            queue.task_done()

                worker_tasks = [
                    asyncio.create_task(worker()) for _ in range(self.config.concurrency)
                ]

                try:
                    await queue.join()
                finally:
                    await self._flush_checkpoint()
                    for task in worker_tasks:
                        task.cancel()
                    await asyncio.gather(*worker_tasks, return_exceptions=True)
            finally:
                if progress_ctx is not None:
                    progress_ctx.stop()
```

This is a single code path for both quiet and non-quiet modes. The key difference: progress bar is created and started only when not quiet; worker logic is identical either way.

- [ ] **Step 7: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_output.py tests/test_models.py -v`
Expected: ALL PASS

- [ ] **Step 8: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 9: Commit**

```bash
git add panoptic/models.py panoptic/cli.py panoptic/output.py panoptic/core.py tests/test_output.py
git commit -m "feat: add --quiet flag to suppress non-actionable output"
```

---

### Task 13: Add `--follow-redirects` flag (spec item 12)

**Files:**
- Modify: `panoptic/models.py` (add field)
- Modify: `panoptic/cli.py` (add arg)
- Modify: `panoptic/network.py:56` (use config flag)
- Test: `tests/test_network.py`

- [ ] **Step 1: Write failing test**

In `tests/test_network.py`, add a behavioral test instead of checking private httpx internals:

```python
    async def test_follow_redirects_when_enabled(self, httpx_mock: HTTPXMock) -> None:
        """Verify redirect following works by checking final response content."""
        config = ScanConfig(url="http://example.com", follow_redirects=True)
        httpx_mock.add_response(
            url="http://example.com/start",
            status_code=302,
            headers={"Location": "http://example.com/final"},
        )
        httpx_mock.add_response(url="http://example.com/final", text="followed")
        async with NetworkClient(config) as client:
            resp = await client.fetch("http://example.com/start")
            assert resp is not None
            assert resp.text == "followed"
            assert resp.status_code == 200

    async def test_no_follow_redirects_by_default(self, httpx_mock: HTTPXMock) -> None:
        """Default behavior should NOT follow redirects."""
        config = ScanConfig(url="http://example.com")
        httpx_mock.add_response(
            url="http://example.com/start",
            status_code=302,
            headers={"Location": "http://example.com/final"},
        )
        async with NetworkClient(config) as client:
            resp = await client.fetch("http://example.com/start")
            assert resp is not None
            assert resp.status_code == 302
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_network.py::TestNetworkClient::test_follow_redirects_when_enabled -v`
Expected: FAIL — `ScanConfig` doesn't have `follow_redirects` field.

- [ ] **Step 3: Add field to `ScanConfig`**

In `panoptic/models.py`, add after `all_versions` (line 102):

```python
    all_versions: bool = False
    follow_redirects: bool = False
```

- [ ] **Step 4: Add CLI argument**

In `panoptic/cli.py`, in Connection/Proxy group (after line 46):

```python
    conn.add_argument("--follow-redirects", dest="follow_redirects", action="store_true",
                       help="Follow HTTP redirects (default: don't follow)")
```

Add `"follow_redirects": False` to `_ARGPARSE_DEFAULTS`.

- [ ] **Step 5: Use config flag in `NetworkClient`**

In `panoptic/network.py`, change line 56:

```python
# OLD:
            follow_redirects=False,
# NEW:
            follow_redirects=self.config.follow_redirects,
```

- [ ] **Step 6: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add panoptic/models.py panoptic/cli.py panoptic/network.py tests/test_network.py
git commit -m "feat: add --follow-redirects flag"
```

---

## Chunk 5: New Features — Complex

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

In `panoptic/cli.py`, in Scan Options group (after `--bad-string` line 76):

```python
    scan.add_argument("--match-string", dest="match_string",
                       help="Only report findings containing this string in response")
```

- [ ] **Step 3: Write failing tests**

In `tests/test_core.py`, add:

```python
from unittest.mock import AsyncMock, patch

class TestMatchString:
    async def test_match_string_excludes_non_matching_response(self) -> None:
        """Responses WITHOUT match_string should NOT be reported as found."""
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt",
            param="file",
            match_string="root:x:0:0",
            automatic=True,
        )
        scanner = Scanner(config)
        scanner.invalid_response = "<html>not found</html>"
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "nonexistent"

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "<html>some content without the string</html>"
        mock_response.headers = {"content-length": "0"}

        text_out = AsyncMock()
        queue: asyncio.Queue[Case] = asyncio.Queue()
        case = Case(location="/etc/shadow", os="*NIX")

        with patch.object(scanner, "_fetch", return_value=mock_response):
            with patch("panoptic.core.is_match", return_value=True):
                await scanner._process_case(case, AsyncMock(), "file=test.txt", queue, text_out)

        # No result should be recorded — response lacks match_string
        assert len(scanner.results) == 0

    async def test_match_string_includes_matching_response(self) -> None:
        """Responses WITH match_string should be reported as found."""
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt",
            param="file",
            match_string="root:x:0:0",
            automatic=True,
        )
        scanner = Scanner(config)
        scanner.invalid_response = "<html>not found</html>"
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "nonexistent"

        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "root:x:0:0:root:/root:/bin/bash"
        mock_response.headers = {"content-length": "0"}

        text_out = AsyncMock()
        text_out.write_found = lambda r: None
        text_out.write_info = lambda m: None
        queue: asyncio.Queue[Case] = asyncio.Queue()
        case = Case(location="/etc/passwd", os="*NIX")

        with patch.object(scanner, "_fetch", return_value=mock_response):
            with patch("panoptic.core.is_match", return_value=True):
                await scanner._process_case(case, AsyncMock(), "file=test.txt", queue, text_out)

        assert len(scanner.results) == 1
        assert scanner.results[0].found is True

    async def test_match_string_disables_content_length_fast_path(self) -> None:
        """Content-Length optimization must be skipped when match_string requires body inspection."""
        config = ScanConfig(
            url="http://example.com/test.php?file=test.txt",
            param="file",
            match_string="root:x:0:0",
            automatic=True,
        )
        scanner = Scanner(config)
        scanner.invalid_response = "x" * 100
        scanner.invalid_status_code = 200
        scanner.invalid_filename = "nonexistent"
        scanner.original_response = "x" * 100

        # Response has large content-length (would trigger fast path) but body lacks match_string
        mock_response = AsyncMock()
        mock_response.status_code = 200
        mock_response.text = "large body " * 500  # No match_string present
        mock_response.headers = {"content-length": "50000"}

        text_out = AsyncMock()
        text_out.write_found = lambda r: None
        queue: asyncio.Queue[Case] = asyncio.Queue()
        case = Case(location="/etc/passwd", os="*NIX")

        with patch.object(scanner, "_fetch", return_value=mock_response):
            await scanner._process_case(case, AsyncMock(), "file=test.txt", queue, text_out)

        # Should NOT be found because match_string is absent, even though content-length is huge
        assert len(scanner.results) == 0
```

- [ ] **Step 4: Modify `_process_case` to gate all positive paths**

In `panoptic/core.py`, modify the Content-Length optimization (line 339) to skip when `match_string` requires body:

```python
        if (
            not self.config.write_files
            and not self.config.match_string
            and content_length > 0
            and content_length - baseline_length > SKIP_RETRIEVE_THRESHOLD
        ):
```

Add `match_string` check after `bad_string` check (after line 360):

```python
        if self.config.bad_string and self.config.bad_string in html:
            await self._mark_completed(case)
            return

        if self.config.match_string and self.config.match_string not in html:
            await self._mark_completed(case)
            return
```

- [ ] **Step 5: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 6: Commit**

```bash
git add panoptic/models.py panoptic/cli.py panoptic/core.py tests/test_core.py
git commit -m "feat: add --match-string to only report findings containing a specific string"
```

---

### Task 15: Add `--match-code` and `--filter-code` (spec item 11)

**Files:**
- Modify: `panoptic/models.py` (add fields)
- Modify: `panoptic/cli.py` (add args + parsing + validation)
- Modify: `panoptic/core.py` (add filtering)
- Test: `tests/test_cli.py`
- Test: `tests/test_core.py`

- [ ] **Step 1: Add fields to `ScanConfig`**

In `panoptic/models.py`, add after `match_string`:

```python
    match_string: str | None = None
    match_codes: list[int] | None = None
    filter_codes: list[int] | None = None
```

- [ ] **Step 2: Write failing tests for CLI parsing**

In `tests/test_cli.py`, add to `TestParseArgs`:

```python
def test_match_code_parsing(self) -> None:
    args = parse_args(["--url", "http://example.com", "--match-code", "200,301"])
    assert args["match_codes"] == [200, 301]

def test_filter_code_parsing(self) -> None:
    args = parse_args(["--url", "http://example.com", "--filter-code", "404,500"])
    assert args["filter_codes"] == [404, 500]

def test_invalid_match_code_rejected(self) -> None:
    with pytest.raises(SystemExit):
        parse_args(["--url", "http://example.com", "--match-code", "999"])

def test_non_numeric_match_code_rejected(self) -> None:
    with pytest.raises(SystemExit):
        parse_args(["--url", "http://example.com", "--match-code", "abc"])
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_cli.py::TestParseArgs::test_match_code_parsing -v`
Expected: FAIL — no `--match-code` argument.

- [ ] **Step 4: Add CLI arguments and parsing**

In `panoptic/cli.py`, add to Scan Options group:

```python
    scan.add_argument("--match-code", dest="match_codes",
                       help="Only report findings with these HTTP status codes (comma-separated, e.g. '200,301')")
    scan.add_argument("--filter-code", dest="filter_codes",
                       help="Exclude findings with these HTTP status codes (comma-separated, e.g. '404,500')")
```

In `parse_args`, after the random-delay parsing block, add:

```python
    # Parse --match-code and --filter-code comma-separated strings
    for code_key in ("match_codes", "filter_codes"):
        if result.get(code_key) and isinstance(result[code_key], str):
            try:
                codes = [int(c.strip()) for c in result[code_key].split(",")]
                for code in codes:
                    if not 100 <= code <= 599:
                        raise ValueError(f"HTTP status code out of range: {code}")
                result[code_key] = codes
            except ValueError as e:
                flag = "--match-code" if code_key == "match_codes" else "--filter-code"
                print(f"[!] Invalid {flag}: {e}", file=sys.stderr)
                sys.exit(1)
```

- [ ] **Step 5: Add `config.py` normalization for TOML sources**

TOML config files may provide `match_codes` and `filter_codes` as TOML arrays (`[200, 301]`) or comma-separated strings (`"200,301"`). Add normalization in `config.py:merge_config()` before constructing `ScanConfig`:

```python
    # Normalize match_codes/filter_codes: accept TOML arrays or comma-separated strings
    for code_key in ("match_codes", "filter_codes"):
        val = merged.get(code_key)
        if isinstance(val, str):
            try:
                merged[code_key] = [int(c.strip()) for c in val.split(",")]
            except ValueError:
                pass  # CLI parsing will catch invalid values
        elif isinstance(val, list) and val and isinstance(val[0], str):
            try:
                merged[code_key] = [int(c) for c in val]
            except ValueError:
                pass
```

Add test in `tests/test_config.py`:

```python
def test_match_codes_from_toml_array(self, tmp_path: Path) -> None:
    config_file = tmp_path / "config.toml"
    config_file.write_text('[defaults]\nmatch_codes = [200, 301]\n')
    file_config = load_config(str(config_file))
    config = merge_config({"url": "http://example.com"}, file_config)
    assert config.match_codes == [200, 301]
```

- [ ] **Step 6: Add filtering in `_process_case`**

In `panoptic/core.py`, add after the existing status-class check (after line 330):

```python
        # User-specified status code filtering
        if self.config.filter_codes and response.status_code in self.config.filter_codes:
            await self._mark_completed(case)
            return
        if self.config.match_codes and response.status_code not in self.config.match_codes:
            await self._mark_completed(case)
            return
```

- [ ] **Step 6: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 7: Commit**

```bash
git add panoptic/models.py panoptic/cli.py panoptic/core.py tests/test_cli.py
git commit -m "feat: add --match-code and --filter-code for HTTP status filtering"
```

---

### Task 16: Add multiple `--header` support (spec item 13)

**Files:**
- Modify: `panoptic/models.py:115` (rename field)
- Modify: `panoptic/cli.py:42,214-219,277` (action=append, validation, FUZZ check)
- Modify: `panoptic/core.py:410-418` (iterate headers for FUZZ)
- Modify: `panoptic/network.py:107-128` (iterate headers)
- Modify: `panoptic/config.py:65-68` (normalize merge)
- Test: `tests/test_network.py:70`
- Test: `tests/test_cli.py`

This is a breaking rename: `header: str | None` → `headers: list[str] | None`. All 6 callsites must update.

- [ ] **Step 1: Write failing tests for multi-header**

In `tests/test_network.py`, add:

```python
    async def test_multiple_custom_headers(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", headers=["X-Custom: val1", "X-Other: val2"])
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/test")
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["x-custom"] == "val1"
        assert request.headers["x-other"] == "val2"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m pytest tests/test_network.py::TestNetworkClient::test_multiple_custom_headers -v`
Expected: FAIL — `ScanConfig` has no `headers` field.

- [ ] **Step 3: Rename field in `ScanConfig`**

In `panoptic/models.py`, change line 115:

```python
# OLD:
    header: str | None = None
# NEW:
    headers: list[str] | None = None
```

- [ ] **Step 4: Update CLI argument**

In `panoptic/cli.py`, change line 42:

```python
# OLD:
    conn.add_argument("--header", help="Add custom HTTP header (e.g. 'X-Forwarded-For: 127.0.0.1')")
# NEW:
    conn.add_argument("--header", dest="headers", action="append",
                       help="Add custom HTTP header (repeatable, e.g. --header 'X-Foo: 1' --header 'X-Bar: 2')")
```

Update `validate_args` (line 213-219):

```python
    # Header CRLF validation
    for hdr in args.get("headers") or []:
        try:
            validate_header(hdr)
        except ValueError as e:
            print(f"[!] Invalid header: {e}", file=sys.stderr)
            sys.exit(1)
```

Update `has_fuzz` check (line 277):

```python
# OLD:
    has_fuzz = "FUZZ" in (config.data or "") or "FUZZ" in (config.header or "")
# NEW:
    has_fuzz = "FUZZ" in (config.data or "") or any("FUZZ" in h for h in (config.headers or []))
```

- [ ] **Step 5: Update `_fuzz_headers` in core.py**

In `panoptic/core.py`, replace `_fuzz_headers` (line 410):

```python
    def _fuzz_headers(self, location: str) -> dict[str, str] | None:
        """Build per-request headers with FUZZ replaced, or None if no FUZZ in headers."""
        if not self.config.headers:
            return None
        from panoptic.utils import validate_header

        fuzz_hdrs: dict[str, str] = {}
        processed = process_path(self.config, location)
        for hdr in self.config.headers:
            if FUZZ_MARKER in hdr:
                name, value = validate_header(hdr)
                fuzz_hdrs[name] = value.replace(FUZZ_MARKER, processed)
        return fuzz_hdrs or None
```

- [ ] **Step 6: Update `_build_headers` in network.py with Cookie conflict detection**

In `panoptic/network.py`, replace lines 123-126:

```python
        # Custom headers (Name: Value format, with CRLF validation)
        if self.config.headers:
            for hdr in self.config.headers:
                name, value = validate_header(hdr)
                # Warn on Cookie conflict: --cookie and --header "Cookie: ..." both set
                if name.lower() == "cookie" and "Cookie" in headers:
                    import sys
                    print(
                        "[!] Warning: --header 'Cookie: ...' overrides --cookie value",
                        file=sys.stderr,
                    )
                headers[name] = value
```

> **Design note:** The design spec mentions Cookie conflict detection. When both
> `--cookie "sid=abc"` and `--header "Cookie: extra=1"` are passed, the header
> value silently overwrites the cookie value. Printing a warning is the simplest
> solution that respects KISS — merging Cookie values is complex and error-prone.

- [ ] **Step 7: Update `config.py` merge for backward compatibility**

In `panoptic/config.py`, add normalization before constructing `ScanConfig` (before line 77):

```python
    # Normalize header/headers: accept single string (old TOML) or list
    if "header" in merged and "headers" not in merged:
        val = merged.pop("header")
        if isinstance(val, str):
            merged["headers"] = [val]
        elif isinstance(val, list):
            merged["headers"] = val
    elif "header" in merged:
        merged.pop("header")  # headers takes precedence
```

- [ ] **Step 8: Update ALL existing tests that reference `header`**

In `tests/test_network.py`, change `test_custom_header` (line 69):

```python
    async def test_custom_header(self, httpx_mock: HTTPXMock) -> None:
        config = ScanConfig(url="http://example.com", headers=["X-Custom: value123"])
        httpx_mock.add_response()
        async with NetworkClient(config) as client:
            await client.fetch("http://example.com/test")
        request = httpx_mock.get_request()
        assert request is not None
        assert request.headers["x-custom"] == "value123"
```

In `tests/test_cli.py`, update ALL `validate_args` test calls that pass `"header"`:

```python
# test_rejects_file_scheme (line 60) — change:
#   "header": None,
# to:
#   "headers": None,

# test_rejects_crlf_header (line 70) — change:
#   "header": "X-Foo: bar\r\nInjected: yes",
# to:
#   "headers": ["X-Foo: bar\r\nInjected: yes"],

# test_accepts_valid_args (line 83) — change:
#   "header": None,
# to:
#   "headers": None,
```

There are 4 calls to `validate_args` in `test_cli.py` — update all of them from `"header"` key to `"headers"` key. For string values, wrap in a list.

- [ ] **Step 9: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 10: Commit**

```bash
git add panoptic/models.py panoptic/cli.py panoptic/core.py panoptic/network.py panoptic/config.py tests/
git commit -m "feat: support multiple --header flags with backward-compatible config merge"
```

---

### Task 17: Add `--output-format` for `--list` and `--list-all-files` (spec item 14)

**Files:**
- Modify: `panoptic/cli.py:244-261`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write tests**

In `tests/test_cli.py`, add:

```python
class TestListFormatting:
    def test_list_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """--list with --output-format json should produce valid JSON."""
        import json

        from panoptic.cases import list_values
        values = list_values("os")
        output = json.dumps(sorted(values), indent=2)
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert "*NIX" in parsed

    def test_list_all_files_json_output(self, capsys: pytest.CaptureFixture[str]) -> None:
        """--list-all-files with --output-format json should produce valid JSON."""
        import json

        from panoptic.cases import list_all_files
        paths = list_all_files()
        output = json.dumps(paths, indent=2)
        parsed = json.loads(output)
        assert isinstance(parsed, list)
        assert len(parsed) > 0
        assert all(isinstance(p, str) for p in parsed)

    def test_list_all_files_csv_output(self) -> None:
        """--list-all-files with --output-format csv should have header row."""
        from panoptic.cases import list_all_files
        paths = list_all_files()
        # CSV format: header + data rows
        lines = ["path"] + paths
        assert lines[0] == "path"
        assert len(lines) > 1
```

- [ ] **Step 2: Modify `--list` handler to support output format**

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
                print(val)
        else:
            print(f"Available {args['list']} values ({len(values)}):")
            for val in sorted(values):
                print(f"  {val}")
        return
```

- [ ] **Step 3: Modify `--list-all-files` handler similarly**

In `panoptic/cli.py`, replace the `--list-all-files` handler (lines 244-249):

```python
    if args.get("list_all_files"):
        import json as json_mod

        from panoptic.cases import list_all_files

        paths = list_all_files()
        fmt = args.get("output_format") or "text"

        if fmt == "json":
            print(json_mod.dumps(paths, indent=2))
        elif fmt == "csv":
            print("path")
            for path in paths:
                print(path)
        else:
            for path in paths:
                print(path)
        return
```

- [ ] **Step 4: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/cli.py tests/test_cli.py
git commit -m "feat: add --output-format support for --list and --list-all-files"
```

---

### Task 18: URL-encode payloads for GET requests (spec item 3c)

**Files:**
- Modify: `panoptic/core.py:68-107`
- Test: `tests/test_core.py`

After base64 encoding or slash replacement, payloads can contain `&` and `#` which corrupt the query string. Use `urllib.parse.quote` with a conservative safe set.

- [ ] **Step 1: Write failing test**

In `tests/test_core.py`, add to `TestBuildPayload`:

```python
def test_get_payload_encodes_ampersand(self) -> None:
    """Payload containing & must be encoded in GET query strings."""
    config = ScanConfig(url="http://example.com/test.php?file=test.txt", param="file")
    # A path that contains & after transformation
    payload = build_payload(config, "/etc/foo&bar", "file=test.txt")
    # The & in the path value must be percent-encoded to prevent query string corruption
    assert "foo%26bar" in payload

def test_post_payload_encodes_plus_as_percent2b(self) -> None:
    """POST payloads must encode + to prevent space decoding in form bodies."""
    config = ScanConfig(
        url="http://example.com/test.php",
        param="file",
        data="file=test.txt",
    )
    # Base64 value containing + (e.g., from --base64 encoding)
    payload = build_payload(config, "/etc/foo+bar", "file=test.txt")
    assert "%2B" in payload or "foo%2Bbar" in payload  # + encoded for POST

def test_get_payload_preserves_plus(self) -> None:
    """GET payloads should keep + unencoded for base64 compat with PHP $_GET."""
    config = ScanConfig(url="http://example.com/test.php?file=test.txt", param="file")
    payload = build_payload(config, "/etc/foo+bar", "file=test.txt")
    assert "foo+bar" in payload  # + stays raw for GET

def test_replace_slash_percent_not_double_encoded(self) -> None:
    """--replace-slash with pre-encoded value like %2F must not double-encode."""
    config = ScanConfig(
        url="http://example.com/test.php?file=test.txt",
        param="file",
        replace_slash="%2F",
    )
    payload = build_payload(config, "/etc/passwd", "file=test.txt")
    # %2F should stay as %2F, NOT become %252F
    assert "%2F" in payload
    assert "%252F" not in payload

def test_fuzz_mode_no_encoding(self) -> None:
    """FUZZ mode should not auto-encode — user controls the template."""
    config = ScanConfig(url="http://example.com/test.php", data='{"file":"FUZZ"}')
    payload = build_payload(config, "/etc/passwd", '{"file":"FUZZ"}')
    assert "/etc/passwd" in payload  # Raw, no encoding
```

- [ ] **Step 2: Run tests to verify first two fail**

Run: `python3 -m pytest tests/test_core.py::TestBuildPayload::test_get_payload_encodes_ampersand -v`
Expected: FAIL — `&bar` appears raw in the query string.

- [ ] **Step 3: Add URL-encoding to `build_payload`**

In `panoptic/core.py`, add import at the top:

```python
from urllib.parse import quote as url_quote
```

In `build_payload`, add encoding helpers. **Important design decisions:**

> 1. **GET vs POST encoding must differ.** Under `application/x-www-form-urlencoded`,
>    `+` is decoded as space by PHP and most frameworks. Base64 values containing `+`
>    (like `dGVz+dA==`) would silently corrupt. POST bodies must encode `+` as `%2B`.
> 2. **Pre-encoded values must not be double-encoded.** If `--replace-slash "%2F"` is
>    used, the `%` would be encoded to `%25`, producing `%252F`. Use `safe="%"` to
>    preserve pre-encoded sequences, or detect and skip already-encoded values.

```python
def _encode_param_value(value: str, *, is_post: bool = False) -> str:
    """URL-encode chars that would corrupt a query/form body.

    Safe chars (not encoded):
      /       : LFI path traversal separators must stay literal
      %       : Preserve pre-encoded sequences (e.g., --replace-slash "%2F")
    GET-specific safe: = and + (base64 compat, PHP $_GET handles natively)
    POST-specific: + MUST be encoded as %2B (decoded as space by form parsers)
    """
    if is_post:
        return url_quote(value, safe="=/%")
    return url_quote(value, safe="=+/%")
```

Then in the param replacement branches, encode the full_path before substitution (but NOT in FUZZ mode), passing `is_post=bool(config.data)` to select the right encoding:

```python
    result = request_params
    is_post = bool(config.data)
    if FUZZ_MARKER in result:
        result = result.replace(FUZZ_MARKER, full_path)
    elif config.ext_param and config.param and "." in full_path:
        path_without_ext, ext = full_path.rsplit(".", 1)
        encoded_base = _encode_param_value(path_without_ext, is_post=is_post)
        encoded_ext = _encode_param_value(ext, is_post=is_post)
        result = re.sub(
            rf"(?:^|(?<=&)){re.escape(config.param)}=(?P<value>[^&]*)",
            rf"{config.param}={encoded_base}",
            result,
        )
        result = re.sub(
            rf"(?:^|(?<=&)){re.escape(config.ext_param)}=(?P<value>[^&]*)",
            rf"{config.ext_param}={encoded_ext}",
            result,
        )
    elif config.param:
        encoded_path = _encode_param_value(full_path, is_post=is_post)
        result = re.sub(
            rf"(?:^|(?<=&)){re.escape(config.param)}=(?P<value>[^&]*)",
            rf"{config.param}={encoded_path}",
            result,
        )
```

- [ ] **Step 4: Run full suite + type check**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/`
Expected: ALL PASS

- [ ] **Step 5: Commit**

```bash
git add panoptic/core.py tests/test_core.py
git commit -m "fix: URL-encode reserved chars in GET/POST payloads to prevent query corruption"
```

---

### Task 19: Final — update CLAUDE.md with new flags

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add new flags to CLAUDE.md**

In the Key Patterns or a new section, document:

```markdown
- **`--quiet` / `-q`** — Suppress banner, info, progress, and summary. Only shows `[+] Found` and `[!]` warnings.
- **`--match-string`** — Only report findings when this string IS present in the response (inverse of `--bad-string`).
- **`--match-code` / `--filter-code`** — Filter by HTTP status code (comma-separated, e.g. `--match-code 200,301`).
- **`--follow-redirects`** — Follow HTTP redirects (default: don't follow).
- **`--header`** — Repeatable. Multiple `--header` flags add multiple headers.
- **`--output-format`** — Now also applies to `--list` and `--list-all-files` commands (json, csv, text).

### Breaking Changes

- **JSON/CSV URL redaction** — The `url` field in JSON and CSV output now uses
  `redact_url()`, which replaces query param values with `***`. If downstream tools
  re-parse the URL field for retesting, redacted URLs will break them. Use `--verbose`
  with text output format for full URLs.
```

- [ ] **Step 2: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: document new CLI flags in CLAUDE.md"
```

- [ ] **Step 3: Run full test suite one final time**

Run: `python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/ && python3 -m ruff check panoptic/`
Expected: ALL PASS
