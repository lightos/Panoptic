# XML-to-CSV Case Database Migration

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the XML case database with a flat CSV file, dropping the `defusedxml` dependency, simplifying the parser, and adding schema validation.

**Architecture:** Convert `cases.xml` (nested hierarchy with inherited metadata) to `cases.csv` (flat rows with explicit columns). Rewrite `cases.py` to use stdlib `csv.DictReader` with validation. Add `MIX` to `FileType` enum to fix the 23 entries that currently parse as `file_type=None`.

**Tech Stack:** Python stdlib `csv` module (replaces `defusedxml`)

---

## Chunk 1: Data Conversion & Validation Infrastructure

### Task 1: Add MIX to FileType enum

The XML contains `<mix>` tags for 23 Bash entries. The current parser silently drops these to `file_type=None` because `_determine_file_type()` only handles `conf`, `log`, `other`. Fix by adding `MIX` to the enum.

**Files:**

- Modify: `panoptic/models.py:13-18`
- Test: `tests/test_cases.py`

- [ ] **Step 1: Write test for MIX enum value**

```python
# Add to tests/test_cases.py
def test_file_type_has_mix() -> None:
    assert FileType.MIX.value == "mix"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `source .venv/bin/activate && python3 -m pytest tests/test_cases.py::test_file_type_has_mix -v`
Expected: FAIL — `AttributeError: MIX`

- [ ] **Step 3: Add MIX to FileType enum**

In `panoptic/models.py`, add `MIX = "mix"` after `OTHER = "other"` in the `FileType` enum.

```python
class FileType(Enum):
    """Type of file being tested."""

    CONF = "conf"
    LOG = "log"
    OTHER = "other"
    MIX = "mix"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `source .venv/bin/activate && python3 -m pytest tests/test_cases.py::test_file_type_has_mix -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `source .venv/bin/activate && python3 -m pytest tests/ -x -q`
Expected: All 113 tests pass (112 existing + 1 new)

- [ ] **Step 6: Commit**

```bash
git add panoptic/models.py tests/test_cases.py
git commit -m "feat: add MIX to FileType enum for mixed-type case entries"
```

---

### Task 2: Generate cases.csv from cases.xml

Write a one-time conversion script, run it, verify output matches XML, then delete the script.

**Files:**

- Create (temporary): `scripts/convert_xml_to_csv.py`
- Create: `panoptic/data/cases.csv`

- [ ] **Step 1: Write conversion script**

Create `scripts/convert_xml_to_csv.py`:

```python
#!/usr/bin/env python3
"""One-time conversion: cases.xml → cases.csv.

Reads the XML, resolves inherited metadata via ancestor walking,
and writes a flat CSV sorted by category,software,type,os,path.
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path
from xml.etree.ElementTree import Element

import defusedxml.ElementTree as ET

XML_PATH = Path(__file__).resolve().parent.parent / "panoptic" / "data" / "cases.xml"
CSV_PATH = XML_PATH.with_suffix(".csv")

TYPE_TAGS = {"conf", "log", "other", "mix"}


def find_ancestor(element: Element, tag: str, parent_map: dict) -> str:
    current = element
    while current in parent_map:
        parent = parent_map[current]
        if parent.tag == tag:
            return parent.get("value", "")
        current = parent
    return ""


def find_type(element: Element, parent_map: dict) -> str:
    current = element
    while current in parent_map:
        parent = parent_map[current]
        if parent.tag in TYPE_TAGS:
            return parent.tag
        current = parent
    return ""


def main() -> None:
    tree = ET.parse(str(XML_PATH))
    root = tree.getroot()

    parent_map: dict = {}
    for parent in root.iter():
        for child in parent:
            parent_map[child] = parent

    rows: list[dict[str, str]] = []
    for file_elem in root.iter("file"):
        path = file_elem.get("value", "")
        if not path:
            continue
        rows.append({
            "path": path,
            "os": find_ancestor(file_elem, "os", parent_map),
            "software": find_ancestor(file_elem, "software", parent_map),
            "category": find_ancestor(file_elem, "category", parent_map),
            "type": find_type(file_elem, parent_map),
        })

    # Sort for stable diffs and visual grouping
    rows.sort(key=lambda r: (r["category"], r["software"], r["type"], r["os"], r["path"]))

    with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["path", "os", "software", "category", "type"])
        writer.writeheader()
        writer.writerows(rows)

    print(f"Wrote {len(rows)} cases to {CSV_PATH}")

    # Verify no data loss
    xml_count = sum(1 for _ in root.iter("file") if _.get("value"))
    assert len(rows) == xml_count, f"Count mismatch: {len(rows)} CSV vs {xml_count} XML"
    print(f"Verified: {xml_count} entries match")


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Run the conversion**

```bash
source .venv/bin/activate && python3 scripts/convert_xml_to_csv.py
```

Expected output (count should match actual XML file entries — currently 1024):

```
Wrote 1024 cases to panoptic/data/cases.csv
Verified: 1024 entries match
```

Note the actual count from this output — use it in all subsequent assertions.

- [ ] **Step 3: Verify CSV content**

```bash
head -5 panoptic/data/cases.csv
wc -l panoptic/data/cases.csv
```

Expected: 1025 lines (1 header + 1024 data rows). First line is `path,os,software,category,type`. Every row has all 5 fields populated.

- [ ] **Step 4: Verify no empty fields or broken rows**

```bash
source .venv/bin/activate && python3 -c "
import csv
with open('panoptic/data/cases.csv', newline='', encoding='utf-8') as f:
    reader = csv.DictReader(f)
    rows = list(reader)
    assert len(rows) == 1024, f'Expected 1024, got {len(rows)}'
    for i, row in enumerate(rows):
        for col in ['path','os','software','category','type']:
            assert row[col], f'Row {i+1}: empty {col}: {row}'
    types = {r['type'] for r in rows}
    assert types <= {'conf','log','other','mix'}, f'Unknown types: {types}'
    print(f'All {len(rows)} rows valid')
    print(f'Types: {sorted(types)}')
"
```

Expected: `All 1024 rows valid`, `Types: ['conf', 'log', 'mix', 'other']`

- [ ] **Step 5: Delete conversion script, commit CSV**

```bash
rm scripts/convert_xml_to_csv.py
rmdir scripts 2>/dev/null || true
git add panoptic/data/cases.csv
git commit -m "data: add cases.csv converted from cases.xml (1024 entries)"
```

---

## Chunk 2: Rewrite Parser

### Task 3: Rewrite cases.py to use CSV

Replace the XML parser with a CSV parser. Add validation. Keep the same public API: `parse_cases()`, `load_custom_list()`, `list_values()`, `list_all_files()`, `load_versions()`.

**Files:**

- Modify: `panoptic/cases.py` (full rewrite)
- Test: `tests/test_cases.py`

- [ ] **Step 1: Write validation test**

Add to `tests/test_cases.py`:

```python
class TestCsvValidation:
    def test_parse_cases_returns_same_count(self) -> None:
        """CSV parser returns same number of cases as before."""
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        assert len(cases) == 1024

    def test_all_cases_have_metadata(self) -> None:
        """Every case from CSV has all metadata fields populated."""
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        for case in cases:
            assert case.os is not None, f"Missing os: {case.location}"
            assert case.software is not None, f"Missing software: {case.location}"
            assert case.category is not None, f"Missing category: {case.location}"
            assert case.file_type is not None, f"Missing file_type: {case.location}"

    def test_mix_type_cases_exist(self) -> None:
        """The mix type entries (Bash) are properly typed, not None."""
        config = ScanConfig(url="http://example.com")
        cases = parse_cases(config)
        mix_cases = [c for c in cases if c.file_type == FileType.MIX]
        assert len(mix_cases) > 0


class TestListFunctions:
    def test_list_values_os(self) -> None:
        from panoptic.cases import list_values
        values = list_values("os")
        assert "*NIX" in values
        assert "Windows" in values

    def test_list_values_software(self) -> None:
        from panoptic.cases import list_values
        values = list_values("software")
        assert "PHP" in values
        assert "nginx" in values

    def test_list_values_unknown_group(self) -> None:
        from panoptic.cases import list_values
        values = list_values("nonexistent")
        assert values == set()

    def test_list_all_files(self) -> None:
        from panoptic.cases import list_all_files
        files = list_all_files()
        assert len(files) > 0
        assert all(isinstance(f, str) for f in files)
```

- [ ] **Step 2: Run tests — they should fail on current XML parser (mix test)**

Run: `source .venv/bin/activate && python3 -m pytest tests/test_cases.py::TestCsvValidation -v`
Expected: `test_mix_type_cases_exist` FAILS (current parser returns `None` for mix entries)

- [ ] **Step 3: Rewrite cases.py**

Replace the full contents of `panoptic/cases.py` with:

```python
"""CSV case parsing, filtering, version expansion, and custom list loading."""

from __future__ import annotations

import csv
import os
import re
from urllib.parse import urlsplit

from panoptic.models import Case, FileType, ScanConfig
from panoptic.utils import load_data_file

REQUIRED_COLUMNS = frozenset({"path", "os", "software", "category", "type"})
VALID_TYPES = frozenset(t.value for t in FileType)


def _validate_csv(rows: list[dict[str, str]]) -> None:
    """Validate CSV data on first load. Raises ValueError on bad data."""
    for i, row in enumerate(rows, start=2):  # line 1 is header
        for col in REQUIRED_COLUMNS:
            if not row.get(col):
                raise ValueError(f"cases.csv line {i}: empty '{col}' field")
        if row["type"] not in VALID_TYPES:
            raise ValueError(
                f"cases.csv line {i}: unknown type '{row['type']}', "
                f"expected one of {sorted(VALID_TYPES)}"
            )


def _load_csv() -> list[dict[str, str]]:
    """Load and validate cases.csv. Returns list of row dicts."""
    content = load_data_file("cases.csv")
    reader = csv.DictReader(content.splitlines())
    if reader.fieldnames is None or not REQUIRED_COLUMNS.issubset(set(reader.fieldnames)):
        raise ValueError(
            f"cases.csv: missing required columns {sorted(REQUIRED_COLUMNS)}, "
            f"got {reader.fieldnames}"
        )
    rows = list(reader)
    _validate_csv(rows)
    return rows


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
    """Parse cases.csv and return test cases filtered by config.

    Validates CSV structure on load. Applies OS/software/category/type filters.
    Expands {HOST} placeholders and [SECTION] version patterns.
    """
    rows = _load_csv()

    # Build replacements dict for placeholder expansion
    replacements: dict[str, str] = {}
    if config.url:
        replacements["HOST"] = urlsplit(config.url).netloc

    # Load versions for expansion
    versions = load_versions() if config.all_versions else {}

    cases: list[Case] = []

    for row in rows:
        os_val = row["os"]
        software_val = row["software"]
        category_val = row["category"]
        file_type = FileType(row["type"])
        location = row["path"]

        # Apply filters
        if config.os_filter and os_val.lower() != config.os_filter.lower():
            continue
        if config.software_filter and software_val.lower() != config.software_filter.lower():
            continue
        if config.category_filter and category_val.lower() != config.category_filter.lower():
            continue
        if config.type_filter and file_type.value != config.type_filter.lower():
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
                cases.append(
                    Case(
                        location=expanded,
                        os=os_val,
                        category=category_val,
                        software=software_val,
                        file_type=file_type,
                    )
                )
        else:
            cases.append(
                Case(
                    location=location,
                    os=os_val,
                    category=category_val,
                    software=software_val,
                    file_type=file_type,
                )
            )

    return cases


def load_custom_list(filepath: str) -> list[Case]:
    """Load a custom file list from a user-provided path.

    Validates the file exists and is a regular file.
    """
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"List file not found: {filepath}")
    if not os.path.isfile(filepath):
        raise ValueError(f"Path is not a regular file: {filepath}")

    with open(filepath, encoding="utf-8") as f:
        return [Case(location=stripped) for line in f if (stripped := line.strip())]


def list_values(group: str, config: ScanConfig | None = None) -> set[str]:
    """List unique values for a given group (os, software, category).

    When config is provided, respects active filters (matching original behavior).
    Used by --list command.
    """
    # Map group names to CSV column / Case attribute names
    col_map = {"os": "os", "software": "software", "category": "category"}
    col = col_map.get(group)
    if col is None:
        return set()

    if config is not None:
        cases = parse_cases(config)
        return {getattr(c, col) for c in cases if getattr(c, col)}

    rows = _load_csv()
    return {row[col] for row in rows if row.get(col)}


def list_all_files() -> list[str]:
    """List all file paths in cases.csv.

    Used by --list-all-files command.
    """
    rows = _load_csv()
    return [row["path"] for row in rows]
```

- [ ] **Step 4: Run all tests**

Run: `source .venv/bin/activate && python3 -m pytest tests/ -x -q`
Expected: All tests pass (existing + new validation tests)

- [ ] **Step 5: Run mypy**

Run: `source .venv/bin/activate && python3 -m mypy panoptic/cases.py`
Expected: Success, no errors

- [ ] **Step 6: Run ruff**

Run: `source .venv/bin/activate && python3 -m ruff check panoptic/cases.py`
Expected: All checks passed

- [ ] **Step 7: Commit**

```bash
git add panoptic/cases.py tests/test_cases.py
git commit -m "feat: rewrite case parser from XML to CSV with validation"
```

---

## Chunk 3: Cleanup

### Task 4: Remove defusedxml dependency and XML file

**Files:**

- Delete: `panoptic/data/cases.xml`
- Modify: `pyproject.toml:20` (remove defusedxml from dependencies)
- Modify: `pyproject.toml:57` (remove defusedxml from mypy overrides)
- Modify: `panoptic/cli.py:138` (update help text that says "XML")

- [ ] **Step 1: Remove defusedxml from pyproject.toml dependencies**

In `pyproject.toml`, remove the line `"defusedxml>=0.7",` from `dependencies`.

- [ ] **Step 2: Remove defusedxml from mypy overrides**

In `pyproject.toml`, change the mypy overrides module list from:

```toml
module = ["defusedxml.*", "rich_argparse", "tomli"]
```

to:

```toml
module = ["rich_argparse", "tomli"]
```

- [ ] **Step 3: Update CLI help text**

In `panoptic/cli.py:138`, change the help text from:

```python
help="List all file paths in the XML and exit"
```

to:

```python
help="List all file paths in the case database and exit"
```

- [ ] **Step 4: Delete cases.xml**

```bash
git rm panoptic/data/cases.xml
```

- [ ] **Step 5: Reinstall and verify**

```bash
source .venv/bin/activate && pip install -e ".[dev]" 2>&1 | tail -3
```

- [ ] **Step 6: Run full test suite + mypy + ruff**

```bash
source .venv/bin/activate && python3 -m pytest tests/ -x -q && python3 -m mypy panoptic/ && python3 -m ruff check panoptic/
```

Expected: 115+ tests pass, mypy clean, ruff clean

- [ ] **Step 7: Verify CLI still works**

```bash
source .venv/bin/activate && python3 -m panoptic --help
source .venv/bin/activate && python3 -m panoptic --list-all-files | head -5
source .venv/bin/activate && python3 -m panoptic --list-all-files | wc -l
```

Expected: Help displays, file listing works, count is 1024

- [ ] **Step 8: Commit**

Note: `git rm` in Step 4 already staged the deletion of `cases.xml`.

```bash
git add pyproject.toml panoptic/cli.py panoptic/data/cases.xml
git commit -m "chore: remove defusedxml dependency and cases.xml after CSV migration"
```

---

### Task 5: Update CLAUDE.md

**Files:**

- Modify: `CLAUDE.md`

- [ ] **Step 1: Update architecture section**

Change `cases.py` description from:

```
cases.py     → XML case parser with filtering (os/software/category/type)
```

to:

```
cases.py     → CSV case parser with validation and filtering (os/software/category/type)
```

- [ ] **Step 2: Update dependencies mention**

In the Gotchas section, remove:

```
- `defusedxml` is used for XML parsing (security)
```

And in the Code Quality / Security first section, remove the `defusedxml` reference:
Change:

```
Use `defusedxml` for XML. Verify git remote before
```

to:

```
Verify git remote before
```

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs: update CLAUDE.md for CSV migration"
```
