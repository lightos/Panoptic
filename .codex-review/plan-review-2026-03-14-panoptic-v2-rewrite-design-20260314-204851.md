OpenAI Codex v0.114.0 (research preview)
--------
workdir: /home/manchine/dev/Panoptic
model: gpt-5.4
provider: openai
approval: never
sandbox: read-only
reasoning effort: high
reasoning summaries: none
session id: 019cef9c-6f1f-7eb3-99ad-4472143df84c
--------
user
Review implementation plan at: /home/manchine/dev/Panoptic/docs/superpowers/specs/2026-03-14-panoptic-v2-rewrite-design.md

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
Reviewing the plan document first, then I’ll check whether the proposed phases cover the stated requirements and call out concrete gaps, risks, and unnecessary complexity with section references.
exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/docs/superpowers/specs/2026-03-14-panoptic-v2-rewrite-design.md" in /home/manchine/dev/Panoptic succeeded in 0ms:
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
| Concurrency | `asyncio` with `Semaphore` | No threads, no locks, no race conditions by design |
| Terminal UX | `rich` | Progress bars, colors, tables, cross-platform |
| Output formats | Text + JSON + CSV | Pipeline integration via `--output-format` |
| Config | TOML file (`~/.config/panoptic/config.toml`) | Persistent defaults, CLI overrides |
| Testing | pytest + CI (GitHub Actions) | Python 3.10/3.11/3.12 matrix, ruff, mypy |
exec
/bin/bash -lc "rg --files /home/manchine/dev/Panoptic | rg 'AGENTS\\.md"'$|README|docs/superpowers/specs'"'" in /home/manchine/dev/Panoptic succeeded in 0ms:
/home/manchine/dev/Panoptic/README.md
/home/manchine/dev/Panoptic/docs/superpowers/specs/2026-03-14-panoptic-v2-rewrite-design.md
codex
I’ve got the main structure. Next I’m reading the remainder of the spec and checking it against the current project surface so the review is grounded in what Panoptic already claims to support.
exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/README.md" in /home/manchine/dev/Panopticexec
/bin/bash -lc "sed -n '261,520p' /home/manchine/dev/Panoptic/docs/superpowers/specs/2026-03-14-panoptic-v2-rewrite-design.md" in /home/manchine/dev/Panoptic succeeded in 0ms:

Merge priority: CLI args > config file > built-in defaults. Loaded via `tomli` (Python 3.10) or `tomllib` (3.11+).

## Self-Update (`update.py`)

- `subprocess.run(["git", "pull", "origin", "main"], ...)` — list args, no `shell=True`
- `subprocess.run(["git", "rev-parse", "--verify", "HEAD"], ...)` — same pattern
- Clear error messages on failure

## Resume/Checkpoint

- If `--resume-file` specified, completed case hashes are serialized to JSON after each batch
- On restart with same resume file, already-completed cases are skipped
- Uses `Case.__hash__()` (frozen dataclass provides this automatically)

## Dependencies (`pyproject.toml`)

```toml
[project]
name = "panoptic"
 succeeded in 0ms:
Panoptic
===

![Panoptic Logo](https://i.imgur.com/nQrtLkO.png)
+ [![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
+ [![Python Versions](https://img.shields.io/badge/python-3.x-blue.svg)](https://www.python.org/)
  
  Panoptic is an open source penetration testing tool that automates the process of search and retrieval of content for common log and config files through path traversal vulnerability. Official introductionary post can be found [here](http://websec.ca/blog/view/panoptic). Also, you can find a sample run [here](https://gist.github.com/stamparm/5335273).

## Features

* Automatic discovery of common log and configuration files via parameter-based and path-based LFI
* Automatic detection of target OS when a file is found, with option to restrict further scans (`--os`)
* Ability to test all versioned file paths (`--all-versions`) based on `versions.ini`
* Extension parameter handling for separate filename and extension (`--ext-param`)
* Multi-threaded scanning for faster results (`--threads`)
* Comprehensive built-in testing library with categorization by OS, category, and software
* Multiple traversal bypass techniques: custom prefixes (`--prefix`), postfixes (`--postfix`), traversal depth (`--multiplier`), and slash replacement (`--replace-slash`)
* Listing options: list available filters (`--list`), and list all built-in file paths (`--list-all-files`)
* Support for HTTP/HTTPS and SOCKS4/SOCKS5 proxies (`--proxy`), with proxy validation
codex
The spec claims backward compatibility, so I’m comparing it to the current CLI and behavior surface now. That’s where most hidden omissions usually show up.
exec
/bin/bash -lc "sed -n '1,260p' /home/manchine/dev/Panoptic/panoptic.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
#!/usr/bin/env python3

"""
Copyright (c) 2013-2015 Roberto Christopher Salgado Bjerre, Miroslav Stampar.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"),
to deal in the Software without restriction, including without limitation the
rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
sell copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
exec
/bin/bash -lc "rg -n \"--[a-z-]+|add_argument|parser\\.add_option|optparse|ArgumentParser|OptionParser|list_all_files|write_files|update|ext_param|random-agent|log-file|list=\" /home/manchine/dev/Panoptic/panoptic.py" in /home/manchine/dev/Panoptic exited 2 in 0ms:
rg: unrecognized flag --[a-z-]+|add_argument|parser\.add_option|optparse|ArgumentParser|OptionParser|list_all_files|write_files|update|ext_param|random-agent|log-file|list
exec
/bin/bash -lc "sed -n '260,620p' /home/manchine/dev/Panoptic/panoptic.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
        for variable in re.findall(r"\{[^}]+\}", case.location):
            case.location = case.location.replace(variable, replacements.get(variable.strip("{}"), variable))

        match = re.search(r"\[([^\]]+)\]", case.location)
        if match and kb.all_versions:
            original = case.location
            for replacement in kb.versioned_locations[match.group(1)]:
                case_copy = AttribDict(case)
                case_copy.location = original.replace(match.group(0), replacement)
                cases.append(case_copy)
        else:
            cases.append(case)

    return cases


def load_list(filepath):
    """
    Loads list of items from a custom given filepath location
    """
exec
/bin/bash -lc "rg -n \"add_argument|ArgumentParser|--list-all-files|--log-file|--update|--load|--threads|--header|--bad-string|--replace-slash|--ext-param|--random-agent|--proxy|--ignore-proxy|--path-based|--skip-parsing|--write-files|--all-versions|--list\\b|--category|--software|--os\\b|--type\\b|--data\\b|--param\\b|--url\\b\" /home/manchine/dev/Panoptic/panoptic.py" in /home/manchine/dev/Panoptic succeeded in 0ms:
75:# If content size is bigger than normal (and illegal) skip content retrieval (if --write-files not used) and mark it as found
95:  ./panoptic.py --url "http://localhost/include.php?file=test.txt"
96:  ./panoptic.py --url "http://localhost/include.php?file=test.txt&id=1" --param file
97:  ./panoptic.py --url "http://localhost/include.php" --data "file=test.txt&id=1" --param file
98:  ./panoptic.py --url "http://localhost/files/view/test.txt" --path-based --prefix "..%252f"
99:  ./panoptic.py --url "http://localhost/param.php?file=test&type=txt" --param file --ext-param type
100:  ./panoptic.py --url "http://localhost/include.php?file=test.txt" --auto --all-versions
102:  ./panoptic.py --list software
103:  ./panoptic.py --list category
104:  ./panoptic.py --list os
106:  ./panoptic.py -u "http://localhost/include.php?file=test.txt" --os "*NIX"
107:  ./panoptic.py -u "http://localhost/include.php?file=test.txt" --software WAMP
649:    parser = argparse.ArgumentParser(
656:    parser.add_argument("-h", "--help", action="help", help="Show this help message and exit")
658:    conn = parser.add_argument_group("Connection / Proxy")
659:    conn.add_argument("-u", "--url", dest="url",
661:    conn.add_argument("--proxy", help="Route requests through proxy (e.g. 'socks5://127.0.0.1:9050')")
662:    conn.add_argument("--ignore-proxy", action="store_true",
664:    conn.add_argument("--random-agent", action="store_true", dest="random_agent",
667:    conn.add_argument("--header", dest="header", default=None,
exec
/bin/bash -lc "sed -n '620,980p' /home/manchine/dev/Panoptic/panoptic.py" in /home/manchine/dev/Panopticexec
/bin/bash -lc "sed -n '980,1240p' /home/manchine/dev/Panoptic/panoptic.py" in /home/manchine/dev/Panoptic succeeded in 0ms:

            if args.verbose:
                print_func("[*] Extracting home folders from '%s'." % case.location)

            for user in users:
                if args.verbose:
                    print_func("[*] User: %s, Info: %s" % (user.group("username"), user.group("info")))
                if not kb.home_files:
                    with open(HOME_FILES_FILE, "r") as f:
                        kb.home_files = list(filter(None, [_.strip() for _ in f.readlines()]))
                for _ in kb.home_files:
                    if user.group("home") == "/":
                        continue
                    request_file(AttribDict({"category": "*NIX User File", "type": "conf", "os": case.os, "location": "%s/%s" % (user.group("home"), _), "software": "*NIX"}))

        if "mysql-bin.index" in case.location and not args.skip_parsing:
            binlogs = re.findall("\\.\\\\(?P<binlog>mysql-bin\\.\\d{0,6})", html)
            location = case.location.rfind("/") + 1

            if args.verbose:
 succeeded in 0ms:
    if not kb.found:
        print_func("[i] No files found!")
    elif args.verbose:
        print_func("\n[i] Files found:")
        for _ in kb.files:
            print_func("[o] %s" % _)

    print_func("  \n[i] File search complete.")
    print_func("[i] Total files found: %d" % kb.total_found)
    print_func("\n[i] Finishing scan at: %s\n" % time.strftime("%X"))
    # Close the log file if it was successfully opened
    fp = getattr(kb, 'log_fp', None)
    if fp:
        fp.close()


def get_page(**kwargs):
    """
    Retrieves page content from a given target URL
    """
codex
I’ve identified a few structural gaps already around dynamic scan flow, packaging, and compatibility claims. I’m pulling exact section line numbers now so the review can point to the spec precisely.
exec
/bin/bash -lc "nl -ba /home/manchine/dev/Panoptic/docs/superpowers/specs/2026-03-14-panoptic-v2-rewrite-design.md | sed -n '1,260p'" in /home/manchine/dev/Panoptic succeeded in 0ms:
     1	# Panoptic v2.0 Rewrite Design Spec
     2	
     3	## Overview
     4	
     5	Complete rewrite of Panoptic from a monolithic single-file script into a modern Python package. Fixes all critical bugs identified in the codebase audit, adds missing features expected of a professional security tool, and establishes a proper testing/CI foundation.
     6	
     7	**Approach:** Clean rewrite into new package structure, porting logic function-by-function from the original `panoptic.py`. Old file stays as reference until new version passes all tests.
     8	
     9	## Decisions
    10	
    11	| Decision | Choice | Rationale |
    12	|----------|--------|-----------|
    13	| Architecture | Python package (`panoptic/`) | Testable, maintainable, pip-installable |
    14	| Python version | 3.10+ | Best asyncio support, match/case, union types |
    15	| HTTP client | `httpx` (async) | Native async, SOCKS support, HTTP/2, granular timeouts |
    16	| Concurrency | `asyncio` with `Semaphore` | No threads, no locks, no race conditions by design |
    17	| Terminal UX | `rich` | Progress bars, colors, tables, cross-platform |
    18	| Output formats | Text + JSON + CSV | Pipeline integration via `--output-format` |
    19	| Config | TOML file (`~/.config/panoptic/config.toml`) | Persistent defaults, CLI overrides |
    20	| Testing | pytest + CI (GitHub Actions) | Python 3.10/3.11/3.12 matrix, ruff, mypy |
exec
/bin/bash -lc "nl -ba /home/manchine/dev/Panoptic/docs/superpowers/specs/2026-03-14-panoptic-v2-rewrite-design.md | sed -n '261,420p'" in /home/manchine/dev/Panoptic succeeded in 0ms:
   261	
   262	Merge priority: CLI args > config file > built-in defaults. Loaded via `tomli` (Python 3.10) or `tomllib` (3.11+).
   263	
   264	## Self-Update (`update.py`)
   265	
   266	- `subprocess.run(["git", "pull", "origin", "main"], ...)` — list args, no `shell=True`
   267	- `subprocess.run(["git", "rev-parse", "--verify", "HEAD"], ...)` — same pattern
   268	- Clear error messages on failure
   269	
   270	## Resume/Checkpoint
   271	
   272	- If `--resume-file` specified, completed case hashes are serialized to JSON after each batch
   273	- On restart with same resume file, already-completed cases are skipped
   274	- Uses `Case.__hash__()` (frozen dataclass provides this automatically)
   275	
   276	## Dependencies (`pyproject.toml`)
   277	
   278	```toml
   279	[project]
   280	name = "panoptic"
codex
One more pass against the current implementation surfaced a few smaller behavioral requirements that the rewrite spec doesn’t mention explicitly. I’m checking which of those are real requirements versus just implementation detail so the review stays focused.
exec
/bin/bash -lc "sed -n '1,120p' /home/manchine/dev/Panoptic/home.txt" in /home/manchine/dev/Panoptic succeeded in 0ms:
.aptitude/config
.aws/credentials
.azure/accessTokens.json
.azure/azureProfile.json
.bash_config
.bash_history
.bash_logout
.bashrc
.boto
.bundle/config
.cache/notify-osd.log
.cargo/credentials
.config/gcloud/access_tokens.db
.config/gcloud/credentials.db
.config/oDesk/oDesk Team.conf
.config/rclone/rclone.conf
.cshrc
.docker/config.json
.env
.gem/credentials
exec
/bin/bash -lc "rg -n \"\\{HOST\\}|\\[["'^]]+'"\\]\" /home/manchine/dev/Panoptic/cases.xml /home/manchine/dev/Panoptic/versions.ini" in /home/manchine/dev/Panoptic succeeded in 0ms:
/home/manchine/dev/Panoptic/versions.ini:1:[JBOSS]
/home/manchine/dev/Panoptic/cases.xml:127:                    <file value="/Program Files/MySQL/MySQL Server 5.0/data/{HOST}.err"/>
/home/manchine/dev/Panoptic/cases.xml:132:                    <file value="/Program Files/MySQL/data/{HOST}.err"/>
/home/manchine/dev/Panoptic/cases.xml:137:                    <file value="/MySQL/data/{HOST}.err"/>
/home/manchine/dev/Panoptic/cases.xml:149:                    <file value="/usr/local/mysql/data/{HOST}.err"/>
/home/manchine/dev/Panoptic/cases.xml:316:                    <file value="/xampp/mysql/data/{HOST}.err"/>
/home/manchine/dev/Panoptic/cases.xml:1520:                    <file value="/opt/[JBOSS]/server/default/conf/jboss-minimal.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1521:                    <file value="/opt/[JBOSS]/server/default/conf/jboss-service.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1522:                    <file value="/opt/[JBOSS]/server/default/conf/jndi.properties"/>
/home/manchine/dev/Panoptic/cases.xml:1523:                    <file value="/opt/[JBOSS]/server/default/conf/log4j.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1524:                    <file value="/opt/[JBOSS]/server/default/conf/login-config.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1525:                    <file value="/opt/[JBOSS]/server/default/conf/standardjaws.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1526:                    <file value="/opt/[JBOSS]/server/default/conf/standardjboss.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1527:                    <file value="/opt/[JBOSS]/server/default/conf/server.log.properties"/>
/home/manchine/dev/Panoptic/cases.xml:1528:                    <file value="/opt/[JBOSS]/server/default/deploy/jboss-logging.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1529:                    <file value="/usr/local/[JBOSS]/server/default/conf/jboss-minimal.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1530:                    <file value="/usr/local/[JBOSS]/server/default/conf/jboss-service.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1531:                    <file value="/usr/local/[JBOSS]/server/default/conf/jndi.properties"/>
/home/manchine/dev/Panoptic/cases.xml:1532:                    <file value="/usr/local/[JBOSS]/server/default/conf/log4j.xml"/>
/home/manchine/dev/Panoptic/cases.xml:1533:                    <file value="/usr/local/[JBOSS]/server/default/conf/login-config.xml"/>
codex
**Findings**

SECTION: `Scanner Core`  
SEVERITY: CRITICAL  
ISSUE: `asyncio.gather` over a fixed case list conflicts with two required behaviors in the same spec: OS restriction after the first hit, and dynamic follow-up work from passwd/binlog parsing. If tasks are created up front, later decisions cannot reliably stop or add work.  
SUGGESTION: Replace fixed-list `gather` with an `asyncio.Queue` plus worker pool. Apply OS restriction when dequeuing, and let parsers enqueue derived cases into the same queue.

SECTION: `Resume/Checkpoint`  
SEVERITY: CRITICAL  
ISSUE: Persisting `Case.__hash__()` is not safe across runs. Python hashes for strings are randomized per process, so a resume file will not produce stable identities after restart.  
SUGGESTION: Store a stable case ID instead, such as a canonical JSON tuple of case fields or a deterministic digest like SHA-256 over those fields.

SECTION: `Dependencies (pyproject.toml)` / `Package Structure` / `Migration Path`  
SEVERITY: HIGH  
ISSUE: The plan moves `cases.xml`, `versions.ini`, `agents.txt`, and `home.txt` into `panoptic/data/`, but it does not define how those files are packaged into wheels/sdists or loaded at runtime. Installed builds will likely lose access to them.  
SUGGESTION: Add a `build-system`, package-data/include rules, and a runtime resource-loading strategy using `importlib.resources`.

SECTION: `Case Parser (cases.py)`  
SEVERITY: HIGH  
ISSUE: The current case library depends on `{HOST}` substitution inside `cases.xml`. The rewrite spec mentions version expansion but not placeholder expansion, so some built-in cases would silently stop working.  
SUGGESTION: Add explicit token expansion for `{HOST}` and test it together with version expansion.

SECTION: `Self-Update (update.py)`  
SEVERITY: HIGH  
ISSUE: `git pull origin main` does not fit the stated “pip-installable” architecture. It only works in a source checkout and creates an inconsistent upgrade path for installed users.  
SUGGESTION: Either drop `--update`, restrict it to verified git checkouts, or replace it with installer-specific guidance such as `pip install -U panoptic`.

SECTION: `CLI (cli.py)`  
SEVERITY: HIGH  
ISSUE: “Validation: param `re.escape()`” is the wrong fix for the regex-injection bug. Escaping should happen where the regex is built, not during argument validation, or parameter names may be transformed and request generation can break.  
SUGGESTION: Keep raw parameter names in config and escape only at the regex use site, or better, replace regex-based query mutation with structured query parsing.

SECTION: `CLI (cli.py)` / `What's NOT Changing`  
SEVERITY: MEDIUM  
ISSUE: The spec claims existing flags are preserved, but it only designs the scan path. Current non-scan behaviors like `--list`, `--list-all-files`, and `--log-file` are not actually described.  
SUGGESTION: Add explicit command-mode flows for listing filters, listing all file paths, and logging semantics separate from scan result formatting.

SECTION: `Network Layer (network.py)` / `CLI (cli.py)`  
SEVERITY: MEDIUM  
ISSUE: Two compatibility-sensitive behaviors are underspecified: `--ignore-proxy` needs `httpx` `trust_env=False`, and `--header` syntax is inconsistent today (`=` in README, `:` in help). The rewrite can easily regress one or both.  
SUGGESTION: Define proxy behavior explicitly with `trust_env=not ignore_proxy`, and accept both header syntaxes while rejecting CR/LF.

SECTION: `Scanner Core (core.py)` / `Heuristic Engine (heuristic.py)`  
SEVERITY: MEDIUM  
ISSUE: `bad_string` exists in `ScanConfig` but is missing from the scan flow, and the current tool has a large-response shortcut when `--write-files` is off. Omitting these changes behavior and can increase memory/time cost.  
SUGGESTION: Add an explicit `bad_string` rejection step and a body-size strategy before reading large responses fully into memory.

SECTION: `Migration Path`  
SEVERITY: MEDIUM  
ISSUE: Removing `panoptic.py` breaks the currently documented invocation style (`./panoptic.py` / `python panoptic.py`) even though the spec otherwise emphasizes compatibility.  
SUGGESTION: Keep a thin compatibility shim for at least one release, or mark this clearly as an intentional breaking change.

Main blockers are the queue design, stable checkpoint identity, packaging/resource handling, and the mismatch between “pip-installable” and `git pull` self-update.
tokens used
35,192
**Findings**

SECTION: `Scanner Core`  
SEVERITY: CRITICAL  
ISSUE: `asyncio.gather` over a fixed case list conflicts with two required behaviors in the same spec: OS restriction after the first hit, and dynamic follow-up work from passwd/binlog parsing. If tasks are created up front, later decisions cannot reliably stop or add work.  
SUGGESTION: Replace fixed-list `gather` with an `asyncio.Queue` plus worker pool. Apply OS restriction when dequeuing, and let parsers enqueue derived cases into the same queue.

SECTION: `Resume/Checkpoint`  
SEVERITY: CRITICAL  
ISSUE: Persisting `Case.__hash__()` is not safe across runs. Python hashes for strings are randomized per process, so a resume file will not produce stable identities after restart.  
SUGGESTION: Store a stable case ID instead, such as a canonical JSON tuple of case fields or a deterministic digest like SHA-256 over those fields.

SECTION: `Dependencies (pyproject.toml)` / `Package Structure` / `Migration Path`  
SEVERITY: HIGH  
ISSUE: The plan moves `cases.xml`, `versions.ini`, `agents.txt`, and `home.txt` into `panoptic/data/`, but it does not define how those files are packaged into wheels/sdists or loaded at runtime. Installed builds will likely lose access to them.  
SUGGESTION: Add a `build-system`, package-data/include rules, and a runtime resource-loading strategy using `importlib.resources`.

SECTION: `Case Parser (cases.py)`  
SEVERITY: HIGH  
ISSUE: The current case library depends on `{HOST}` substitution inside `cases.xml`. The rewrite spec mentions version expansion but not placeholder expansion, so some built-in cases would silently stop working.  
SUGGESTION: Add explicit token expansion for `{HOST}` and test it together with version expansion.

SECTION: `Self-Update (update.py)`  
SEVERITY: HIGH  
ISSUE: `git pull origin main` does not fit the stated “pip-installable” architecture. It only works in a source checkout and creates an inconsistent upgrade path for installed users.  
SUGGESTION: Either drop `--update`, restrict it to verified git checkouts, or replace it with installer-specific guidance such as `pip install -U panoptic`.

SECTION: `CLI (cli.py)`  
SEVERITY: HIGH  
ISSUE: “Validation: param `re.escape()`” is the wrong fix for the regex-injection bug. Escaping should happen where the regex is built, not during argument validation, or parameter names may be transformed and request generation can break.  
SUGGESTION: Keep raw parameter names in config and escape only at the regex use site, or better, replace regex-based query mutation with structured query parsing.

SECTION: `CLI (cli.py)` / `What's NOT Changing`  
SEVERITY: MEDIUM  
ISSUE: The spec claims existing flags are preserved, but it only designs the scan path. Current non-scan behaviors like `--list`, `--list-all-files`, and `--log-file` are not actually described.  
SUGGESTION: Add explicit command-mode flows for listing filters, listing all file paths, and logging semantics separate from scan result formatting.

SECTION: `Network Layer (network.py)` / `CLI (cli.py)`  
SEVERITY: MEDIUM  
ISSUE: Two compatibility-sensitive behaviors are underspecified: `--ignore-proxy` needs `httpx` `trust_env=False`, and `--header` syntax is inconsistent today (`=` in README, `:` in help). The rewrite can easily regress one or both.  
SUGGESTION: Define proxy behavior explicitly with `trust_env=not ignore_proxy`, and accept both header syntaxes while rejecting CR/LF.

SECTION: `Scanner Core (core.py)` / `Heuristic Engine (heuristic.py)`  
SEVERITY: MEDIUM  
ISSUE: `bad_string` exists in `ScanConfig` but is missing from the scan flow, and the current tool has a large-response shortcut when `--write-files` is off. Omitting these changes behavior and can increase memory/time cost.  
SUGGESTION: Add an explicit `bad_string` rejection step and a body-size strategy before reading large responses fully into memory.

SECTION: `Migration Path`  
SEVERITY: MEDIUM  
ISSUE: Removing `panoptic.py` breaks the currently documented invocation style (`./panoptic.py` / `python panoptic.py`) even though the spec otherwise emphasizes compatibility.  
SUGGESTION: Keep a thin compatibility shim for at least one release, or mark this clearly as an intentional breaking change.

Main blockers are the queue design, stable checkpoint identity, packaging/resource handling, and the mismatch between “pip-installable” and `git pull` self-update.
