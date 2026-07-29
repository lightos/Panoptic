# Panoptic

![Panoptic Logo](https://i.imgur.com/nQrtLkO.png)

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![Ruff](https://img.shields.io/badge/linting-ruff-261230.svg)](https://github.com/astral-sh/ruff)
[![mypy](https://img.shields.io/badge/type_check-mypy_strict-blue.svg)](https://mypy-lang.org/)
[![GitHub last commit](https://img.shields.io/github/last-commit/lightos/Panoptic.svg)](https://github.com/lightos/Panoptic/commits/)
![CodeRabbit Pull Request Reviews](https://img.shields.io/coderabbit/prs/github/lightos/Panoptic?utm_source=oss&utm_medium=github&utm_campaign=lightos%2FPanoptic&labelColor=171717&color=FF570A&link=https%3A%2F%2Fcoderabbit.ai&label=CodeRabbit+Reviews)

Panoptic is an open source penetration testing tool that automates
the search and retrieval of common log and config files through
path traversal vulnerabilities.

![Panoptic Demo](assets/demo.gif)

## Features

* Async concurrent scanning with configurable worker pool
  (`--concurrency`)
* Automatic discovery of common log and configuration files via
  parameter-based, path-based, POST, cookie, header, and JSON
  body injection
* FUZZ marker for arbitrary injection points — place `FUZZ`
  in any `--header` or `--data` value
* Base64 encoding for endpoints that decode file paths
  (`--base64`)
* Automatic OS detection with option to restrict further scans
* Heuristic response comparison with status code filtering to
  reduce false positives
* Dynamic case injection — parse `/etc/passwd` for home directory
  files, `mysql-bin.index` for binlog files
* Multiple output formats: text (rich), JSON, CSV
  (`--output-format`)
* Resume/checkpoint support for long-running scans
  (`--resume-file`)
* TOML config files for persistent settings (`--config`)
* Multiple traversal bypass techniques: prefixes, postfixes,
  multiplier, slash replacement, double encoding
* HTTP/HTTPS and SOCKS5 proxy support with validation
* Random or custom User-Agent, cookie, and header support
* Credential redaction in banner, log, and machine-readable output
  (including numeric and boolean JSON body values)
* Sensitive artifacts hardened with owner-only `0600` permissions on
  POSIX and final-component symlink protection where the OS supports it
* Self-update with remote URL verification (`--update`)

## Requirements

* Python 3.10+
* Dependencies: `httpx[socks]`, `rich`, `rich-argparse`

## Installation

```bash
git clone https://github.com/lightos/Panoptic.git
cd Panoptic
pip install -e .
```

For development:

```bash
pip install -e ".[dev]"
```

## Usage

```bash
panoptic --url "http://target/include.php?file=test.txt"
```

## Examples

### Basic parameter-based LFI

```bash
panoptic --url "http://target/include.php?file=test.txt"
panoptic --url "http://target/include.php?file=test.txt&id=1" \
  --param file
```

### POST data injection

```bash
panoptic --url "http://target/include.php" \
  --data "file=test.txt&id=1" --param file
```

### Path-based LFI

```bash
panoptic --url "http://target/view.php/test.txt" --path-based
```

### Base64-encoded parameter

```bash
panoptic --url "http://target/load.php?file=dGVzdC50eHQ=" \
  --base64 --auto
```

### Cookie injection (FUZZ marker)

```bash
panoptic --url "http://target/page.php" \
  --header "Cookie: lang=FUZZ" --auto
```

### JSON body injection (FUZZ marker)

```bash
panoptic --url "http://target/api/load" \
  --data '{"file":"FUZZ"}' --auto
```

### Custom header injection (FUZZ marker)

```bash
panoptic --url "http://target/page.php" \
  --header "X-Template: FUZZ" --auto
```

### Extension parameter

```bash
panoptic --url "http://target/view.php?file=test&type=txt" \
  --param file --ext-param type
```

### Filter bypass with prefix

```bash
panoptic --url "http://target/filtered.php?file=test.txt" \
  --prefix "....//....//....//....//"
```

### Filtered scans

```bash
panoptic --url "http://target/include.php?file=test.txt" \
  --os "*NIX" --type conf
panoptic --url "http://target/include.php?file=test.txt" \
  --software PostgreSQL
```

### JSON output with resume support

```bash
panoptic --url "http://target/include.php?file=test.txt" \
  --output-format json --output-file results.json \
  --resume-file scan.checkpoint
```

### Proxy with SSL errors ignored

```bash
panoptic --url "https://target/include.php?file=test.txt" \
  --proxy "socks5://127.0.0.1:9050" --invalid-ssl
```

### List available filters

```bash
panoptic --list software
panoptic --list category
panoptic --list os
```

### Comprehensive scan

```bash
panoptic --url "http://target/include.php?file=test.txt" \
  --auto --all-versions --concurrency 8
```

## FUZZ Marker

Place `FUZZ` anywhere in `--header` or `--data` values to mark
the injection point. Panoptic replaces `FUZZ` with each file path
during scanning. This enables testing injection points that
`--param` can't reach:

| Injection Type | Example                                  |
| -------------- | ---------------------------------------- |
| Cookie value   | `--header "Cookie: theme=FUZZ"`          |
| Custom header  | `--header "X-Include: FUZZ"`             |
| JSON body      | `--data '{"template":"FUZZ"}'`           |
| Nested value   | `--header "Cookie: sid=abc; lang=FUZZ"`  |

When `FUZZ` is present, `--param` is not required.

## Configuration

Panoptic supports TOML config files for persistent settings:

```bash
panoptic --url "http://target/include.php?file=test.txt" \
  --config ~/.config/panoptic/config.toml
```

Default config location: `~/.config/panoptic/config.toml` (loaded
automatically when present, even without `--config`).

```toml
[defaults]
# Any long option name (with dashes as underscores) is accepted here,
# including the target and output destinations.
url = "http://target/include.php?file=test.txt"
concurrency = 8
verbose = true
automatic = true
all_versions = true
output_format = "json"
output_file = "results.json"
log_file = "scan.log"
resume_file = "scan.checkpoint"

[proxy]
url = "socks5://127.0.0.1:9050"

[headers]
user_agent = "Mozilla/5.0"
cookie = "sid=foobar; auth=1"
values = ["X-Forwarded-For: 127.0.0.1"]
```

Priority: **CLI args > config file > built-in defaults.**

### Config-supported target and output options

The `[defaults]` table accepts any scan option, not just performance
tuning. In particular you can persist:

* `url` — the default target (override per-run with `--url`)
* `output_format`, `output_file` — where machine-readable results go
* `log_file` — mirror console output to a file
* `resume_file` — checkpoint location for resumable scans

Sensitive artifacts written by Panoptic — the log file, the results/list
output file, and any files saved with `--write-files` — are forced to
owner-only `0600` permissions on POSIX. Platforms exposing `O_NOFOLLOW`
also atomically refuse a pre-existing symlink at the final path component.
On platforms without `O_NOFOLLOW`, Panoptic performs a best-effort
pre-open symlink/junction check, but the check cannot eliminate a race.
Windows mode bits do not configure NTFS ACLs, so use an appropriately
restricted directory when artifacts may contain sensitive data.

### Overriding config booleans on the command line

Every boolean flag has a `--no-` counterpart, so a value set to `true`
in the config file can be turned off for a single run without editing
the file:

```bash
# config.toml sets verbose = true and automatic = true
panoptic --url "http://target/x.php?file=test.txt" --no-verbose --no-auto
```

Because an omitted boolean flag is left unset (rather than defaulting to
`false`), the config value is used unless you pass the flag or its
`--no-` form explicitly.

## Proxying

Route traffic through an HTTP(S) or SOCKS proxy:

```bash
panoptic --url "https://target/x.php?file=test.txt" \
  --proxy "socks5://127.0.0.1:9050"
```

* Accepted schemes: `http://`, `https://`, `socks5://`, `socks5h://`
  (`socks5h` resolves DNS through the proxy — useful for Tor and to
  avoid local DNS leaks). SOCKS4 is not supported by the underlying
  HTTP client. The scheme and host are validated before the scan starts.
* SOCKS support comes from the `httpx[socks]` extra, which is installed
  by default.
* By default Panoptic honours the standard `HTTP_PROXY` / `HTTPS_PROXY` /
  `NO_PROXY` environment variables. Pass `--ignore-proxy` to bypass them
  and connect directly (this also disables any env-configured proxy).
* Combine with `--invalid-ssl` when intercepting HTTPS through a proxy
  with its own CA. This disables certificate verification and is unsafe
  on untrusted networks.

## Version Expansion (`--all-versions`)

Some bundled paths are version templates (for example JBoss release
directories written as `[JBOSS]`). By default these template rows are
skipped, because a literal `[JBOSS]` path can never match a real file.
Passing `--all-versions` expands each template against the bundled
version list, adding one concrete path per known version — a much larger
but far more thorough scan:

```bash
panoptic --url "http://target/x.php?file=test.txt" --auto --all-versions
```

## Response Comparison

Panoptic does not classify a path from the target-controlled
`Content-Length` header alone. It compares the complete normalized body
against the invalid-path baseline. A cheap similarity upper bound avoids
the full comparison only when it can already prove the bodies differ;
ambiguous responses use the exact ratio to avoid reordered-body false
negatives.

## Resume / Checkpoints

`--resume-file PATH` records completed cases so an interrupted scan can
continue where it left off:

```bash
panoptic --url "http://target/x.php?file=test.txt" \
  --resume-file scan.checkpoint
# ... interrupt with Ctrl-C, then re-run the same command to resume
```

The checkpoint stores only completed case IDs plus a SHA-256
**fingerprint** of the scan definition (URL, injection parameters,
detection options, headers, cookie, User-Agent, and the exact case set).
It never stores credentials, headers, or URLs in plaintext.

On resume, the fingerprint is recomputed and compared. If anything that
would change the meaning of the scan differs — a different target,
parameter, header, cookie, filter set, or `--all-versions` toggle — the
checkpoint is rejected with a warning and the scan starts fresh, so a
stale checkpoint can never silently skip cases from a different scan.
Legacy bare-list checkpoints are accepted with a warning and restricted
to case IDs present in the current scan; because that old format has no
fingerprint, users should replace it with the newly written format.
Failed (network-error) requests are deliberately **not** checkpointed so
they are retried on resume.

## Version and Update

```bash
panoptic --version   # print the installed version and exit
panoptic --update    # fast-forward update from the official GitHub repo
```

`--update` only works from a git checkout whose `origin` remote uses
HTTPS or SSH and matches the official upstream (verified before pulling,
to resist insecure or tampered remote configuration). It fast-forwards
the checked-out `main` branch from the explicit upstream `main` ref; for
pip installs it prints the correct
`pip install -U` command instead. When run from a checkout, the banner
also shows the current short git revision.

## Exit Codes

Panoptic uses conventional process exit codes so it can be scripted:

* `0` — Success: the scan (or `--list` / `--update`) completed. Individual
  requests that exhaust their retries are warned about and remain eligible
  for a resumed scan, but do not fail an otherwise successful run.
* `1` — Invalid usage: missing or invalid arguments, or no injectable
  parameter could be found.
* `2` — Operational failure: cannot connect, no matching test cases, all
  queued requests failed, or a worker, checkpoint, output write, or
  configuration failed.
* `130` — Interrupted by the user (Ctrl-C / SIGINT).

## Contributing

Contributions are welcome! Please open issues or pull requests on
[GitHub](https://github.com/lightos/Panoptic).

## Testbed

For safe, reproducible end-to-end testing, see the
[Panoptic LFI Testbed](https://github.com/lightos/panoptic-lfi-testbed).
It provides deliberately vulnerable endpoints covering Panoptic's supported
injection methods and traversal transformations.

## License

This project is licensed under the MIT License - see the
[LICENSE](LICENSE) file for details.
