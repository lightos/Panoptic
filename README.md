Panoptic
===

![Panoptic Logo](https://i.imgur.com/nQrtLkO.png)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Python Versions](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)

Panoptic is an open source penetration testing tool that automates the process of search and retrieval of content for common log and config files through path traversal vulnerability. Official introductory post can be found [here](http://websec.ca/blog/view/panoptic).

## Features

* **Async concurrent scanning** with configurable worker pool (`--concurrency`)
* Automatic discovery of common log and configuration files via parameter-based, path-based, POST, cookie, header, and JSON body injection
* **FUZZ marker** for arbitrary injection points — place `FUZZ` in any `--header` or `--data` value
* **Base64 encoding** for endpoints that decode file paths (`--base64`)
* Automatic OS detection with option to restrict further scans
* Heuristic response comparison with status code filtering to reduce false positives
* Dynamic case injection — parse `/etc/passwd` for home directory files, `mysql-bin.index` for binlog files
* **Multiple output formats**: text (rich), JSON, CSV (`--output-format`)
* **Resume/checkpoint** support for long-running scans (`--resume-file`)
* **TOML config files** for persistent settings (`--config`)
* Multiple traversal bypass techniques: prefixes, postfixes, multiplier, slash replacement, double encoding
* HTTP/HTTPS and SOCKS4/SOCKS5 proxy support with validation
* Random or custom User-Agent, cookie, and header support
* Credential redaction in banner and log output
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
panoptic --url "http://target/include.php?file=test.txt&id=1" --param file
```

### POST data injection
```bash
panoptic --url "http://target/include.php" --data "file=test.txt&id=1" --param file
```

### Path-based LFI
```bash
panoptic --url "http://target/view.php/test.txt" --path-based
```

### Base64-encoded parameter
```bash
panoptic --url "http://target/load.php?file=dGVzdC50eHQ=" --base64 --auto
```

### Cookie injection (FUZZ marker)
```bash
panoptic --url "http://target/page.php" --header "Cookie: lang=FUZZ" --auto
```

### JSON body injection (FUZZ marker)
```bash
panoptic --url "http://target/api/load" --data '{"file":"FUZZ"}' --auto
```

### Custom header injection (FUZZ marker)
```bash
panoptic --url "http://target/page.php" --header "X-Template: FUZZ" --auto
```

### Extension parameter
```bash
panoptic --url "http://target/view.php?file=test&type=txt" --param file --ext-param type
```

### Filter bypass with prefix
```bash
panoptic --url "http://target/filtered.php?file=test.txt" --prefix "....//....//....//....//"
```

### Filtered scans
```bash
panoptic --url "http://target/include.php?file=test.txt" --os "*NIX" --type conf
panoptic --url "http://target/include.php?file=test.txt" --software PostgreSQL
```

### JSON output with resume support
```bash
panoptic --url "http://target/include.php?file=test.txt" --output-format json --output-file results.json --resume-file scan.checkpoint
```

### Proxy with SSL errors ignored
```bash
panoptic --url "https://target/include.php?file=test.txt" --proxy "socks5://127.0.0.1:9050" --invalid-ssl
```

### List available filters
```bash
panoptic --list software
panoptic --list category
panoptic --list os
```

### Comprehensive scan
```bash
panoptic --url "http://target/include.php?file=test.txt" --auto --all-versions --concurrency 8
```

## FUZZ Marker

Place `FUZZ` anywhere in `--header` or `--data` values to mark the injection point. Panoptic replaces `FUZZ` with each file path during scanning. This enables testing injection points that `--param` can't reach:

| Injection Type | Example |
|---------------|---------|
| Cookie value | `--header "Cookie: theme=FUZZ"` |
| Custom header | `--header "X-Include: FUZZ"` |
| JSON body | `--data '{"template":"FUZZ"}'` |
| Nested value | `--header "Cookie: sid=abc; lang=FUZZ"` |

When `FUZZ` is present, `--param` is not required.

## Configuration

Panoptic supports TOML config files for persistent settings:

```bash
panoptic --url "http://target/include.php?file=test.txt" --config ~/.config/panoptic/config.toml
```

Default config location: `~/.config/panoptic/config.toml`

```toml
[defaults]
concurrency = 8
verbose = true
automatic = true

[proxy]
url = "socks5://127.0.0.1:9050"

[headers]
user_agent = "Mozilla/5.0"
```

Priority: CLI args > config file > built-in defaults.

## Contributing

Contributions are welcome! Please open issues or pull requests on GitHub:
https://github.com/lightos/Panoptic

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
