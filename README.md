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
* Random or custom User-Agent support (`--random-agent`, `--user-agent`)
* Heuristic response comparison to skip invalid paths and reduce false positives
* Parse `/etc/passwd` to enumerate users and retrieve home directory files
* Save discovered files to a local output directory (`--write-files`)
* Auto-update Panoptic to the latest version from the official repository (`--update`)

## Requirements
* Python 3.x
* The script uses the `python3` shebang. You can run it directly with `./panoptic.py` (after `chmod +x panoptic.py`) or explicitly with `python3 panoptic.py`. If your system's `python` points to Python 3, you may use `python` instead.

## Installation / Quick Start
Clone the repository and make the script executable:
```bash
git clone https://github.com/lightos/Panoptic.git
cd Panoptic
chmod +x panoptic.py
```
Then run the tool:
```bash
./panoptic.py --url "http://localhost/include.php?file=test.txt"
```

## Usage
Use these common invocation patterns:
```bash
# Basic LFI testing
./panoptic.py --url "http://localhost/include.php?file=test.txt"

# Filter scans
./panoptic.py --url "http://localhost/include.php?file=test.txt" --os "*NIX" --type conf
```

## Help Menu
```text
Usage: panoptic.py --url TARGET [options]

Options:
  -h/--help             show this help message and exit
  -v/--verbose          display extra output information
  -u/--url=URL          set target URL
  -p/--param=PARAM      set parameter name to test for (e.g. "page")
  -d/--data=DATA        set data for HTTP POST request (e.g. "page=default")
  -t/--type=TYPE        set type of file to look for ("conf" or "log")
  -o/--os=OS            set filter name for OS (e.g. "*NIX")
  -s/--software=SOFT..  set filter name for software (e.g. "PHP")
  -c/--category=CATE..  set filter name for category (e.g. "FTP")
  -l/--list=GROUP       list available filters for group (e.g. "software")
  -a/--auto             avoid user interaction by using default options
  -w/--write-files      write content of retrieved files to output folder
  -x/--skip-parsing     skip special tests if *NIX passwd file is found
  -P/--path-based       target file paths directly instead of using query parameters
  -i/--invalid-ssl      ignore SSL certificate validation errors
  --load=LISTFILE       load and try user provided list from a file
  --ignore-proxy        ignore system default HTTP proxy
  --proxy=PROXY         set proxy (e.g. "socks5://192.168.5.92")
  --user-agent=UA       set HTTP User-Agent header value
  --random-agent        choose random HTTP User-Agent header value
  --cookie=COOKIE       set HTTP Cookie header value (e.g. "sid=foobar")
  --header=HEADER       set a custom HTTP header (e.g. "Max-Forwards=10")
  --prefix=PREFIX       set prefix for file path (e.g. "../")
  --postfix=POSTFIX     set postfix for file path (e.g. "%00")
  --multiplier=MULTI..  set multiplication number for prefix (default: 1)
  --bad-string=STRING   set a string occurring when file is not found
  --replace-slash=RE..  set replacement for char / in paths (e.g. "/././")
  --threads=THREADS     set number of threads (default: 1)
  --all-versions        test all versioned file paths (may significantly increase scan time)
  --ext-param=PARAM     name of parameter containing file extension (e.g. "type")
  --update              update Panoptic from official repository
  --list-all-files      list all file paths in the XML and exit
```

## Examples

### Basic parameter-based LFI testing
```bash
./panoptic.py --url "http://localhost/include.php?file=test.txt"
./panoptic.py --url "http://localhost/include.php?file=test.txt&id=1" --param file
./panoptic.py --url "http://localhost/include.php" --data "file=test.txt&id=1" --param file
```

### Path-based LFI testing
```bash
./panoptic.py --url "http://localhost/files/view/test.txt" --path-based --prefix "../"
```

### Extension parameter testing
```bash
./panoptic.py --url "http://localhost/param.php?file=test&type=txt" --param file --ext-param type
```

### Comprehensive scanning with all-versions option
```bash
./panoptic.py --url "http://localhost/include.php?file=test.txt" --auto --all-versions
```

### Filter listings
```bash
./panoptic.py --list software
./panoptic.py --list category
./panoptic.py --list os
```

### Filtered scans
```bash
./panoptic.py -u "http://localhost/include.php?file=test.txt" --os "Windows"
./panoptic.py -u "http://localhost/include.php?file=test.txt" --software PostgreSQL
```

### Proxy usage with SSL errors ignored
```bash
./panoptic.py -u "https://localhost/include.php?file=test.txt" --proxy "socks5://127.0.0.1:9050" --invalid-ssl
```

## Contributing
Contributions are welcome! Please open issues or pull requests on GitHub:
https://github.com/lightos/Panoptic

## License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

