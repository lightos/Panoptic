Panoptic
===

![Logo](http://i.imgur.com/PPGy8UE.jpg)

Panoptic is an open source penetration testing tool that automates the process of search and retrieval of content for common log and config files through path traversal vulnerability. Official introductionary post can be found [here](http://websec.ca/blog/view/panoptic). Also, you can find a sample run [here](https://gist.github.com/stamparm/5335273).

## Features

* Automatic discovery of common log and configuration files
* Support for both parameter-based and path-based Local File Inclusion (LFI)
* Extension parameter handling for scenarios where filename and extension are separate parameters
* Multi-threaded scanning for faster results
* Comprehensive built-in testing library with categorization by OS and software
* Multiple traversal bypass techniques including custom prefixes/postfixes and slash character replacement
* SOCKS4/SOCKS5 proxy support with connection testing
* Parse passwd files to enumerate users and access their home directories
* Detailed filtering options by OS, software type, and category

## Requirements
* Python 3.x

## Help Menu
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
      --through             test all versions of files (may significantly increase scan time)
      --ext-param=PARAM     name of parameter containing file extension (e.g. "type")
      --update              update Panoptic from official repository

## Examples
    # Basic parameter-based LFI testing
    ./panoptic.py --url "http://localhost/include.php?file=test.txt"
    ./panoptic.py --url "http://localhost/include.php?file=test.txt&id=1" --param file
    ./panoptic.py --url "http://localhost/include.php" --data "file=test.txt&id=1" --param file
    
    # Path-based LFI testing
    ./panoptic.py --url "http://localhost/files/view/test.txt" --path-based --prefix "../"
    
    # Extension parameter testing (for URLs that separate filename and extension)
    ./panoptic.py --url "http://localhost/param.php?file=test&type=txt" --param file --ext-param type
    
    # Comprehensive scanning with 'through' option
    ./panoptic.py --url "http://localhost/include.php?file=test.txt" --auto --through
    
    # Filter listings
    ./panoptic.py --list software
    ./panoptic.py --list category
    ./panoptic.py --list os
    
    # Filtered scans
    ./panoptic.py -u "http://localhost/include.php?file=test.txt" --os "*NIX"
    ./panoptic.py -u "http://localhost/include.php?file=test.txt" --software WAMP
    
    # Proxy usage with SSL errors ignored
    ./panoptic.py -u "https://localhost/include.php?file=test.txt" --proxy "socks5://127.0.0.1:9050" --invalid-ssl

