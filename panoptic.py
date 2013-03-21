#!/usr/bin/env python

"""
Panoptic:
Search default file locations for logs and config files.
"""

import re

from urllib import urlencode
from urllib2 import urlopen, Request
from urlparse import urlsplit, parse_qsl
from sys import argv, exit

NAME = "Panoptic"
VERSION = "v0.1"
URL = "https://github.com/lightos/Panoptic/"

class Panoptic:
    """
    Contains all the functionality to run panoptic.
    """
    def __init__(self):
        """
        Initiates the Panoptic object.
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
        Returns available types of categories, software or operating systems.
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
            if not file_location: continue
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
        Parses the file locations list.
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
                #HANDLE HOST/DOMAIN replacement
                continue
            
            if self.args.has_key("software"):
                if self.software.lower() != self.args["software"].lower():
                    continue
            if self.args.has_key("category"):
                if self.category.lower() != self.args["category"].lower():
                    continue
            if self.args.has_key("type"):
                if self.classification.lower() not in [self.args["classification"].lower(), "other"]:
                    continue
            if self.args.has_key("os"):
                if self.operating_system.lower() != self.args["os"].lower():
                    continue

            self.file_attributes["location"] = file_location
            self.file_attributes["software"] = self.software
            self.file_attributes["category"] = self.category
            self.file_attributes["classification"] = self.classification
            
            yield self.file_attributes
    
    def get_args(self):
        """
        Parse command line arguements.
        """
        args = {}
        if len(argv) < 2:
            exit()
        if "--help" in argv:
            help()
        if "--list" in argv:
            if len(argv)-1 < argv.index("--list") + 1:
                print("[!] Missing argument for --list")
                exit()
            self.list_items(argv[argv.index("--list") + 1])
        if "--os" in argv:
            if len(argv)-1 < argv.index("--os") + 1:
                print("[!] Missing argument for --os")
                exit()
            args["os"] = argv[argv.index("--os") + 1]
        if "--target" in argv:
            if len(argv)-1 < argv.index("--target") + 1:
                print("[!] Missing argument for --target")
                exit()
            args["target"] = argv[argv.index("--target") + 1]
        else:
            help()
        if "--param" in argv:
            if len(argv)-1 < argv.index("--param") + 1:
                print("[!] Missing argument for --param")
                exit()
            args["param"] = argv[argv.index("--param") + 1]
        if "--user-agent" in argv:
            args["user-agent"] = "gotta get a random UA here"
        if "--software" in argv:
            if len(argv)-1 < argv.index("--software") + 1:
                print("[!] Missing argument for --software")
                exit()
            args["software"] = argv[argv.index("--software") + 1]
        if "--category" in argv:
            if len(argv)-1 < argv.index("--category") + 1:
                print("[!] Missing argument for --category")
                exit()
            args["category"] = argv[argv.index("--category") + 1]
            
        self.args = args
    
class Connect:
    """
    Handles all requests to web site.
    """
    
    @staticmethod
    def get_page(**kwargs):
        """
        This method retrieves the URL
        """
        url = kwargs.get("target", None)
        post = kwargs.get("data", None)
        header = kwargs.get("header", None)
        cookie = kwargs.get("cookie", None)
        proxy = kwargs.get("proxy", False)
        user_agent = kwargs.get("user_agent", None)

        if url is None:
            raise Exception("URL cannot be None.")

        try:
            parsed_url = urlsplit(url)
        except:
            raise Exception("unable to parse URL: %s" % url)

        if proxy:
            import socks
            import socket

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
            post = urlencode(post, "POST")

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
                print "failed to reach the server."
                raise Exception(str(e.reason).lower())

            if e.code == 401:
                exception_msg = "not authorized, try to provide right HTTP "
                exception_msg += "authentication type and valid credentials"
                raise Exception("%s - %s\n%s" % (exception_msg, url, str(parsed_url)))

            elif e.code == 404:
                exception_msg = "page not found"
                raise Exception("%s - %s\n%s" % (exception_msg, url, str(parsed_url)))

            else:
                page = e.read()
                code = e.code
                status = e.msg
                responseHeaders = e.info()
                print("HTTP error code: %d" % code)
        
        return page, parsed_url

def main():
    """
    Initialize the execution of the program.
    """
    banner()
    dfl = Panoptic()
    dfl.get_args()
    parsed_url = urlsplit(dfl.args["target"])
    dfl.invalid_response, _ = Connect().get_page(**{
                                    "target": "%s://%s%s?%s" % 
                                    (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                     re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % dfl.args["param"],
                                     r"\1=%s" % "non_existing_file.panoptic", parsed_url.query))
                                    })
    for file in dfl.parse_file():
        html, _ = Connect().get_page(**{
                                        "target": "%s://%s%s?%s" % 
                                        (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                         re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % dfl.args["param"],
                                         r"\1=%s" % file['location'], parsed_url.query))
                                        })
        
        if html != dfl.invalid_response:
            if not dfl.file_found:
                dfl.file_found = True
                print("Possible file(s) found!")
                if dfl.operating_system:
                    print("OS: %s\n" % dfl.operating_system)
            print("[+] File: %s" % dfl.file_attributes)
            
    if not dfl.file_found:
        print("No files found!")

def help():
    """
    Prints help menu.
    """
    print("""== help menu ==
    
--target{:>14}set the target to test.
--param{:>15}set the parameter to test.
--os{:>18}set a specific operating system to limit searches.
--software{:>12}set the name of the software to search for.
--category{:>12}set a specific category of software to look for.
--type{:>16}set the type of file to search for (conf or log).
--list{:>16}list the available types of categories, software or operating systems.
--help{:>16}print this menu.
""").format(" ", " ", " ", " ", " ", " ", " ", " ")

    exit()

def banner():
    """
    Prints banner.
    
    ASCII eye taken from http://www.retrojunkie.com/asciiart/health/eyes.htm
    """
    print("""
 .-',--.`-.
<_ | () | _>
  `-`=='-'

%s %s
%s
""") % (NAME, VERSION, URL)

if __name__ == "__main__": main()
