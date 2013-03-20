#!/usr/bin/env python

"""
Search default file locations for logs and config files.
"""

import re

from urllib import urlencode
from urllib2 import urlopen, Request
from urlparse import urlsplit, parse_qsl
from sys import argv, exit

NAME = "Panoptic"
VERSION = "v0.1"

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
        
    def parse_file(self):
        """
        Main function for panoptic.
        """    
        for file_location in open("file_locations.txt"):
            file_location = file_location.rstrip()
            if not file_location:
                continue
            elif file_location[0] == "[":
                self.category = file_location[1:-1]
                continue
            elif file_location[0] == "(":
                self.operating_system = file_location[1:-1]
                continue
            elif file_location[0] == "#":
                self.software = file_location[1:]
                continue
            elif file_location[0] == "*":
                self.classification = file_location[1:]
                continue
            elif file_location[0] == r"\n":
                self.software = ""
                self.classification = ""
                self.file_attributes = {}
                continue
            elif file_location.find("{") != -1:
                #HANDLE HOST/DOMAIN replacement
                continue
            
            self.file_attributes["location"] = file_location
            self.file_attributes["software"] = self.software
            self.file_attributes["category"] = self.category
            self.file_attributes["classification"] = self.classification
            
            yield self.file_attributes
    
    @staticmethod
    def get_args():
        """
        Parse command line arguements.
        """
        args = {}
        if len(argv) < 2:
            exit()
        if "--help" in argv:
            help()
        if "--os" in argv:
            args["os"] = argv[argv.index("--os") + 1]
        if "--target" in argv:
            args["target"] = argv[argv.index("--target") + 1]
        else:
            help()
        if "--param" in argv:
            args["param"] = argv[argv.index("--param") + 1]
        if "--user-agent" in argv:
            args["user-agent"] = "gotta get a random UA here"
            
        return args        
    
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

            return page, parsed_url

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
    args = dfl.get_args()
    parsed_url = urlsplit(args["target"])
    dfl.invalid_response, _ = Connect().get_page(**{
                                    "target": "%s://%s%s?%s" % 
                                    (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                     re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % args["param"],
                                     r"\1=%s" % "non_existing_file.panoptic", parsed_url.query))
                                    })
    for file in dfl.parse_file():
        html, _ = Connect().get_page(**{
                                        "target": "%s://%s%s?%s" % 
                                        (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                         re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % args["param"],
                                         r"\1=%s" % file['location'], parsed_url.query))
                                        })
        
        if html != dfl.invalid_response:
            if not dfl.file_found:
                print("Possible file(s) found!")
                if dfl.operating_system:
                    print("OS: %s\n" % dfl.operating_system)
                    dfl.file_found = True
            print("File: %s" % dfl.file_attributes)

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
--help{:>16}print this menu.
""").format(" ", " ", " ", " ", " ", " ")

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
""") % (NAME, VERSION)

if __name__ == "__main__": main()
