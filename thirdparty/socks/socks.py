#!/usr/bin/env python3

"""PySocks - Updated SocksiPy for Python 3.

This is a modernized version of SocksiPy for use with Python 3,
based on PySocks (https://github.com/Anorov/PySocks).

Implements SOCKS4, SOCKS4A, and SOCKS5 proxies.
"""

import socket
import struct
import ipaddress
import io
import os
import sys
from errno import EALREADY, EINPROGRESS, EWOULDBLOCK, EAGAIN

__version__ = "1.7.1"

PROXY_TYPE_SOCKS4 = 1
PROXY_TYPE_SOCKS5 = 2
PROXY_TYPE_HTTP = 3

_defaultproxy = None
_orig_socket = socket.socket


class ProxyError(IOError):
    """Base class for all proxy-related errors."""
    pass


class GeneralProxyError(ProxyError):
    """General proxy error."""
    pass


class ProxyConnectionError(ProxyError):
    """Connection error."""
    pass


class SOCKS5AuthError(ProxyError):
    """SOCKS5 authentication error."""
    pass


class SOCKS5Error(ProxyError):
    """SOCKS5 error."""
    pass


class SOCKS4Error(ProxyError):
    """SOCKS4 error."""
    pass


class HTTPError(ProxyError):
    """HTTP proxy error."""
    pass


_generalerrors = {
    1: "General SOCKS server failure",
    2: "Connection not allowed by ruleset",
    3: "Network unreachable",
    4: "Host unreachable",
    5: "Connection refused",
    6: "TTL expired",
    7: "Command not supported",
    8: "Address type not supported",
    9: "Unknown error",
}

_socks5errors = {
    0x01: "General SOCKS server failure",
    0x02: "Connection not allowed by ruleset",
    0x03: "Network unreachable",
    0x04: "Host unreachable",
    0x05: "Connection refused",
    0x06: "TTL expired",
    0x07: "Command not supported",
    0x08: "Address type not supported",
    0x09: "Unknown error",
}

_socks5autherrors = {
    0x01: "Authentication is required",
    0x02: "All offered authentication methods were rejected",
    0x03: "Unknown username or invalid password",
    0x04: "Unknown error",
}

_socks4errors = {
    0x5B: "Request rejected or failed",
    0x5C: "Request rejected because SOCKS server cannot connect to identd on the client",
    0x5D: "Request rejected because the client program and identd report different user-ids",
}


def setdefaultproxy(proxytype=None, addr=None, port=None, rdns=True, username=None, password=None):
    """Sets a default proxy.

    All further socksocket objects will use the default unless explicitly
    changed.
    """
    global _defaultproxy
    _defaultproxy = (proxytype, addr, port, rdns, username, password)


def get_proxy_settings():
    """Get system proxy settings.

    Returns:
        A proxies dict suitable for use with requests.
    """
    proxies = {}
    for proto in ['http', 'https']:
        for varname in [proto + '_proxy', proto.upper() + '_PROXY']:
            if varname in os.environ:
                proxies[proto] = os.environ[varname]
                break
    return proxies


class socksocket(socket.socket):
    """socksocket([family[, type[, proto]]]) -> socket object

    Open a SOCKS enabled socket. The parameters are the same as
    those of the standard socket init. In order for SOCKS to work,
    you must specify family=AF_INET, type=SOCK_STREAM and proto=0.
    """

    def __init__(self, family=socket.AF_INET, type=socket.SOCK_STREAM, proto=0, *args, **kwargs):
        if type != socket.SOCK_STREAM:
            msg = "Socket type must be stream oriented (SOCK_STREAM)"
            raise ValueError(msg)

        _orig_socket.__init__(self, family, type, proto, *args, **kwargs)
        
        self._proxyconn = None  # TCP connection to keep track of proxy connection
        
        if _defaultproxy:
            self.proxy = _defaultproxy
        else:
            self.proxy = (None, None, None, None, None, None)
        
        self._proxysockname = None
        self._proxypeername = None
        self._timeout = None

    def settimeout(self, timeout):
        self._timeout = timeout
        if self._proxyconn:
            self._proxyconn.settimeout(timeout)
        return super().settimeout(timeout)

    def _recvall(self, count):
        """Receive exactly specified number of bytes from the socket."""
        data = b""
        while len(data) < count:
            d = self.recv(count - len(data))
            if not d:
                raise GeneralProxyError("Connection closed unexpectedly")
            data += d
        return data

    def setproxy(self, proxytype=None, addr=None, port=None, rdns=True, username=None, password=None):
        """Set the proxy to be used.

        proxytype -  The type of the proxy to be used. Three types
                    are supported: PROXY_TYPE_SOCKS4 (including SOCKS4A),
                    PROXY_TYPE_SOCKS5 and PROXY_TYPE_HTTP
        addr -      The address of the server (IP or DNS).
        port -      The port of the server. Defaults to 1080 for SOCKS
                    servers and 8080 for HTTP proxy servers.
        rdns -      Should DNS queries be performed on the remote side
                    (rather than the local side). The default is True.
                    Note: This has no effect with SOCKS4 servers.
        username -  Username to authenticate with to the server.
                    The default is no authentication.
        password -  Password to authenticate with to the server.
                    Only relevant when username is also provided.
        """
        self.proxy = (proxytype, addr, port, rdns, username, password)

    def _negotiate_SOCKS5(self, dest_addr, dest_port):
        """Negotiates a connection through a SOCKS5 server."""
        proxy_type, addr, port, rdns, username, password = self.proxy
        
        if not port:
            port = 1080
            
        # First we'll send the authentication packages we support.
        if username and password:
            # The username/password details were supplied to setproxy
            # so we support the USERNAME/PASSWORD authentication
            # (in addition to the standard none).
            self.sendall(b"\x05\x02\x00\x02")
        else:
            # No username/password were entered, therefore we
            # only support connections with no authentication.
            self.sendall(b"\x05\x01\x00")
            
        # We'll receive the server's response to determine which
        # method was selected
        chosen_auth = self._recvall(2)
        
        if chosen_auth[0:1] != b"\x05":
            raise GeneralProxyError("SOCKS5 proxy server sent invalid data")
            
        # Check the chosen authentication method
        if chosen_auth[1:2] == b"\x02":
            # Server selected username/password authentication
            if not username or not password:
                raise GeneralProxyError("No username/password supplied, but server requested username/password authentication")
                
            self.sendall(b"\x01" + chr(len(username)).encode() + 
                        username.encode() + 
                        chr(len(password)).encode() + 
                        password.encode())
            auth_status = self._recvall(2)
            
            if auth_status[0:1] != b"\x01":
                raise GeneralProxyError("SOCKS5 proxy server sent invalid data")
                
            if auth_status[1:2] != b"\x00":
                raise SOCKS5AuthError("SOCKS5 authentication failed")
        elif chosen_auth[1:2] != b"\x00":
            raise SOCKS5AuthError("Unsupported authentication method")
            
        # Now we can request the actual connection
        req = b"\x05\x01\x00"
        
        # If the given destination address is an IP address, we'll
        # use the IPv4 address request even if remote resolving was specified.
        try:
            ipaddr = socket.inet_aton(dest_addr)
            req += b"\x01" + ipaddr
        except socket.error:
            # It's a DNS name.
            if rdns:
                # Resolve remotely
                req += b"\x03" + chr(len(dest_addr)).encode() + dest_addr.encode()
            else:
                # Resolve locally
                addr_bytes = None
                try:
                    addr_bytes = socket.inet_aton(socket.gethostbyname(dest_addr))
                except socket.gaierror:
                    addr_bytes = socket.inet_aton("0.0.0.0")
                req += b"\x01" + addr_bytes
                
        req += struct.pack(">H", dest_port)
        self.sendall(req)
        
        # Get the response
        resp = self._recvall(4)
        if resp[0:1] != b"\x05":
            raise GeneralProxyError("SOCKS5 proxy server sent invalid data")
            
        if resp[1:2] != b"\x00":
            # Connection failed
            if resp[1] <= 8:
                raise SOCKS5Error("SOCKS5 server error: {}".format(_socks5errors.get(resp[1], "Unknown error")))
            else:
                raise SOCKS5Error("SOCKS5 server error: Unknown error")
                
        # Get the bound address/port
        if resp[3:4] == b"\x01":
            bound_addr = self._recvall(4)
        elif resp[3:4] == b"\x03":
            resp = resp + self._recvall(1)
            bound_addr = self._recvall(ord(resp[4:5]))
        else:
            raise GeneralProxyError("SOCKS5 proxy server sent invalid data")
            
        bound_port = struct.unpack(">H", self._recvall(2))[0]
        
        self._proxysockname = (bound_addr, bound_port)
        if bound_addr == b"\x00\x00\x00\x00":
            bound_addr = "0.0.0.0"
        else:
            bound_addr = socket.inet_ntoa(bound_addr)
        self._proxysockname = (bound_addr, bound_port)
        
        if dest_addr == "0.0.0.0" and dest_port == 0:
            # Return the bound address as the required address for connect
            return (bound_addr, bound_port)
        else:
            self._proxypeername = (dest_addr, dest_port)
            
    def _negotiate_SOCKS4(self, dest_addr, dest_port):
        """Negotiates a connection through a SOCKS4 server."""
        proxy_type, addr, port, rdns, username, password = self.proxy
        
        if not port:
            port = 1080
            
        # Resolve the destination address for SOCKS4 request
        remote_resolve = False
        try:
            addr_bytes = socket.inet_aton(dest_addr)
        except socket.error:
            # It's a DNS name. Check where it should be resolved.
            if rdns:
                addr_bytes = b"\x00\x00\x00\x01"
                remote_resolve = True
            else:
                addr_bytes = socket.inet_aton(socket.gethostbyname(dest_addr))
                
        # Construct the request packet
        req = struct.pack(">BBH", 0x04, 0x01, dest_port) + addr_bytes
        
        # The username parameter is considered userid for SOCKS4
        if username:
            req += username.encode()
        req += b"\x00"
        
        # DNS name if remote resolving is required
        # NOTE: This is actually an extension to the SOCKS4 protocol
        # called SOCKS4A and may not be supported in all cases.
        if remote_resolve:
            req += dest_addr.encode() + b"\x00"
            
        self.sendall(req)
        
        # Get the response from the server
        resp = self._recvall(8)
        if resp[0:1] != b"\x00":
            # Bad data
            raise GeneralProxyError("SOCKS4 proxy server sent invalid data")
            
        if resp[1:2] != b"\x5A":
            # Server returned an error
            status = ord(resp[1:2])
            if status in (91, 92, 93):
                raise SOCKS4Error("SOCKS4 server error: {}".format(_socks4errors.get(status, "Unknown error")))
            else:
                raise SOCKS4Error("SOCKS4 server error: Unknown error")
                
        # Get the bound address/port
        bound_addr = socket.inet_ntoa(resp[4:8])
        bound_port = struct.unpack(">H", resp[2:4])[0]
        self._proxysockname = (bound_addr, bound_port)
        
        # If the requested address was a DNS name and we were configured to
        # resolve it remotely, we need to return the resolved IP
        if remote_resolve:
            # Returned IP if host was resolved remotely
            self._proxypeername = (socket.inet_ntoa(addr_bytes), dest_port)
        else:
            self._proxypeername = (dest_addr, dest_port)
            
    def _negotiate_HTTP(self, dest_addr, dest_port):
        """Negotiates a connection through an HTTP proxy server."""
        proxy_type, addr, port, rdns, username, password = self.proxy
        
        if not port:
            port = 8080
            
        # If we need to resolve locally, we do this now
        if not rdns:
            dest_addr = socket.gethostbyname(dest_addr)
            
        # Construct the HTTP CONNECT request
        connect_str = "CONNECT {}:{} HTTP/1.1\r\n".format(dest_addr, dest_port)
        
        # If the proxy requires authentication, add the headers
        if username and password:
            # The username & password need to be base64 encoded
            import base64
            auth = "{}:{}".format(username, password)
            auth = "Basic " + base64.b64encode(auth.encode()).decode()
            connect_str += "Proxy-Authorization: {}\r\n".format(auth)
            
        connect_str += "Host: {}:{}\r\n".format(dest_addr, dest_port)
        connect_str += "Connection: keep-alive\r\n\r\n"
        
        self.sendall(connect_str.encode())
        
        # We read the response until we get a blank line
        resp = b""
        while True:
            chunk = self.recv(1)
            resp += chunk
            if resp.endswith(b"\r\n\r\n"):
                break
                
        # Parse the response status line
        line = resp.split(b"\r\n")[0].decode()
        status_line = line.split(" ", 2)
        
        if not status_line[0].startswith("HTTP/"):
            raise GeneralProxyError("Proxy server does not appear to be an HTTP proxy")
            
        try:
            status_code = int(status_line[1])
        except ValueError:
            raise GeneralProxyError("HTTP proxy server sent invalid response")
            
        if status_code != 200:
            error = "HTTP proxy server response: {}".format(status_line[2] if len(status_line) > 2 else "Unknown error")
            raise HTTPError(error)
            
        self._proxysockname = ("0.0.0.0", 0)
        self._proxypeername = (dest_addr, dest_port)
        
    def connect(self, dest_pair, catch_errors=True):
        """connect(self, despair)
        Connects to the specified destination through a proxy.
        dest_pair - A tuple of (addr, port) for the desired destination.
        """
        if len(dest_pair) != 2 or not isinstance(dest_pair[0], str):
            raise GeneralProxyError("Invalid destination address format")
            
        if self.proxy[0] == PROXY_TYPE_SOCKS5:
            if self._negotiate_SOCKS5(dest_pair[0], dest_pair[1]):
                return True
        elif self.proxy[0] == PROXY_TYPE_SOCKS4:
            if self._negotiate_SOCKS4(dest_pair[0], dest_pair[1]):
                return True
        elif self.proxy[0] == PROXY_TYPE_HTTP:
            if self._negotiate_HTTP(dest_pair[0], dest_pair[1]):
                return True
        elif self.proxy[0] is None:
            return _orig_socket.connect(self, (dest_pair[0], dest_pair[1]))
        else:
            raise GeneralProxyError("Unknown proxy type")
            
    def getproxysockname(self):
        """getsockname() -> address info
        Returns the bound IP address and port number at the proxy.
        """
        return self._proxysockname
        
    def getproxypeername(self):
        """getproxypeername() -> address info
        Returns the IP and port number of the proxy.
        """
        return _orig_socket.getpeername(self)
        
    def getpeername(self):
        """getpeername() -> address info
        Returns the IP address and port number of the destination
        machine.
        """
        return self._proxypeername
        
    def __negotiatesocks5(self, *args, **kwargs):
        """Backwards compatibility"""
        return self._negotiate_SOCKS5(*args, **kwargs)
        
    def __negotiatesocks4(self, *args, **kwargs):
        """Backwards compatibility"""
        return self._negotiate_SOCKS4(*args, **kwargs)
        
    def __negotiatehttp(self, *args, **kwargs):
        """Backwards compatibility"""
        return self._negotiate_HTTP(*args, **kwargs)

# Legacy aliases
rawsocket = socket.socket