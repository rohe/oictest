#!/usr/bin/env python
# Just for serving static files

__author__ = 'rohe0002'

import SimpleHTTPServer
import SocketServer


class MyTCPServer(SocketServer.TCPServer):
    def __init__(self, server_address, requesthandlerclass):
        self.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address,
                                        requesthandlerclass)

    def __call__(self, *args, **kwargs):
        return "MyTCPServer"


def main(arg=None):
    handler = SimpleHTTPServer.SimpleHTTPRequestHandler

    if arg[0] == "localhost":
        hostname = ""
    else:
        hostname = arg[0]

    port = int(arg[1])
#    s = socket.socket()
#    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#    s.bind((hostname, port))
    httpd = MyTCPServer((hostname, port), handler)
    print "Starting request handler on %s:%s" % (hostname, arg[1])
    httpd.serve_forever()

if __name__ == "__main__":
    import sys

    main(sys.argv[1:])
