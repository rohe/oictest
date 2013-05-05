#!/usr/bin/env python
# Just for serving static files
import socket

__author__ = 'rohe0002'

import SimpleHTTPServer
import SocketServer


class MyTCPServer(SocketServer.TCPServer):
    def __init__(self, server_address, RequestHandlerClass):
        self.allow_reuse_address = True
        SocketServer.TCPServer.__init__(self, server_address,
                                        RequestHandlerClass)


def main(arg):
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler

    if arg[0] == "localhost":
        hostname = ""
    else:
        hostname = arg[0]

    port = int(arg[1])
#    s = socket.socket()
#    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
#    s.bind((hostname, port))
    httpd = MyTCPServer((hostname, port), Handler)
    print "Starting request handler on %s:%s" % (hostname, arg[1])
    httpd.serve_forever()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        main(sys.argv[1:])
    else:
        main()