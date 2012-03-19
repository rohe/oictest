#!/usr/bin/env python
# Just for serving static files

__author__ = 'rohe0002'

import SimpleHTTPServer
import SocketServer

def main(arg):
    Handler = SimpleHTTPServer.SimpleHTTPRequestHandler

    if arg[0] == "localhost":
        hostname = ""
    else:
        hostname = arg[0]

    httpd = SocketServer.TCPServer((hostname, int(arg[1])), Handler)
    print "Starting request handler on %s:%s" % (hostname, arg[1])
    httpd.serve_forever()

if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        main(sys.argv[1:])
    else:
        main()