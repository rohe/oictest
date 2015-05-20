#!/usr/bin/env python
import sys

__author__ = 'roland'

import BaseHTTPServer, SimpleHTTPServer
import ssl

httpd = BaseHTTPServer.HTTPServer((sys.argv[1], int(sys.argv[2])),
                                  SimpleHTTPServer.SimpleHTTPRequestHandler)

httpd.socket = ssl.wrap_socket(httpd.socket,
                               certfile='../certs/server.crt',
                               server_side=True,
                               keyfile='../certs/server.key')

httpd.serve_forever()