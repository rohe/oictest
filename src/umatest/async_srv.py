import asynchat
import asyncore
import logging
import socket
import cStringIO
from BaseHTTPServer import BaseHTTPRequestHandler
import time
import sys

logger = logging.getLogger(__name__)

__author__ = 'roland'
__version__ = 'UMAServer version 0.1'

WEEKDAYNAME = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

MONTHNAME = [None,
             'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
             'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']

SERVER_VERSION = "DirgHTTP/" + __version__
SYS_VERSION = "Python/" + sys.version.split()[0]


def setup_logging(filename):
    hdlr = logging.FileHandler(filename)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")
    hdlr.setFormatter(base_formatter)
    logger.addHandler(hdlr)
    logger.setLevel(logging.DEBUG)


class CIdict(object):
    """ Dictionary with case-insensitive keys """

    def __init__(self, infile, *args):
        self._ci_dict = {}
        lines = infile.readlines()
        for line in lines:
            k, v = line.split(":", 1)
            self._ci_dict[k.lower()] = self[k] = v.strip()
        self.headers = self.keys()

    def getheader(self, key, default=""):
        return self._ci_dict.get(key.lower(), default)

    def get(self, key, default=""):
        return self._ci_dict.get(key.lower(), default)

    def __getitem__(self, key):
        return self._ci_dict[key.lower()]

    def __contains__(self, key):
        return key.lower() in self._ci_dict

    def __setitem__(self, key, value):
        self._ci_dict[key.lower()] = value

    def keys(self):
        return self._ci_dict.keys()

    def items(self):
        return self._ci_dict.items()


class RequestHandler(asynchat.async_chat, BaseHTTPRequestHandler):
    MessageClass = CIdict

    def __init__(self, server, sock):
        asynchat.async_chat.__init__(self, sock)
        self._server = server
        self.__conn = sock
        self.rfile = cStringIO.StringIO()
        self._data = ''
        #self.__fqdn = socket.getfqdn()
        self.set_terminator("\r\n\r\n")
        self.set_reuse_addr()
        self.reading_headers = True
        self.headers = None
        self.raw_requestline = ""
        self.handling = False
        self.output = ""
        self.request = None

    # Implementation of base class abstract method
    def collect_incoming_data(self, data):
        logger.debug("data: %s [[%s]]" % (data, self.get_terminator()))
        self.rfile.write(data)

    # Implementation of base class abstract method
    def found_terminator(self):
        logger.debug("handling: %s, reading_headers: %s" % (
            self.handling, self.reading_headers))
        if self.reading_headers:
            self.reading_headers = False
            self.handle_request_line()
            self.rfile.seek(0)
            logger.info(self.command)
            if self.command.upper() == "POST":
                clen = self.headers.getheader("content-length")
                self.set_terminator(int(clen))
            else:
                self.handling = True
                self.set_terminator(None)
                self.handle_request()
        elif not self.handling:
            self.set_terminator(None)  # browsers sometimes over-send
            self.handling = True
            self.rfile.seek(0)
            self.handle_request()

    def handle_request(self):
        # information in self.rfile
        self._data = self.rfile.readlines()
        try:
            self.request = {"command": self.command,
                            "path": self.path,
                            "headers": dict(self.headers.items()),
                            "data": self._data}
        except Exception, err:
            logger.exception(err)
            raise

    def handle_request_line(self):
        """Called when the http request line and headers have been received"""
        # prepare attributes needed in parse_request()
        self.rfile.seek(0)
        self.raw_requestline = self.rfile.readline()
        self.parse_request()
        logger.debug("Command: %s, Headers: %s" % (self.command,
                                                   self.headers.items()))
        #print self.command, self.headers.items()

    def get_request(self):
        try:
            return self.command, self.path, self._data
        except AttributeError:
            return "","",""

    def handle_write(self):
        logger.debug("Handler write")
        while self.output:
            sent = self.send(self.output)
            self.output = self.output[sent:]

    def respond(self, resp):
        self.output = resp
        self.request = None
        self.handle_write()
        self.close()


class DirgServer(asyncore.dispatcher):
    allow_reuse_address = False
    request_queue_size = 5
    address_family = socket.AF_INET
    socket_type = socket.SOCK_STREAM

    def __init__(self, address, server=None):
        self._address = address
        self.handler_class = RequestHandler
        self.server = server
        self.handler = []

        asyncore.dispatcher.__init__(self)
        try:
            self.create_socket(self.address_family, self.socket_type)
            # try to re-use a server port if possible
            if self.allow_reuse_address:
                self.set_reuse_addr()

            self.server_bind()
            self.server_activate()
        except:
            # cleanup asyncore.socket_map before raising
            self.close()
            raise

    def server_bind(self):
        self.bind(self._address)
        logger.debug("bind: address=%s:%s" % (self._address[0],
                                              self._address[1]))

    def server_activate(self):
        self.listen(self.request_queue_size)
        logger.debug("listen: backlog=%d" % self.request_queue_size)

    def handle_accept(self):
        peer = self.accept()
        if peer is not None:
            sock, addr = peer
            logger.info('Incoming connection from %s' % repr(addr))
            self.handler.append(self.handler_class(self, sock))

    def get_requests(self):
        return self.requests

    def handle_close(self):
        self.close()


class Response(object):
    _status = (200, "OK")
    _content_type = 'text/html'
    protocol_version = "HTTP/1.0"

    def __init__(self, message=None, **kwargs):
        self.status = kwargs.get('status', self._status)
        self.response = kwargs.get('response', self._response)

        self.message = message

        self.headers = kwargs.get('headers', [])
        _content_type = kwargs.get('content', self._content_type)
        self.headers.append(('Content-type', _content_type))
        self.headers.append(('Server', self.version_string()))
        self.headers.append(('Date', self.date_time_string()))

    def __call__(self, **kwargs):
        return self.response(self.message, **kwargs)

    #noinspection PyUnusedLocal
    def _response(self, message="", **argv):
        res = ["%s %d %s" % (self.protocol_version, self.status[0],
                             self.status[1])]
        for header in self.headers:
            res.append("%s: %s" % header)
        res.append("")
        res.append(message)
        return "\r\n".join(res)

    @staticmethod
    def version_string():
        """Return the server software version string."""
        return SERVER_VERSION + ' ' + SYS_VERSION

    @staticmethod
    def date_time_string(timestamp=None):
        """Return the current date and time formatted for a message header."""
        if timestamp is None:
            timestamp = time.time()
        year, month, day, hh, mm, ss, wd, y, z = time.gmtime(timestamp)
        s = "%s, %02d %3s %4d %02d:%02d:%02d GMT" % (WEEKDAYNAME[wd], day,
                                                     MONTHNAME[month], year,
                                                     hh, mm, ss)
        return s


class Main(object):
    protocol_version = "HTTP/1.0"

    def __init__(self, host, port):
        self.umasrv = DirgServer(('0.0.0.0', 8080), self)

    @staticmethod
    def check_in():
        asyncore.loop(timeout=5.0, count=1)

    @staticmethod
    def send_response(handler, status=200, message=""):
        _txt = handler.responses[status][0]
        resp = Response(message, status=(status, _txt))
        logger.debug(resp())
        handler.respond(resp())

    def run(self):
        start = time.time()
        while True:
            self.check_in()
            time.sleep(0.5)
            for handler in self.umasrv.handler:
                if handler.request:
                    print handler.request
                    self.send_response(handler, 200,
                                       "<html><data><h1>foxx</h1></data></html>")

            if time.time() - start > 10:
                break
        self.umasrv.close()


if __name__ == "__main__":
    setup_logging("async_srv.log")
    main = Main('0.0.0.0', 8080)
    main.run()