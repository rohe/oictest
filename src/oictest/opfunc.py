__author__ = 'rohe0002'

import json

from urlparse import urlparse

from mechanize import ParseResponse
from mechanize._form import ControlNotFoundError


#def get_page(url):
#    http = httplib2.Http()
#    resp, content = http.request(url)
#    if resp.status == 200:
#        return content
#    else:
#        raise HTTP_ERROR(resp.status)

class FlowException(Exception):
    def __init__(self, function="", content="", url=""):
        Exception.__init__(self)
        self.function = function
        self.content = content
        self.url = url

    def __str__(self):
        return json.dumps(self.__dict__)


class DResponse():
    """ A Response class that behaves in the way that mechanize expects it
    """
    def __init__(self, **kwargs):
        self.status = 200
        self.index = 0
        self._message = ""
        self.url = ""
        if kwargs:
            for key, val in kwargs.items():
                if val:
                    self.__setitem__(key, val)

    def __setitem__(self, key, value):
        setattr(self, key, value)

    def __getitem__(self, item):
        if item == "content-location":
            return self.url
        elif item == "content-length":
            return len(self._message)
        else:
            return getattr(self, item)

    def geturl(self):
        """
        The base url for the response

        :return: The url
        """
        return self.url

    def read(self, size=0):
        """
        Read from the content of the response. The class remembers what has
        been read so it's possible to read small consecutive parts of the
        content.

        :param size: The number of bytes to read
        :return: Somewhere between zero and 'size' number of bytes depending
            on how much it left in the content buffer to read.
        """
        if size:
            if self._len < size:
                return self._message
            else:
                if self._len == self.index:
                    part = None
                elif self._len - self.index < size:
                    part = self._message[self.index:]
                    self.index = self._len
                else:
                    part = self._message[self.index:self.index+size]
                    self.index += size
                return part
        else:
            return self._message

    def write(self, message):
        """
        Write the message into the content buffer

        :param message: The message
        """
        self._message = message
        self._len = len(message)


def do_request(client, url, method, body="", headers=None, trace=False):
    """
    Sends a HTTP request. It handles trace logging if asked for

    :param client: The client instance
    :param url: Where to send the request
    :param method: The HTTP method to use for the request
    :param body: The request body
    :param headers: The requset headers
    :param trace: A class instance to use for trace logging
    :return: A tuple of
        url - the url the request was sent to
        response - the response to the request
        content - the content of the response if any
    """
    if headers is None:
        headers = {}

    if trace:
        trace.request("URL: %s" % url)
        trace.request("BODY: %s" % body)

    response, content = client.http_request(url, method=method,
                                            body=body, headers=headers,
                                            trace=trace)

    if trace:
        trace.reply("RESPONSE: %s" % response)
        trace.reply("CONTENT: %s" % unicode(content, encoding="utf-8"))

    return url, response, content

def pick_form(response, content, url=None, **kwargs):
    """
    Picks which form in a web-page that should be used

    :param response: A HTTP request response. A DResponse instance
    :param content: The HTTP response content
    :param url: The url the request was sent to
    :return: The picked form or None of no form matched the criteria.
    """
    forms = ParseResponse(response)
    if not forms:
        raise FlowException(content=content, url=url)

    _form = None
    if len(forms) == 1:
        _form = forms[0]
    else:
        if "pick" in kwargs:
            _dict = kwargs["pick"]
            for form in forms:
                if _form:
                    break
                for key, _ava in _dict.items():
                    if key == "form":
                        _keys = form.attrs.keys()
                        for attr, val in _ava.items():
                            if attr in _keys and val == form.attrs[attr]:
                                _form = form
                    elif key == "control":
                        prop = _ava["id"]
                        _default = _ava["value"]
                        try:
                            orig_val = form[prop]
                            if isinstance(orig_val, basestring):
                                if orig_val == _default:
                                    _form = form
                            elif _default in orig_val:
                                _form = form
                        except KeyError:
                            pass
                    else:
                        _form = None

                    if not _form:
                        break
        elif "index" in kwargs:
            _form = forms[kwargs["index"]]

    return _form

def do_click(client, form, **kwargs):
    """
    Emulates the user clicking submit on a form.

    :param client: The Client instance
    :param form: The form that should be submitted
    :return: What do_request() returns
    """
    request = form.click()

    headers = {}
    for key, val in request.unredirected_hdrs.items():
        headers[key] = val

    url = request._Request__original
    try:
        _trace = kwargs["_trace_"]
    except KeyError:
        _trace = False

    if form.method == "POST":
        return do_request(client, url, "POST", request.data, headers, _trace)
    else:
        return do_request(client, url, "GET", headers=headers, trace=_trace)

def select_form(client, orig_response, content, **kwargs):
    """
    Pick a form on a web page, possibly enter some information and submit
    the form.

    :param client: The Client
    :param orig_response: The original response (as returned by httplib2)
    :param content: The content of the response
    :return: The response do_click() returns
    """
    try:
        _url = orig_response["content-location"]
    except KeyError:
        _url = kwargs["location"]
    # content is a form to be filled in and returned
    response = DResponse(status=orig_response["status"], url=_url)
    response.write(content)

    form = pick_form(response, content, _url, **kwargs)

    if "set" in kwargs:
        for key, val in kwargs["set"].items():
            if key.startswith("_"):
                continue

            try:
                form[key] = val
            except ControlNotFoundError:
                pass

    return do_click(client, form, **kwargs)

#noinspection PyUnusedLocal
def chose(client, orig_response, content, path, **kwargs):
    """
    Sends a HTTP GET to a url given by the present url and the given
    relative path.

    :param orig_response: The original response
    :param content: The content of the response
    :param path: The relative path to add to the base URL
    :return: The response do_click() returns
    """

    try:
        _trace = kwargs["trace"]
    except KeyError:
        _trace = False

    if not path.startswith("http"):
        try:
            _url = orig_response["content-location"]
        except KeyError:
            _url = kwargs["location"]

        part = urlparse(_url)
        url = "%s://%s%s" %  (part[0], part[1], path)
    else:
        url = path

    return do_request(client, url, "GET", trace=_trace)
    #return resp, ""

def post_form(client, orig_response, content, **kwargs):
    """
    The same as select_form but with no possibility of change the content
    of the form.

    :param client: The Client instance
    :param orig_response: The original response (as returned by httplib2)
    :param content: The content of the response
    :return: The response do_click() returns
    """
    _url = orig_response["content-location"]
    # content is a form to be filled in and returned
    response = DResponse(status=orig_response["status"], url=_url)
    response.write(content)

    form = pick_form(response, content, _url, **kwargs)

    return do_click(client, form, **kwargs)

#noinspection PyUnusedLocal
def interaction(args):
    _type = args["type"]
    if _type == "form":
        return select_form
    elif _type == "link":
        return chose
    else:
        return None

# ========================================================================

class Operation(object):
    def __init__(self, message_mod, args=None):
        if args:
            self.function = interaction(args)

        self.message_mod = message_mod
        self.args = args or {}
        self.request = None

    def update(self, dic):
        self.args.update(dic)

    #noinspection PyUnusedLocal
    def post_op(self, result, environ, args):
        pass

    def __call__(self, environ, trace, location, response, content):
        try:
            _args = self.args.copy()
        except (KeyError, AttributeError):
            _args = {}

        _args["_trace_"] = trace
        _args["location"] = location

        if trace:
            trace.reply("FUNCTION: %s" % self.function.__name__)
            trace.reply("ARGS: %s" % _args)

        result = self.function(environ["client"], response, content, **_args)
        self.post_op(result, environ, _args)
        return result

