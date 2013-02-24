from rrtest.check import CheckHTTPResponse

__author__ = 'rolandh'


class Request(object):
    request = ""
    method = ""
    lax = False
    _request_args = {}
    _kw_args = {}
    tests = {"post": [CheckHTTPResponse], "pre": []}

    def __init__(self, conv):
        self.request_args = self._request_args.copy()
        self.kw_args = self._kw_args.copy()
        self.conv = conv
        self.trace = conv.trace

    #noinspection PyUnusedLocal
    def __call__(self, location, response, content, features):
        _client = self.conv.client
        if isinstance(self.request, basestring):
            request = self.conv.msg_factory(self.request)
        else:
            request = self.request

        try:
            kwargs = self.kw_args.copy()
        except KeyError:
            kwargs = {}

        try:
            kwargs["request_args"] = self.request_args.copy()
            _req = kwargs["request_args"].copy()
        except KeyError:
            _req = {}

        cis = getattr(_client, "construct_%s" % request.__name__)(request,
                                                                  **kwargs)
        # Remove parameters with None value
        for key, val in cis.items():
            if val is None:
                del cis[key]

        setattr(self.conv, request.__name__, cis)
        try:
            cis.lax = self.lax
        except AttributeError:
            pass

        ht_add = None

        if "authn_method" in kwargs:
            h_arg = _client.init_authentication_method(cis, **kwargs)
        else:
            h_arg = None

        url, body, ht_args, cis = _client.uri_and_body(request, cis,
                                                       method=self.method,
                                                       request_args=_req)

        self.conv.cis.append(cis)
        if h_arg:
            ht_args.update(h_arg)
        if ht_add:
            ht_args.update({"headers": ht_add})

        self.trace.request("URL: %s" % url)
        self.trace.request("BODY: %s" % body)
        try:
            self.trace.request("HEADERS: %s" % ht_args["headers"])
        except KeyError:
            pass

        response = _client.http_request(url, method=self.method, data=body,
                                        **ht_args)

        self.trace.reply("RESPONSE: %s" % response)
        self.trace.reply("CONTENT: %s" % response.text)
        if response.status_code in [301, 302]:
            self.trace.reply("LOCATION: %s" % response.headers["location"])
        self.trace.reply("COOKIES: %s" % response.cookies)

        return url, response, response.text

    def update(self, dic):
        _tmp = {"request": self.request_args.copy(), "kw": self.kw_args}
        for key, val in self.rec_update(_tmp, dic).items():
            setattr(self, "%s_args" % key, val)

    def rec_update(self, dic0, dic1):
        res = {}
        for key, val in dic0.items():
            if key not in dic1:
                res[key] = val
            else:
                if isinstance(val, dict):
                    res[key] = self.rec_update(val, dic1[key])
                else:
                    res[key] = dic1[key]

        for key, val in dic1.items():
            if key in dic0:
                continue
            else:
                res[key] = val

        return res
