import cookielib
import logging
import sys
import traceback
from oic.utils.http_util import Redirect
from rrtest import FatalError
from rrtest.check import ExpectedError
from rrtest.check import STATUSCODE

from oictest.check import factory as check_factory
from oictest.oic_operations import AuthorizationRequest

from oic.oic.message import factory as message_factory
from oic.oic.message import ProviderConfigurationResponse
from oic.oic.message import RegistrationResponse

__author__ = 'rolandh'

logger = logging.getLogger(__name__)


def get_body(environ):
    length = int(environ["CONTENT_LENGTH"])
    try:
        body = environ["wsgi.input"].read(length)
    except Exception, excp:
        logger.exception("Exception while reading post: %s" % (excp,))
        raise

    # restore what I might have upset
    from StringIO import StringIO
    environ['wsgi.input'] = StringIO(body)

    return body


class Conversation(object):
    """
    :ivar response: The received HTTP messages
    :ivar protocol_response: List of the received protocol messages
    """

    def __init__(self, client, config, trace,
                 features=None, verbose=False, expect_exception=None):
        self.client = client
        self.client_config = config
        self.trace = trace
        self.test_output = []
        self.features = features
        self.verbose = verbose
        self.check_factory = check_factory
        self.msg_factory = message_factory
        self.expect_exception = expect_exception

        self.cjar = {"browser": cookielib.CookieJar(),
                     "rp": cookielib.CookieJar(),
                     "service": cookielib.CookieJar()}

        self.last_response = None
        self.last_content = None
        self.response = None
        self.exception = None
        self.provider_info = None
        # to keep track on what's happened
        self.protocol_response = []
        self.cis = []

    def check_severity(self, stat):
        if stat["status"] >= 4:
            self.trace.error("WHERE: %s" % stat["id"])
            self.trace.error("STATUS:%s" % STATUSCODE[stat["status"]])
            try:
                self.trace.error("HTTP STATUS: %s" % stat["http_status"])
            except KeyError:
                pass
            try:
                self.trace.error("INFO: %s" % stat["message"])
            except KeyError:
                pass

            raise FatalError

    def do_check(self, test, **kwargs):
        if isinstance(test, basestring):
            chk = self.check_factory(test)(**kwargs)
        else:
            chk = test(**kwargs)
        stat = chk(self, self.test_output)
        self.check_severity(stat)

    def err_check(self, test, err=None, bryt=True):
        if err:
            self.exception = err
        chk = self.check_factory(test)()
        chk(self, self.test_output)
        if bryt:
            e = FatalError("%s" % err)
            e.trace = "".join(traceback.format_exception(*sys.exc_info()))
            raise e

    def test_sequence(self, sequence):
        for test in sequence:
            if isinstance(test, tuple):
                test, kwargs = test
            else:
                kwargs = {}
            self.do_check(test, **kwargs)
            if test == ExpectedError:
                return False
        return True


class Request(Conversation):
    def __init__(self, phase, client, config, trace, verbose=False,
                 features=None, endpoint=""):
        Conversation.__init__(self, client, config, trace)
        self.creq, self.cresp = phase
        self.verbose = verbose
        self.features = features
        self.endpoint = endpoint

        self.last_response = None
        self.last_content = None
        self.position = 0

    def setup_request(self):
        self.request_spec = req = self.creq(conv=self)

        try:
            self.request_args = req.request_args
        except KeyError:
            pass
        try:
            self.args = req.kw_args
        except KeyError:
            pass

        self.req = req

    def send(self):
        # works since there only should be one
        try:
            self.provider_info = self.client.provider_info
        except IndexError:
            pass
        try:
            self.test_sequence(self.req.tests["pre"])
        except KeyError:
            pass
        except Exception, err:
            raise

        try:
            if self.verbose:
                print >> sys.stderr, "> %s" % self.req.request
            kwargs = {}
            if self.endpoint:
                kwargs["endpoint"] = str(self.endpoint)
            if isinstance(self.req, AuthorizationRequest):
                url, body, ht_args = self.req.construct_request(self.client,
                                                                **kwargs)
                resp = Redirect(str(url))
                return resp
            else:
                part = self.req(self.position, features=self.features, **kwargs)
                (self.position, self.last_response, self.last_content) = part

            try:
                if not self.test_sequence(self.req.tests["post"]):
                    self.position = None
            except KeyError:
                pass
        except FatalError:
            raise
        except Exception, err:
            self.err_check("exception", err)

        return None

    def do_query(self):
        self.setup_request()
        return self.send()


class Response(Conversation):
    def __init__(self, phase, client, config, trace, session,
                 verbose=False, keyjar=None, accept_exception=False,
                 last_response=None, last_content=""):
        Conversation.__init__(self, client, config, trace)
        self.session = session
        self.creq, self.cresp = phase
        self.test_output = []
        self.protocol_response = []
        self.verbose = verbose
        self.keyjar = keyjar
        self.accept_exception = accept_exception

        self.last_response = last_response
        self.last_content = last_content
        self.position = 0
        self.response_type = ""

    def post_process(self, resp):
        _msg = self.response_message
        if _msg:
            try:
                self.test_sequence(resp.tests["post"])
            except KeyError:
                pass

            if isinstance(_msg, RegistrationResponse):
                self.client.registration_response = _msg
                for key in ["client_id", "client_secret",
                            "registration_access_token",
                            "registration_client_uri"]:
                    try:
                        setattr(self.client, key, _msg[key])
                    except KeyError:
                        pass
            elif isinstance(_msg, ProviderConfigurationResponse):
                _issuer = self.session["srv_discovery_url"]
                _op_conf = self.session["op_conf"]
                if _op_conf:
                    for key, val in _op_conf["provider"].items():
                        if key == "dynamic":
                            continue
                        else:
                            _msg[key] = val
                self.client.handle_provider_config(_msg, _issuer)
                self.client.provider_info = _msg

            resp(self, self.response_message)

            return True
        else:
            return False

    def parse_response(self, environ):
        try:
            self.response_spec = resp = self.cresp()
        except TypeError:
            self.response_spec = None
            return True

        self.info = None
        self.response_message = None
        self.response_type = resp.response
        resp_type = resp.ctype

        _info = ""
        if resp.where == "url":
            try:
                if environ:
                    _info = environ["QUERY_STRING"]
                    self.trace.reply("RESPONSE: %s" % _info)
                else:
                    _info = self.last_response
                resp_type = "urlencoded"
            except KeyError:
                try:
                    _check = getattr(self.creq, "interaction_check", None)
                except AttributeError:
                    _check = None

                if _check:
                    self.err_check("interaction-check")
                else:
                    self.do_check("missing-redirect")
        else:
            self.do_check("check_content_type_header")
            if environ:
                _info = get_body(environ)
                self.trace.reply("RESPONSE: %s" % _info)
            else:
                _info = self.last_content

        if isinstance(resp.response, basestring):
            response = message_factory(resp.response)
        else:
            response = resp.response

        #self.response_type = response.__name__
        try:
            _cli = self.client

            if _cli.provider_info:
                kwargs = {"opponent_id": _cli.provider_info["issuer"]}
            else:
                kwargs = {}

            _qresp = _cli.parse_response(
                response, _info, resp_type, _cli.state,
                keyjar=_cli.keyjar, client_id=_cli.client_id,
                scope="openid", **kwargs)
            if _qresp:
                self.trace.info("[%s]: %s" % (_qresp.type(),
                                              _qresp.to_dict()))
                if _qresp.extra():
                    self.trace.info("### extra claims: %s" % _qresp.extra())
                self.response_message = _qresp
                self.protocol_response.append((_qresp, self.info))
            else:
                self.response_message = None
            err = None
            _errtxt = ""
        except Exception, err:
            _errtxt = "%s" % err
            self.trace.error(_errtxt)
            self.exception = _errtxt

        if err:
            if self.accept_exception:
                if isinstance(err, self.accept_exception):
                    self.trace.info("Got expected exception: %s [%s]" % (
                        err, err.__class__.__name__))
                else:
                    raise
            else:
                raise FatalError(_errtxt)
        elif self.response_message:
            self.do_check("response-parse")

        return self.post_process(resp)
