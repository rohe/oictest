import cookielib
import traceback
from oic.exception import UnSupported
from oic.oauth2 import Message
from oic.oic import RegistrationResponse
import sys
from rrtest.opfunc import Operation
from rrtest import FatalError
from rrtest.check import INTERACTION
from rrtest.check import ExpectedError
from rrtest.check import STATUSCODE
from rrtest.interaction import Interaction
from rrtest.interaction import Action
from rrtest.interaction import InteractionNeeded

__author__ = 'rolandh'

ROLES = ["C", "RS"]


class Conversation(object):
    """
    :param response: The received HTTP messages
    :param protocol_response: List of the received protocol messages
    """

    def __init__(self, client, config, trace, interaction, resource_owner,
                 requester, msg_factory=None, check_factory=None,
                 expect_exception=None, **extra_args):

        self.resource_owner = resource_owner
        self.requester = requester
        self._clients = client
        self._client_config = config
        self.client = None
        self.client_config = None
        self.trace = trace
        self.test_output = []
        self.features = {}
        self.verbose = False
        self.check_factory = check_factory
        self.msg_factory = msg_factory
        self.expect_exception = expect_exception
        self.extra_args = extra_args

        self.cjar = {"browser": cookielib.CookieJar(),
                     "rp": cookielib.CookieJar(),
                     "service": cookielib.CookieJar()}

        self.protocol_response = []
        self.last_response = None
        self.last_content = None
        self.response = None
        self.exception = None
        self.interact_done = []
        self.ignore_check = []

        self.interaction = {}
        self.provider_info = {}
        for role in ROLES:
            self.interaction[role] = Interaction(self._clients[role],
                                                 interaction[role])
            self.provider_info[role] = self._clients[role].provider_info
        self.role = ""
        self.req = None
        self.accept_exception = False
        self.request_spec = None
        self.login_page = None
        self.position = ""
        self.creq = self.cresp = None
        self.request_args = None
        self.args = None
        self.response_spec = None
        self.info = None
        self.response_type = None
        self.response_message = None
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
                self.trace.error("INFO: %s" % (stat["message"],))
            except KeyError:
                pass

            raise FatalError

    def do_check(self, test, **kwargs):
        if isinstance(test, basestring):
            chk = self.check_factory(test)(**kwargs)
        else:
            chk = test(**kwargs)

        if chk.__class__.__name__ not in self.ignore_check:
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

    def my_endpoints(self):
        return self.client.redirect_uris

    def for_me(self, response="", url=""):
        if not response:
            response = self.last_response
        if not url:
            url = response.headers["location"]
        for redirect_uri in self.my_endpoints():
            if url.startswith(redirect_uri):
                return True
        return False

    def intermit(self):
        _response = self.last_response
        if _response.status_code >= 400:
            done = True
        else:
            done = False

        rdseq = []
        while not done:
            url = _response.url
            content = _response.text

            while _response.status_code in [302, 301, 303]:
                url = _response.headers["location"]
                if url in rdseq:
                    raise FatalError("Loop detected in redirects")
                else:
                    rdseq.append(url)
                    if len(rdseq) > 8:
                        raise FatalError(
                            "Too long sequence of redirects: %s" % rdseq)

                self.trace.reply("REDIRECT TO: %s" % url)

                # If back to me
                if self.for_me(_response):
                    self.client.cookiejar = self.cjar["rp"]
                    done = True
                    break
                else:
                    try:
                        _response = self.client.send(url, "GET")
                    except Exception, err:
                        raise FatalError("%s" % err)

                    content = _response.text
                    self.trace.reply("CONTENT: %s" % content)
                    self.position = url
                    self.last_content = content
                    self.response = _response

                    if _response.status_code >= 400:
                        done = True
                        break

            if done or url is None:
                break

            _base = url.split("?")[0]

            try:
                _spec = self.interaction[self.role].pick_interaction(_base,
                                                                     content)
                #if _spec in self.interact_done:
                #    self.trace.error("Same interaction a second time")
                #    raise InteractionNeeded("Same interaction twice")
                #self.interact_done.append(_spec)
            except InteractionNeeded:
                self.position = url
                self.trace.error("Page Content: %s" % content)
                raise
            except KeyError:
                self.position = url
                self.trace.error("Page Content: %s" % content)
                self.err_check("interaction-needed")

            if len(_spec) > 2:
                self.trace.info(">> %s <<" % _spec["page-type"])
                if _spec["page-type"] == "login":
                    self.login_page = content

            _op = Action(_spec["control"])

            try:
                _response = _op(self.client, self, self.trace, url,
                                _response, content, self.features)
                if isinstance(_response, dict):
                    self.last_response = _response
                    self.last_content = _response
                    return _response
                content = _response.text
                self.position = url
                self.last_content = content
                self.response = _response

                if _response.status_code >= 400:
                    break
            except (FatalError, InteractionNeeded):
                raise
            except Exception, err:
                self.err_check("exception", err, False)

        self.last_response = _response
        try:
            self.last_content = _response.text
        except AttributeError:
            self.last_content = None

    def init(self, phase):
        self.creq, self.cresp = phase

    def setup_request(self):
        try:
            self.role = self.creq.role
        except AttributeError:
            # continue with the same if once been used
            if not self.role:
                self.role = ROLES[0]  # doesn't matter which one

        self.trace.info("<< %s >>" % self.role)
        self.client = self._clients[self.role]
        self.client_config = self._client_config[self.role]

        self.request_spec = req = self.creq(conv=self)

        if isinstance(req, Operation):
            for intact in self.interaction[self.role].interactions:
                try:
                    if req.__class__.__name__ == intact["matches"]["class"]:
                        req.args = intact["args"]
                        break
                except KeyError:
                    pass
        else:
            try:
                self.request_args = req.request_args
            except KeyError:
                pass
            try:
                self.args = req.kw_args
            except KeyError:
                pass

        # The authorization dance is all done through the browser
        if req.request == "AuthorizationRequest":
            self.client.cookiejar = self.cjar["browser"]
        # everything else by someone else, assuming the RP
        else:
            self.client.cookiejar = self.cjar["rp"]

        self.req = req

    def do_query(self):
        self.setup_request()
        self.send()
        if self.last_response.status_code in [301, 302, 303] and \
                not self.for_me():
            self.intermit()
        if not self.handle_result():
            self.intermit()
            self.handle_result()

    def do_sequence(self, oper):
        try:
            self.test_sequence(oper["tests"]["pre"])
        except KeyError:
            pass

        for phase in oper["sequence"]:
            self.init(phase)
            try:
                self.do_query()
            except InteractionNeeded:
                self.test_output.append({"status": INTERACTION,
                                         "message": self.last_content,
                                         "id": "exception",
                                         "name": "interaction needed",
                                         "url": self.position})
                break
            except FatalError:
                raise
            except Exception, err:
                #self.err_check("exception", err)
                raise

        try:
            self.test_sequence(oper["tests"]["post"])
        except KeyError:
            pass

    def handle_result(self):
        try:
            self.response_spec = resp = self.cresp()
        except TypeError:
            self.response_spec = None
            return True

        self.info = None
        self.response_message = None

        response = self.last_response
        resp_type = resp.ctype
        if response:
            try:
                ctype = response.headers["content-type"]
                if ctype == "application/jwt":
                    resp_type = "jwt"
            except (AttributeError, TypeError):
                pass

        if response.status_code >= 400:
            pass
        elif not self.position:
            if isinstance(self.last_content, Message):
                self.response_message = self.last_content
            elif response.status_code == 200:
                self.info = self.last_content
        elif resp.where == "url" or response.status_code == 302:
            try:
                self.info = response.headers["location"]
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
            self.info = self.last_content

        if self.info and resp.response:
            if isinstance(resp.response, basestring):
                response = self.msg_factory(resp.response)
            else:
                response = resp.response

            self.response_type = response.__name__
            try:
                _cli = self.client
                _qresp = self.client.parse_response(
                    response, self.info, resp_type, _cli.state,
                    keyjar=_cli.keyjar,
                    client_id=_cli.client_id,
                    scope="openid", opponent_id=_cli.provider_info.keys()[0])
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

    def post_process(self, resp):
        if self.response_message:
            try:
                self.test_sequence(resp.tests["post"])
            except KeyError:
                pass

            if isinstance(self.response_message, RegistrationResponse):
                self.client.registration_response = self.response_message
                for key in ["client_id", "client_secret",
                            "registration_access_token",
                            "registration_client_uri"]:
                    try:
                        setattr(self.client, key, self.response_message[key])
                    except KeyError:
                        pass

            resp(self, self.response_message)

            return True
        else:
            return False

    def collect_extra_args(self):
        _args = {}
        for param in ["extra_args", "kwargs_mod"]:
            try:
                spec = self.extra_args[param]
            except KeyError:
                continue
            else:
                try:
                    _args = {param: spec[self.req.__class__.__name__]}
                except KeyError:
                    try:
                        _args = {param: spec[self.req.request]}
                    except KeyError:
                        pass
        return _args

    def send(self):
        try:
            self.test_sequence(self.req.tests["pre"])
        except KeyError:
            pass

        try:
            if self.verbose:
                print >> sys.stderr, "> %s" % self.req.request

            extra_args = self.collect_extra_args()
            try:
                extra_args.update(self.client_config[self.creq.request])
            except KeyError:
                pass
            part = self.req(self.position, self.last_response,
                            self.last_content, self.features, **extra_args)
            (self.position, self.last_response, self.last_content) = part

            try:
                if not self.test_sequence(self.req.tests["post"]):
                    self.position = None
            except KeyError:
                pass
        except FatalError:
            raise
        except UnSupported, err:
            self.trace.info("%s" % err)
            self.test_output.append(
                {"status": 2, "id": "Check support",
                 "name": "Verifies that a function is supported"})
            raise
        except Exception, err:
            self.err_check("exception", err)
