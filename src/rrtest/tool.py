import cookielib
import json
import sys
import traceback
from oic.exception import PyoidcError
from oic.oic import ProviderConfigurationResponse, RegistrationResponse

from rrtest.opfunc import Operation
from rrtest import FatalError
from rrtest.check import ExpectedError
from rrtest.check import INTERACTION
from rrtest.interaction import Interaction
from rrtest.interaction import Action
from rrtest.interaction import InteractionNeeded
from rrtest.status import STATUSCODE


__author__ = 'rolandh'


class Conversation(object):
    """
    :param response: The received HTTP messages
    :param protocol_response: List of the received protocol messages
    """
    
    def __init__(self, client, config, trace, interaction,
                 check_factory=None, msg_factory=None,
                 features=None, verbose=False, expect_exception=None,
                 **extra_args):
        self.client = client
        self.client_config = config
        self.trace = trace
        self.test_output = []
        self.features = features
        self.verbose = verbose
        self.check_factory = check_factory
        self.msg_factory = msg_factory
        self.expect_exception = expect_exception
        self.extra_args = extra_args

        self.cjar = {"browser": cookielib.MozillaCookieJar(),
                     "rp": cookielib.MozillaCookieJar(),
                     "service": cookielib.MozillaCookieJar()}

        self.protocol_response = []
        self.last_response = None
        self.last_content = None
        self.response = None
        self.interaction = Interaction(self.client, interaction)
        self.exception = None
        self.provider_info = self.client.provider_info or {}
        self.interact_done = []
        self.ignore_check = []
        self.login_page = ""
        self.sequence = {}
        self.flow_index = 0
        self.position = None
        self.request_args = {}
        self.args = {}
        self.creq = None
        self.cresp = None
        self.req = None
        self.request_spec = None

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
        return []

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
                _spec = self.interaction.pick_interaction(_base, content)
                #if _spec in self.interact_done:
                #    self.trace.error("Same interaction a second time")
                #    raise InteractionNeeded("Same interaction twice")
                #self.interact_done.append(_spec)
            except InteractionNeeded:
                if self.extra_args["break"]:
                    self.dump_state(self.extra_args["break"])
                    exit(2)

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
                self.test_output.append(
                    {"status": 3, "id": "Communication error",
                     "message": "%s" % err})
                raise FatalError

        self.last_response = _response
        try:
            self.last_content = _response.text
        except AttributeError:
            self.last_content = None

    def init(self, phase):
        self.creq, self.cresp = phase

    def setup_request(self):
        self.request_spec = req = self.creq(conv=self)

        if isinstance(req, Operation):
            for intact in self.interaction.interactions:
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

    def send(self):
        pass

    def handle_result(self):
        pass

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
        self.sequence = oper
        try:
            self.test_sequence(oper["tests"]["pre"])
        except KeyError:
            pass

        for i in range(self.flow_index, len(oper["sequence"])):
            phase = oper["sequence"][i]
            flow = oper["flow"][i]
            self.flow_index = i

            self.trace.info(flow)
            if not isinstance(phase, tuple):
                _proc = phase()
                _proc(self)
                continue

            self.init(phase)
            if self.extra_args["cookie_imp"]:
                if self.creq.request == "AuthorizationRequest":
                    try:
                        self.client.load_cookies_from_file(
                            self.extra_args["cookie_imp"])
                    except Exception:
                        self.trace.error("Could not import cookies from file")

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
            except PyoidcError as err:
                if err.message:
                    self.trace.info("Protocol message: %s" % err.message)
                raise FatalError
            except Exception as err:
                #self.err_check("exception", err)
                raise
            else:
                if self.extra_args["cookie_exp"]:
                    if self.request_spec.request == "AuthorizationRequest":
                        self.cjar["browser"].save(
                            self.extra_args["cookie_exp"], ignore_discard=True)

        try:
            self.test_sequence(oper["tests"]["post"])
        except KeyError:
            pass

    def dump_state(self, filename):
        state = {
            "client": {
                "behaviour": self.client.behaviour,
                "keyjar": self.client.keyjar.dump(),
                "provider_info": self.client.provider_info.to_json(),
                "client_id": self.client.client_id,
                "client_secret": self.client.client_secret,
            },
            "trace_log": {"start": self.trace.start, "trace": self.trace.trace},
            "sequence": self.sequence["flow"],
            "flow_index": self.flow_index,
            "client_config": self.client_config,
            "test_output": self.test_output
        }

        try:
            state["client"][
                "registration_resp"] = self.client.registration_response.to_json()
        except AttributeError:
            pass

        txt = json.dumps(state)
        _fh = open(filename, "w")
        _fh.write(txt)
        _fh.close()

    def restore_state(self, filename):
        txt = open(filename).read()
        state = json.loads(txt)
        self.trace.start = state["trace_log"]["start"]
        self.trace.trace = state["trace_log"]["trace"]
        self.flow_index = state["flow_index"]
        self.client_config = state["client_config"]
        self.test_output = state["test_output"]

        self.client.behaviour = state["client"]["behaviour"]
        self.client.keyjar.restore(state["client"]["keyjar"])
        pcr = ProviderConfigurationResponse().from_json(
            state["client"]["provider_info"])
        self.client.provider_info = pcr
        self.client.client_id = state["client"]["client_id"]
        self.client.client_secret = state["client"]["client_secret"]

        for key, val in pcr.items():
            if key.endswith("_endpoint"):
                setattr(self.client, key, val)

        try:
            self.client.registration_response = RegistrationResponse().from_json(
                state["client"]["registration_resp"])
        except KeyError:
            pass

    def restart(self, state):
        pass