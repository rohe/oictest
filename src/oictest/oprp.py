#!/usr/bin/env python
import copy
import json
import os
from urllib import quote_plus
from urllib import unquote
import logging
from jwkest import JWKESTException

from jwkest.jws import alg2keytype
from urlparse import parse_qs
from oic.exception import PyoidcError

from oic.oauth2 import rndstr
from oic.oauth2 import ResponseError
from oic.utils.http_util import NotFound
from oic.utils.http_util import get_post
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect
from oic.oic.message import AccessTokenResponse
from oic.oic.message import RegistrationResponse
from oic.oic.message import factory as message_factory
from oic.oic.message import OpenIDSchema

from oictest.base import Conversation
from oictest.check import factory as check_factory
from oictest.check import get_protocol_response
from oictest.oidcrp import test_summation
from oictest.oidcrp import OIDCTestSetup
from oictest.oidcrp import request_and_return

from rrtest import Trace
from rrtest import exception_trace
from rrtest import Break
from rrtest.check import ERROR
from rrtest.check import OK
from rrtest.check import CRITICAL
from rrtest.check import STATUSCODE
from rrtest.check import WARNING

from testclass import Discover
from testclass import RequirementsNotMet
from testclass import Notice
from testclass import DisplayUserInfo
from testclass import DisplayIDToken
from testclass import Webfinger

from profiles import get_sequence
from profiles import from_code
from profiles import flows

LOGGER = logging.getLogger("")

INCOMPLETE = 5
CRYPTSUPPORT = {"none": "n", "signing": "s", "encryption": "e"}


class NotSupported(Exception):
    pass


def setup_logging(logfile):
    hdlr = logging.FileHandler(logfile)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")

    hdlr.setFormatter(base_formatter)
    LOGGER.addHandler(hdlr)
    LOGGER.setLevel(logging.DEBUG)


def pprint_json(json_txt):
    _jso = json.loads(json_txt)
    return json.dumps(_jso, sort_keys=True, indent=2, separators=(',', ': '))


def static(environ, start_response, path):
    LOGGER.info("[static]sending: %s" % (path,))

    try:
        text = open(path).read()
        if path.endswith(".ico"):
            start_response('200 OK', [('Content-Type', "image/x-icon")])
        elif path.endswith(".html"):
            start_response('200 OK', [('Content-Type', 'text/html')])
        elif path.endswith(".json"):
            start_response('200 OK', [('Content-Type', 'application/json')])
        elif path.endswith(".jwt"):
            start_response('200 OK', [('Content-Type', 'application/jwt')])
        elif path.endswith(".txt"):
            start_response('200 OK', [('Content-Type', 'text/plain')])
        elif path.endswith(".css"):
            start_response('200 OK', [('Content-Type', 'text/css')])
        else:
            start_response('200 OK', [('Content-Type', "text/plain")])
        return [text]
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)


def evaluate(session, conv):
    try:
        if session["node"].complete:
            _sum = test_summation(conv, session["testid"])
            session["node"].state = _sum["status"]
        else:
            session["node"].state = INCOMPLETE
    except (AttributeError, KeyError):
        pass


class OPRP(object):
    def __init__(self, lookup, conf, test_flows, cache, test_profile,
                 environ=None, start_response=None):
        self.lookup = lookup
        self.conf = conf
        self.test_flows = test_flows
        self.cache = cache
        self.test_profile = test_profile
        self.environ = environ
        self.start_response = start_response
                
    def opchoice(self, clients):
        resp = Response(mako_template="opchoice.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {
            "op_list": clients.keys()
        }
        return resp(self.environ, self.start_response, **argv)
        
    def flow_list(self, session):
        resp = Response(mako_template="flowlist.mako",
                        template_lookup=self.lookup,
                        headers=[])
    
        dump_log(session)
    
        argv = {
            "flows": session["tests"],
            "profile": session["profile"],
            "test_info": session["test_info"].keys(),
            "base": self.conf.BASE,
            "headlines": self.test_flows.DESC
        }
    
        return resp(self.environ, self.start_response, **argv)

    def opresult(self, conv, session):
        evaluate(session, conv)
        return self.flow_list(session)

    def opresult_fragment(self):
        resp = Response(mako_template="opresult_repost.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {}
        return resp(self.environ, self.start_response, **argv)
    
    def profile_edit(self, session):
        resp = Response(mako_template="profile.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {"profile": session["profile"]}
        return resp(self.environ, self.start_response, **argv)

    def test_info(self, testid, session):
        resp = Response(mako_template="testinfo.mako",
                        template_lookup=self.lookup,
                        headers=[])
    
        # dump_log(session, test_id=testid)
    
        info = session["test_info"][testid]
        _pinfo = profile_info(session, testid)
        argv = {
            "profile": _pinfo,
            "trace": info["trace"],
            "output": info["test_output"],
            "result": represent_result(session)
        }
    
        return resp(self.environ, self.start_response, **argv)

    def not_found(self):
        """Called if no URL matches."""
        resp = NotFound()
        return resp(self.environ, self.start_response)
    
    def static(self, path):
        LOGGER.info("[static]sending: %s" % (path,))

        try:
            text = open(path).read()
            if path.endswith(".ico"):
                self.start_response('200 OK', [('Content-Type',
                                                "image/x-icon")])
            elif path.endswith(".html"):
                self.start_response('200 OK', [('Content-Type', 'text/html')])
            elif path.endswith(".json"):
                self.start_response('200 OK', [('Content-Type',
                                                'application/json')])
            elif path.endswith(".jwt"):
                self.start_response('200 OK', [('Content-Type',
                                                'application/jwt')])
            elif path.endswith(".txt"):
                self.start_response('200 OK', [('Content-Type', 'text/plain')])
            elif path.endswith(".css"):
                self.start_response('200 OK', [('Content-Type', 'text/css')])
            else:
                self.start_response('200 OK', [('Content-Type', "text/plain")])
            return [text]
        except IOError:
            resp = NotFound()
            return resp(self.environ, self.start_response)

    def _display(self, path, tail):
        item = []
        for (dirpath, dirnames, filenames) in os.walk(path):
            if dirnames:
                item = [(unquote(f),
                         os.path.join(tail, f)) for f in dirnames]
                break
            elif filenames:
                item = [(unquote(f),
                         os.path.join(tail, f)) for f in filenames]
                break

        item.sort()
        resp = Response(mako_template="logs.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {"logs": item}

        return resp(self.environ, self.start_response, **argv)

    def display_log(self, path, tail):
        path = path.replace(":", "%3A")
        tail = tail.replace(":", "%3A")
        LOGGER.info("display_log: %s" % tail)
        if os.path.isdir(path):
            return self._display(path, tail)
        elif os.path.isfile(path):
            return static(path)
        else:
            if path.endswith("%2F"):
                path = path[:-3]
                if tail.endswith("%2F"):
                    tail = tail[:-3]
                if os.path.isdir(path):
                    return self._display(path, tail)
                elif os.path.isfile(path):
                    return static(self.environ, self.start_response, path)

            resp = Response("No saved logs")
            return resp(self.environ, self.start_response)

    def client_init(self):
        ots = OIDCTestSetup(self.conf, self.test_flows, str(self.conf.PORT))
        client_conf = ots.config.CLIENT
        trace = Trace()
        conv = Conversation(ots.client, client_conf, trace, None,
                            message_factory, check_factory)
        conv.cache = self.cache
        return ots, conv

    def session_setup(self, session, path, index=0):
        logging.info("session_setup")
        _keys = session.keys()
        for key in _keys:
            if key.startswith("_"):
                continue
            elif key in ["tests", "flow_names", "response_type",
                         "test_info", "profile"]:  # don't touch !
                continue
            else:
                del session[key]

        session["testid"] = path
        session["node"] = get_node(session["tests"], path)
        sequence_info = {"sequence": get_sequence(path, session["profile"],
                                                  self.test_flows.FLOWS),
                         "mti": session["node"].mti,
                         "tests": session["node"].tests}
        session["seq_info"] = sequence_info
        session["index"] = index
        session["response_type"] = ""
        ots, conv = self.client_init()
        session["conv"] = conv
        session["ots"] = ots

        return conv, sequence_info, ots, conv.trace, index

    def err_response(self, session, where, err):
        if err:
            if isinstance(err, Break):
                session["node"].state = WARNING
            else:
                session["node"].state = ERROR
            exception_trace(where, err, LOGGER)
            session["conv"].trace.error("%s:%s" % (err.__class__.__name__,
                                                   str(err)))
            session["conv"].test_output.append(
                {"id": "-", "status": ERROR, "message": "%s" % err})
        else:
            session["node"].state = ERROR
            session["conv"].test_output.append(
                {"id": "-", "status": ERROR, "message": "Error in %s" % where})

        _tid = session["testid"]
        dump_log(session, _tid)
        session["test_info"][_tid] = {
            "trace": session["conv"].trace,
            "test_output": session["conv"].test_output}

        return self.flow_list(session)

    def sorry_response(self, homepage, err):
        resp = Response(mako_template="sorry.mako",
                        template_lookup=self.lookup,
                        headers=[])
        argv = {"htmlpage": homepage,
                "error": str(err)}
        return resp(self.environ, self.start_response, **argv)

    def none_request_response(self, sequence_info, index, session, conv):
        req_c, arg = sequence_info["sequence"][index]
        req = req_c()
        if isinstance(req, Notice):
            kwargs = {
                "url": "%scontinue?path=%s&index=%d" % (
                    self.conf.BASE, session["testid"], session["index"]),
                "back": self.conf.BASE}
            try:
                kwargs["note"] = session["node"].kwargs["note"]
            except KeyError:
                pass
            try:
                kwargs["op"] = conv.client.provider_info["issuer"]
            except (KeyError, TypeError):
                pass

            if isinstance(req, DisplayUserInfo):
                for presp, _ in conv.protocol_response:
                    if isinstance(presp, OpenIDSchema):
                        kwargs["table"] = presp
                        break
            elif isinstance(req, DisplayIDToken):
                instance, _ = get_protocol_response(
                    conv, AccessTokenResponse)[0]
                kwargs["table"] = instance["id_token"]

            try:
                key = req.cache(self.cache, conv, sequence_info["cache"])
            except KeyError:
                pass
            else:
                kwargs["url"] += "&key=%s" % key

            return req(self.lookup, **kwargs)
        else:
            try:
                req(conv)
                return None
            except RequirementsNotMet as err:
                return self.err_response(session, "run_sequence", err)

    def init_session(self, session, profile=None):
        if profile is None:
            profile = self.test_profile

        f_names = self.test_flows.FLOWS.keys()
        f_names.sort()
        session["flow_names"] = []
        for k in self.test_flows.ORDDESC:
            k += '-'
            l = [z for z in f_names if z.startswith(k)]
            session["flow_names"].extend(l)

        session["tests"] = [make_node(x, self.test_flows.FLOWS[x]) for x in
                            flows(profile, session["flow_names"],
                                  self.test_flows.FLOWS)]

        session["response_type"] = []
        session["test_info"] = {}
        session["profile"] = profile
        if "conv" not in session:
            session["ots"], session["conv"] = self.client_init()

    def reset_session(self, session, profile=None):
        _keys = session.keys()
        for key in _keys:
            if key.startswith("_"):
                continue
            else:
                del session[key]
        self.init_session(session, profile)
        conv, ots = self.client_init()
        session["conv"] = conv
        session["ots"] = ots

    def session_init(self, session):
        if "tests" not in session:
            self.init_session(session)
            return True
        else:
            return False

    def application(self, environ, start_response):
        LOGGER.info("Connection from: %s" % environ["REMOTE_ADDR"])
        session = environ['beaker.session']

        path = environ.get('PATH_INFO', '').lstrip('/')
        LOGGER.info("path: %s" % path)

        if path == "robots.txt":
            return static(environ, start_response, "static/robots.txt")
        elif path == "favicon.ico":
            return static(environ, start_response, "static/favicon.ico")

        if path.startswith("static/"):
            return static(environ, start_response, path)

        if path.startswith("export/"):
            return static(environ, start_response, path)

        self.environ = environ
        self.start_response = start_response

        if path == "":  # list
            try:
                if self.session_init(session):
                    return self.flow_list(session)
                else:
                    try:
                        resp = Redirect("%sopresult#%s" % (
                            self.conf.BASE, session["testid"][0]))
                    except KeyError:
                        return self.flow_list(session)
                    else:
                        return resp(environ, start_response)
            except Exception as err:
                return self.err_response(session, "session_setup", err)
        elif path == "logs":
            return self.display_log("log", "log")
        elif path.startswith("log"):
            if path == "log":
                path = os.path.join(
                    path, quote_plus(self.conf.CLIENT["srv_discovery_url"]))
                tail = path
            else:
                head, tail = os.path.split(path)
            return self.display_log(path, tail)
        elif "flow_names" not in session:
            self.session_init(session)

        if path == "reset":
            self.reset_session(session)
            return self.flow_list(environ, start_response, session)
        elif path == "pedit":
            return self.profile_edit(environ, start_response, session)
        elif path == "profile":
            info = parse_qs(get_post(environ))
            cp = session["profile"].split(".")
            cp[0] = info["rtype"][0]

            crsu = []
            for name, cs in CRYPTSUPPORT.items():
                try:
                    if info[name] == ["on"]:
                        crsu.append(cs)
                except KeyError:
                    pass

            if len(cp) == 3:
                if len(crsu) == 3:
                    pass
                else:
                    cp.append("".join(crsu))
            else:  # len >= 4
                cp[3] = "".join(crsu)

            try:
                if info["extra"] == ['on']:
                    if len(cp) == 3:
                        cp.extend(["", "+"])
                    elif len(cp) == 4:
                        cp.append("+")
                    elif len(cp) == 5:
                        cp[4] = "+"
                else:
                    if len(cp) == 5:
                        cp = cp[:-1]
            except KeyError:
                if len(cp) == 5:
                    cp = cp[:-1]

            # reset all testsflows
            self.reset_session(session, ".".join(cp))
            return self.flow_list(session)
        elif path.startswith("test_info"):
            p = path.split("/")
            try:
                return self.test_info(p[1], session)
            except KeyError:
                return self.not_found()
        elif path == "continue":
            try:
                sequence_info = session["seq_info"]
            except KeyError:  # Cookie delete broke session
                query = parse_qs(environ["QUERY_STRING"])
                path = query["path"][0]
                index = int(query["index"][0])
                conv, sequence_info, ots, trace, index = self.session_setup(
                    session, path, index)
                try:
                    conv.cache_key = query["key"][0]
                except KeyError:
                    pass
            except Exception as err:
                return self.err_response(session, "session_setup", err)
            else:
                index = session["index"]
                ots = session["ots"]
                conv = session["conv"]

            index += 1
            try:
                return self.run_sequence(sequence_info, session, conv, ots,
                                         conv.trace, index)
            except Exception, err:
                return self.err_response(session, "run_sequence", err)
        elif path == "opresult":

            try:
                conv = session["conv"]
            except KeyError as err:
                homepage = ""
                return self.sorry_response(homepage, err)

            return self.opresult(conv, session)
        # expected path format: /<testid>[/<endpoint>]
        elif path in session["flow_names"]:
            LOGGER.info("<=<=<=<=< %s >=>=>=>=>" % path)
            conv, sequence_info, ots, trace, index = self.session_setup(session,
                                                                        path)
            session["node"].complete = False
            try:
                return self.run_sequence(sequence_info, session, conv, ots,
                                         trace, index)
            except Exception as err:
                return self.err_response(session, "run_sequence", err)
        elif path in ["authz_cb", "authz_post"]:
            try:
                sequence_info = session["seq_info"]
                index = session["index"]
                ots = session["ots"]
                conv = session["conv"]
            except KeyError as err:
                # Todo: find out which port I'm listening on
                return self.sorry_response(self.conf.BASE, err)
            (req_c, resp_c), _ = sequence_info["sequence"][index]
            try:
                response_mode = conv.AuthorizationRequest["response_mode"]
            except KeyError:
                response_mode = None

            if path == "authz_cb":
                if response_mode == "form_post":
                    pass
                elif session["response_type"] and not \
                        session["response_type"] == ["code"]:
                    # but what if it's all returned as a query ?
                    try:
                        qs = environ["QUERY_STRING"]
                    except KeyError:
                        qs = ""
                    if qs:
                        session["conv"].trace.response("QUERY_STRING:%s" % qs)
                        session["conv"].info(
                            "Didn't expect response as query parameters")

                    return self.opresult_fragment()

            if resp_c:  # None in cases where no OIDC response is expected
                _ctype = resp_c.ctype

                # parse the response
                if response_mode == "form_post":
                    info = parse_qs(get_post(environ))
                    _ctype = "dict"
                elif path == "authz_post":
                    query = parse_qs(get_post(environ))
                    try:
                        info = query["fragment"][0]
                    except KeyError:
                        return self.sorry_response(self.conf.BASE,
                                                   "missing fragment ?!")
                    _ctype = "urlencoded"
                elif resp_c.where == "url":
                    info = environ["QUERY_STRING"]
                    _ctype = "urlencoded"
                else:  # resp_c.where == "body"
                    info = get_post(environ)

                LOGGER.info("Response: %s" % info)
                conv.trace.reply(info)
                resp_cls = message_factory(resp_c.response)
                algs = ots.client.sign_enc_algs("id_token")
                try:
                    response = ots.client.parse_response(
                        resp_cls, info, _ctype,
                        conv.AuthorizationRequest["state"],
                        keyjar=ots.client.keyjar, algs=algs)
                except ResponseError as err:
                    return self.err_response(session, "run_sequence", err)
                except Exception as err:
                    return self.err_response(session, "run_sequence", err)

                LOGGER.info("Parsed response: %s" % response.to_dict())
                conv.protocol_response.append((response, info))
                conv.trace.response(response)

            try:
                post_tests(conv, req_c, resp_c)
            except Exception as err:
                return self.err_response(session, "post_test", err)

            index += 1
            try:
                return self.run_sequence(sequence_info, session, conv, ots,
                                         conv.trace, index)
            except Exception as err:
                return self.err_response(session, "run_sequence", err)
        else:
            resp = BadRequest()
            return resp(environ, start_response)

    def run_sequence(self, sequence_info, session, conv, ots, trace, index):
        while index < len(sequence_info["sequence"]):
            LOGGER.info("###{i}### {f} ###{i}###".format(
                f=session["testid"], i=index))
            session["index"] = index
            try:
                (req_c, resp_c), _kwa = sequence_info["sequence"][index]
            except (ValueError, TypeError):  # Not a tuple
                ret = self.none_request_response(sequence_info, index, session,
                                                 conv)
                dump_log(session)
                if ret:
                    return ret
            else:
                try:
                    kwargs = setup(_kwa, conv, session)
                except NotSupported:
                    return self.opresult(conv, session)
                except Exception as err:
                    return self.err_response(session, "function()", err)

                req = req_c(conv)
                try:
                    if req.tests["pre"]:
                        conv.test_output.append((req.request, "pre"))
                        conv.test_sequence(req.tests["pre"])
                except KeyError:
                    pass
                except Exception as err:
                    return self.err_response(session, "pre-test", err)

                conv.request_spec = req

                conv.trace.info("------------ %s ------------" % req_c.request)
                if req_c == Discover:
                    # Special since it's just a GET on a URL
                    _r = req.discover(
                        ots.client,
                        issuer=ots.config.CLIENT["srv_discovery_url"])
                    conv.position, conv.last_response, conv.last_content = _r

                    if conv.last_response.status >= 400:
                        return self.err_response(session, "discover",
                                                 conv.last_response.text)

                    for x in ots.client.keyjar[
                            ots.client.provider_info["issuer"]]:
                        try:
                            resp = ots.client.http_request(x.source)
                        except Exception as err:
                            return self.err_response(session, "jwks_fetch",
                                                     str(err))
                        else:
                            if resp.status_code < 300:
                                trace.info(
                                    "JWKS: %s" % pprint_json(resp.content))
                            else:
                                return self.err_response(session, "jwks_fetch",
                                                         resp.content)
                elif req_c == Webfinger:
                    url = req.discover(**kwargs)
                    if url:
                        conv.trace.request(url)
                        conv.test_output.append(
                            {"id": "-", "status": OK,
                             "message": "Found discovery URL: %s" % url})
                    else:
                        conv.test_output.append(
                            {"id": "-", "status": ERROR,
                             "message": "Failed to find discovery URL"})
                else:
                    try:
                        endp = req.endpoint
                    except AttributeError:
                        pass
                    else:
                        if not endpoint_support(conv.client, endp):
                            conv.test_output.append(
                                {"id": "-", "status": ERROR,
                                 "message": "%s not supported" % req.endpoint})
                            return self.opresult(conv, session)

                    LOGGER.info("request: %s" % req.request)
                    if req.request == "AuthorizationRequest":
                        # New state for each request
                        kwargs["request_args"].update({"state": rndstr()})
                        if not ots.client.provider_info:
                            return self.err_response(session, req.request,
                                                     "No provider info")
                    elif req.request in ["AccessTokenRequest",
                                         "UserInfoRequest",
                                         "RefreshAccessTokenRequest"]:
                        kwargs.update(
                            {"state": conv.AuthorizationRequest["state"]})
                        if not ots.client.provider_info:
                            return self.err_response(session, req.request,
                                                     "No provider info")

                    # Extra arguments outside the OIDC spec
                    try:
                        _extra = ots.config.CLIENT["extra"][req.request]
                    except KeyError:
                        pass
                    except Exception as err:
                        return self.err_response(session, "config_exta", err)
                    else:
                        try:
                            kwargs["request_args"].update(_extra)
                        except KeyError:
                            kwargs["request_args"] = _extra

                    req.call_setup()
                    try:
                        url, body, ht_args = req.construct_request(ots.client,
                                                                   **kwargs)
                    except PyoidcError as err:  # A OIDC specific error
                        return self.err_response(session, "construct_request",
                                                 err)

                    if req.request == "AuthorizationRequest":
                        session["response_type"] = kwargs["request_args"][
                            "response_type"]
                        LOGGER.info("redirect.url: %s" % url)
                        LOGGER.info("redirect.header: %s" % ht_args)
                        resp = Redirect(str(url))
                        return resp(self.environ, self.start_response)
                    else:
                        _kwargs = {"http_args": ht_args}

                        if conv.AuthorizationRequest:
                            _kwargs["state"] = conv.AuthorizationRequest[
                                "state"]

                        try:
                            try:
                                _method = kwargs["method"]
                            except KeyError:
                                _method = req.method
                            try:
                                _ctype = kwargs["ctype"]
                            except KeyError:
                                _ctype = resp_c.ctype

                            response = request_and_return(
                                conv, url, trace, message_factory(
                                    resp_c.response), _method, body, _ctype,
                                **_kwargs)
                        except PyoidcError as err:
                            return self.err_response(session,
                                                     "request_and_return", err)
                        except JWKESTException as err:
                            return self.err_response(session,
                                                     "request_and_return", err)

                        if response is None:  # bail out
                            return self.err_response(session,
                                                     "request_and_return", None)

                        trace.response(response)
                        LOGGER.info(response.to_dict())
                        if resp_c.response == "RegistrationResponse":
                            if isinstance(response, RegistrationResponse):
                                ots.client.store_registration_info(response)
                            elif "error" in response:
                                return self.err_response(
                                    session, "id_token_verification",
                                    response["error"])
                        elif resp_c.response == "AccessTokenResponse":
                            if "error" not in response:
                                areq = conv.AuthorizationRequest.to_dict()
                                try:
                                    del areq["acr_values"]
                                except KeyError:
                                    pass

                try:
                    post_tests(conv, req_c, resp_c)
                except Exception as err:
                    return self.err_response(session, "post_test", err)

            index += 1
            _tid = session["testid"]
            dump_log(session, _tid)
            session["test_info"][_tid] = {"trace": conv.trace,
                                          "test_output": conv.test_output}

        # wrap it up
        # Any after the fact tests ?
        try:
            if sequence_info["tests"]:
                conv.test_output.append(("After completing the test flow", ""))
                conv.test_sequence(sequence_info["tests"])
        except KeyError:
            pass
        except Exception as err:
            return self.err_response(session, "post_test", err)

        _tid = session["testid"]
        dump_log(session, _tid)
        session["test_info"][_tid] = {"trace": conv.trace,
                                      "test_output": conv.test_output}
        session["node"].complete = True

        _grp = _tid.split("-")[1]

        resp = Redirect("%sopresult#%s" % (self.conf.BASE, _grp))
        return resp(self.environ, self.start_response)


# =============================================================================

def get_id_token(client, conv):
    return client.grant[conv.AuthorizationRequest["state"]].get_id_token()


# Produce a JWS, a signed JWT, containing a previously received ID token
def id_token_as_signed_jwt(client, id_token, alg="RS256"):
    ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


def add_test_result(conv, status, message, tid="-"):
    conv.test_output.append({"id": str(tid),
                             "status": status,
                             "message": message})


def test_output(out):
    """

    """
    element = ["Test output\n"]
    for item in out:
        if isinstance(item, tuple):
            element.append("__%s:%s__" % item)
        else:
            element.append("[%s]" % item["id"])
            element.append("\tstatus: %s" % STATUSCODE[item["status"]])
            try:
                element.append("\tdescription: %s" % (item["name"]))
            except KeyError:
                pass
            try:
                element.append("\tinfo: %s" % (item["message"]))
            except KeyError:
                pass
    element.append("\n")
    return element


def trace_output(trace):
    """

    """
    element = ["Trace output\n"]
    for item in trace:
        element.append("%s" % item)
    element.append("\n")
    return element


def log_path(session, test_id=None):
    _conv = session["conv"]

    iss = _conv.client.provider_info["issuer"]
    qiss = quote_plus(iss)
    profile = session["profile"]

    if not os.path.isdir("log/%s/%s" % (qiss, profile)):
        os.makedirs("log/%s/%s" % (qiss, profile))

    if test_id is None:
        test_id = session["testid"]

    return "log/%s/%s/%s" % (qiss, profile, test_id)


def represent_result(session):
    if session["index"] + 1 < len(session["seq_info"]["sequence"]):
        return "PARTIAL RESULT"

    _stat = test_summation(session["conv"], session["testid"])["status"]

    if _stat < WARNING or _stat > CRITICAL:
        text = "PASSED"
    elif _stat == WARNING:
        text = "WARNING"
    else:
        text = "FAILED"

    warnings = []
    for item in session["conv"].test_output:
        if isinstance(item, tuple):
            continue
        elif item["status"] == WARNING:
            warnings.append(item["message"])

    if text == "PASSED":
        try:
            text = "UNKNOWN - %s" % session["seq_info"]["node"].kwargs["result"]
        except KeyError:
            pass

    if warnings:
        text = "%s\nWarnings:\n%s" % (text, "\n".join(warnings))

    return text


def profile_info(session, test_id=None):
    try:
        _conv = session["conv"]
    except KeyError:
        pass
    else:
        try:
            iss = _conv.client.provider_info["issuer"]
        except TypeError:
            pass
        else:
            profile = from_code(session["profile"])

            if test_id is None:
                try:
                    test_id = session["testid"]
                except KeyError:
                    return {}

            return {"Issuer": iss, "Profile": profile, "Test ID": test_id}

    return {}


def dump_log(session, test_id=None):
    try:
        _conv = session["conv"]
    except KeyError:
        pass
    else:
        _pi = profile_info(session, test_id)
        if _pi:
            path = log_path(session, _pi["Test ID"])
            sline = 60*"="
            output = ["%s: %s" % (k, _pi[k]) for k in ["Issuer", "Profile",
                                                       "Test ID"]]

            output.extend(["", sline, ""])
            output.extend(trace_output(_conv.trace))
            output.extend(["", sline, ""])
            output.extend(test_output(_conv.test_output))
            output.extend(["", sline, ""])
            # and lastly the result
            output.append("RESULT: %s" % represent_result(session))
            output.append("")

            f = open(path, "w")
            f.write("\n".join(output))
            f.close()
            return path


def clear_session(session):
    for key in session:
        session.pop(key, None)
    session.invalidate()


def post_tests(conv, req_c, resp_c):
    try:
        inst = req_c(conv)
        _tests = inst.tests["post"]
    except KeyError:
        pass
    else:
        if _tests:
            conv.test_output.append((req_c.request, "post"))
            conv.test_sequence(_tests)

    if resp_c:
        try:
            inst = resp_c()
            _tests = inst.tests["post"]
        except KeyError:
            pass
        else:
            if _tests:
                conv.test_output.append((resp_c.response, "post"))
                conv.test_sequence(_tests)


DEFAULTS = {
    "response_modes_supported": ["query", "fragment"],
    "grant_types_supported": ["authorization_code", "implicit"],
    "token_endpoint_auth_methods_supported": ["client_secret_basic"],
    "claims_parameter_supported": False,
    "request_parameter_supported": False,
    "request_uri_parameter_supported": True,
    "require_request_uri_registration": False,
}


def included(val, given):
    if isinstance(val, basestring):
        assert val == given or val in given
    elif isinstance(val, list):
        for _val in val:
            assert _val == given or _val in given
    else:
        assert val == given

    return True


def support(conv, args):
    pi = conv.client.provider_info
    stat = 0
    for ser in ["warning", "error"]:
        if ser not in args:
            continue
        if ser == "warning":
            err = WARNING
        else:
            err = ERROR
        for key, val in args[ser].items():
            if key not in pi:
                try:
                    included(val, DEFAULTS[key])
                except AssertionError:  # Explicitly Not supported
                    add_test_result(conv, ERROR,
                                    "Not supported: %s=%s" % (key, val))
                    stat = ERROR
                except KeyError:  # Not in defaults
                    conv.trace.info("Not explicit: %s=%s using default" % (key,
                                                                           val))
            else:
                try:
                    included(val, pi[key])
                except AssertionError:  # Not supported
                    add_test_result(conv, err,
                                    "Not supported: %s=%s" % (key, val))
                    stat = err
                except KeyError:  # Not defined
                    conv.trace.info("Not explicit: %s=%s" % (key, val))

    return stat


def endpoint_support(client, endpoint):
    if endpoint in client.provider_info:
        return True
    else:
        return False


def setup(kwa, conv):
    kwargs = copy.deepcopy(kwa)  # decouple

    # evaluate possible functions
    try:
        spec = kwargs["function"]
    except KeyError:
        pass
    else:
        if isinstance(spec, tuple):
            func, args = spec
        else:
            func = spec
            args = {}

        try:
            req_args = kwargs["request_args"]
        except KeyError:
            req_args = {}

        try:
            kwargs["request_args"] = func(req_args, conv, args)
        except KeyError as err:
            conv.trace.error("function: %s failed" % func)
            conv.trace.error(str(err))
            raise NotSupported
        del kwargs["function"]

    try:
        spec = kwargs["kwarg_func"]
    except KeyError:
        pass
    else:
        if isinstance(spec, tuple):
            func, args = spec
        else:
            func = spec
            args = {}

        try:
            kwargs = func(kwargs, conv, args)
        except KeyError as err:
            conv.trace.error("function: %s failed" % func)
            conv.trace.error(str(err))
            raise NotSupported

        del kwargs["kwarg_func"]

    try:
        res = support(conv, kwargs["support"])
        if res >= ERROR:
            raise NotSupported()

        del kwargs["support"]
    except KeyError:
        pass

    return kwargs


class Node():
    def __init__(self, name, desc="", rmc=False, experr=False, mti=None,
                 tests=None, **kwargs):
        self.name = name
        self.desc = desc
        self.state = 0
        self.rmc = rmc
        self.experr = experr
        self.mti = mti
        self.tests = tests or {}
        self.kwargs = kwargs


def make_node(x, spec):
    return Node(x, **spec)


def get_node(tests, nid):
    l = [x for x in tests if x.name == nid]
    try:
        return l[0]
    except ValueError:
        return None
