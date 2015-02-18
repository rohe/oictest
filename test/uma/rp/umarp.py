#!/usr/bin/env python
import importlib
import os
from urllib import quote_plus
from urlparse import parse_qs
import argparse
import logging
import sys
from jwkest import JWKESTException

from mako.lookup import TemplateLookup
from oic.exception import PyoidcError

from oic.oauth2 import rndstr, ResponseError
from oic.oauth2.dynreg import ClientInfoResponse
from oic.oic import PARAMMAP, DEF_SIGN_ALG
from oic.utils.http_util import Redirect, get_post, BadRequest, Response
from oic.oic.message import RegistrationResponse
from uma.client import Client as umaClient

from uma.message import factory as uma_message_factory
from oic.oic.message import factory as oic_message_factory
from oic.oauth2.dynreg import factory as dynreg_message_factory

from oictest.base import Conversation
from oictest.check import factory as check_factory
from oictest.oidcrp import OIDCTestSetup
from oictest.oidcrp import request_and_return
from oictest.oprp import OPRP
from oictest.oprp import static
from oictest.oprp import CRYPTSUPPORT
from oictest.oprp import endpoint_support
from oictest.oprp import post_tests
from oictest.oprp import NotSupported
from oictest.oprp import setup
from oictest.oprp import pprint_json
from oictest.oprp import setup_logging

from rrtest import Trace
from rrtest.check import ERROR
from rrtest.check import OK

from testclass import OIDCDiscover
from testclass import UMADiscover
from testclass import Webfinger

LOGGER = logging.getLogger("")

MODULE2FACTORY = {
    "oic.oic.message": oic_message_factory,
    "oic.oauth2.dynreg": dynreg_message_factory,
    "uma.message": uma_message_factory
}

RP_ARGS = {}


class UmaClient(umaClient):
    def __init__(self, client_id=None, ca_certs=None,
                 client_prefs=None, client_authn_methods=None, keyjar=None,
                 verify_ssl=True, behaviour=None):
        umaClient.__init__(self, client_id, ca_certs, client_prefs,
                           client_authn_methods, keyjar, verify_ssl=verify_ssl)
        if behaviour:
            self.behaviour = behaviour

    def sign_enc_algs(self, typ):
        resp = {}
        for key, val in PARAMMAP.items():
            try:
                resp[key] = self.registration_response[val % typ]
            except (TypeError, KeyError):
                if key == "sign":
                    resp[key] = DEF_SIGN_ALG["id_token"]
        return resp


class UMAoprp(OPRP):
    def client_init(self):
        ots = OIDCTestSetup(CONF, TEST_FLOWS.FLOWS, str(CONF.PORT), UmaClient)
        client_conf = ots.config.CLIENT
        trace = Trace()
        conv = Conversation(ots.client, client_conf, trace, None,
                            uma_message_factory, check_factory)
        conv.cache = CACHE
        return ots, conv

    def run_sequence(self, sequence_info, session, conv, ots, trace, index):
        while index < len(sequence_info["sequence"]):
            session["index"] = index
            try:
                (req_c, resp_c), _kwa = sequence_info["sequence"][index]
            except (ValueError, TypeError):  # Not a tuple
                ret = self.none_request_response(sequence_info, index, session,
                                                 conv)
                self.dump_log(session)
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
                if req_c in [OIDCDiscover, UMADiscover]:
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
                            return self.err_response(session,
                                                     "jwks_fetch", str(err))
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

                    req.request_txt = req.request
                    if req.request:
                        try:
                            req.request = MODULE2FACTORY[req.module](
                                req.request)
                        except AttributeError:
                            pass

                    if req.request_txt == "ResourceSetDescription":
                        req.kw_args["endpoint"] += "/" + kwargs["rsid"]

                    try:
                        url, body, ht_args = req.construct_request(ots.client,
                                                                   **kwargs)
                    except PyoidcError as err:  # A OIDC specific error
                        return self.err_response(session, "construct_request",
                                                 err)

                    if req.request_txt == "AuthorizationRequest":
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

                            _msg_factory = MODULE2FACTORY[resp_c.module]
                            response = request_and_return(
                                conv, url, trace, _msg_factory(resp_c.response),
                                _method, body, _ctype, **_kwargs)
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
                        if resp_c.response in ["ClientInfoResponse",
                                               "RegistrationResponse"]:
                            if isinstance(response, RegistrationResponse):
                                ots.client.oidc_registration_info = response
                                ots.client.store_registration_info(response)
                            elif isinstance(response, ClientInfoResponse):
                                ots.client.uma_registration_info = response
                                ots.client.store_registration_info(response)
                try:
                    post_tests(conv, req_c, resp_c)
                except Exception as err:
                    return self.err_response(session, "post_test", err)

            index += 1
            _tid = session["testid"]
            self.dump_log(session, _tid)
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
        self.dump_log(session, _tid)
        session["test_info"][_tid] = {"trace": conv.trace,
                                      "test_output": conv.test_output}
        session["node"].complete = True

        resp = Redirect("%sopresult#%s" % (CONF.BASE, _tid[3]))
        return resp(self.environ, self.start_response)

    def flow_list(self, session):
        resp = Response(mako_template="flowlist.mako",
                        template_lookup=self.lookup,
                        headers=[])

        self.dump_log(session)

        argv = {
            "target": args.target,
            "role": args.role,
            "flows": session["tests"],
            "profile": session["profile"],
            "test_info": session["test_info"].keys(),
            "base": self.conf.BASE,
            "headlines": self.test_flows.DESC
        }

        return resp(self.environ, self.start_response, **argv)


def application(environ, start_response):
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

    oprp = UMAoprp(**RP_ARGS)

    oprp.environ = environ
    oprp.start_response = start_response

    if path == "":  # list
        try:
            if oprp.session_init(session):
                return oprp.flow_list(session)
            else:
                try:
                    resp = Redirect("%sopresult#%s" % (
                        oprp.conf.BASE, session["testid"][0]))
                except KeyError:
                    return oprp.flow_list(session)
                else:
                    return resp(environ, start_response)
        except Exception as err:
            return oprp.err_response(session, "session_setup", err)
    elif path == "logs":
        return oprp.display_log("log", "log")
    elif path.startswith("log"):
        if path == "log":
            path = os.path.join(
                path, quote_plus(oprp.conf.CLIENT["srv_discovery_url"]))
            tail = path
        else:
            head, tail = os.path.split(path)
        return oprp.display_log(path, tail)
    elif "flow_names" not in session:
        oprp.session_init(session)

    if path == "reset":
        oprp.reset_session(session)
        return oprp.flow_list(session)
    elif path == "pedit":
        return oprp.profile_edit(session)
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
        oprp.reset_session(session, ".".join(cp))
        return oprp.flow_list(session)
    elif path.startswith("test_info"):
        p = path.split("/")
        try:
            return oprp.test_info(p[1], session)
        except KeyError:
            return oprp.not_found()
    elif path == "continue":
        try:
            sequence_info = session["seq_info"]
        except KeyError:  # Cookie delete broke session
            query = parse_qs(environ["QUERY_STRING"])
            path = query["path"][0]
            index = int(query["index"][0])
            conv, sequence_info, ots, trace, index = oprp.session_setup(
                session, path, index)
            try:
                conv.cache_key = query["key"][0]
            except KeyError:
                pass
        except Exception as err:
            return oprp.err_response(session, "session_setup", err)
        else:
            index = session["index"]
            ots = session["ots"]
            conv = session["conv"]

        index += 1
        try:
            return oprp.run_sequence(sequence_info, session, conv, ots,
                                     conv.trace, index)
        except Exception, err:
            return oprp.err_response(session, "run_sequence", err)
    elif path == "opresult":

        try:
            conv = session["conv"]
        except KeyError as err:
            homepage = ""
            return oprp.sorry_response(homepage, err)

        return oprp.opresult(conv, session)
    # expected path format: /<testid>[/<endpoint>]
    elif path in session["flow_names"]:
        LOGGER.info("<=<=<=<=< %s >=>=>=>=>" % path)
        conv, sequence_info, ots, trace, index = oprp.session_setup(session,
                                                                    path)
        session["node"].complete = False
        try:
            return oprp.run_sequence(sequence_info, session, conv, ots,
                                     trace, index)
        except Exception as err:
            return oprp.err_response(session, "run_sequence", err)
    elif path in ["authz_cb", "authz_post"]:
        try:
            sequence_info = session["seq_info"]
            index = session["index"]
            ots = session["ots"]
            conv = session["conv"]
        except KeyError as err:
            # Todo: find out which port I'm listening on
            return oprp.sorry_response(oprp.conf.BASE, err)
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

                return oprp.opresult_fragment()

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
                    return oprp.sorry_response(oprp.conf.BASE,
                                               "missing fragment ?!")
                _ctype = "urlencoded"
            elif resp_c.where == "url":
                info = environ["QUERY_STRING"]
                _ctype = "urlencoded"
            else:  # resp_c.where == "body"
                info = get_post(environ)

            LOGGER.info("Response: %s" % info)
            conv.trace.reply(info)
            resp_cls = MODULE2FACTORY[resp_c.module](resp_c.response)
            algs = ots.client.sign_enc_algs("id_token")
            try:
                response = ots.client.parse_response(
                    resp_cls, info, _ctype,
                    conv.AuthorizationRequest["state"],
                    keyjar=ots.client.keyjar, algs=algs)
            except ResponseError as err:
                return oprp.err_response(session, "run_sequence", err)
            except Exception as err:
                return oprp.err_response(session, "run_sequence", err)

            LOGGER.info("Parsed response: %s" % response.to_dict())
            conv.protocol_response.append((response, info))
            conv.trace.response(response)

        try:
            post_tests(conv, req_c, resp_c)
        except Exception as err:
            return oprp.err_response(session, "post_test", err)

        index += 1
        try:
            return oprp.run_sequence(sequence_info, session, conv, ots,
                                     conv.trace, index)
        except Exception as err:
            return oprp.err_response(session, "run_sequence", err)
    else:
        resp = BadRequest()
        return resp(environ, start_response)


if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='mailaddr')
    parser.add_argument('-t', dest='target')
    parser.add_argument('-r', dest='role')
    parser.add_argument('-d', dest='directory')
    parser.add_argument('-p', dest='profile')
    parser.add_argument('-P', dest='profiles')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    # global ACR_VALUES
    # ACR_VALUES = CONF.ACR_VALUES

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.timeout': 900
    }

    CACHE = {}
    sys.path.insert(0, ".")
    CONF = importlib.import_module(args.config)

    TEST_FLOWS = importlib.import_module("%s_%s_flow" % (args.role,
                                                         args.target))

    if args.profiles:
        PROFILES = importlib.import_module(args.profiles)
    else:
        PROFILES = importlib.import_module("profiles")

    if args.directory:
        _dir = args.directory
        if not _dir.endswith("/"):
            _dir += "/"
    else:
        _dir = "./"

    if args.profile:
        TEST_PROFILE = args.profile
    else:
        TEST_PROFILE = "C.T.T.ns"

    LOOKUP = TemplateLookup(directories=[_dir + 'templates', _dir + 'htdocs'],
                            module_directory=_dir + 'modules',
                            input_encoding='utf-8',
                            output_encoding='utf-8')

    setup_logging("rp_%s.log" % CONF.PORT)

    RP_ARGS = {"lookup": LOOKUP, "conf": CONF, "test_flows": TEST_FLOWS,
               "cache": {}, "test_profile": TEST_PROFILE, "profiles": PROFILES}

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', CONF.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    if CONF.BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            CONF.SERVER_CERT, CONF.SERVER_KEY, CONF.CA_BUNDLE)
        extra = " using SSL/TLS"
    else:
        extra = ""

    txt = "RP server starting listening on port:%s%s" % (CONF.PORT, extra)
    LOGGER.info(txt)
    print txt
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
