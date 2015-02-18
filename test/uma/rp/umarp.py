#!/usr/bin/env python
import importlib
import argparse
import logging
import sys
from jwkest import JWKESTException

from mako.lookup import TemplateLookup
from oic.exception import PyoidcError

from oic.oauth2 import rndstr
from oic.oauth2.dynreg import ClientInfoResponse
from oic.oic import PARAMMAP, DEF_SIGN_ALG
from oic.utils.http_util import Redirect
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
from oictest.oprp import endpoint_support
from oictest.oprp import post_tests
from oictest.oprp import NotSupported
from oictest.oprp import dump_log
from oictest.oprp import setup
from oictest.oprp import pprint_json
from oictest.oprp import setup_logging

from rrtest import Trace
from rrtest.check import ERROR, OK

from testclass import OIDCDiscover
from testclass import UMADiscover
from testclass import Webfinger

LOGGER = logging.getLogger("")

MODULE2FACTORY = {
    "oic.oic.message": oic_message_factory,
    "oic.oauth2.dynreg": dynreg_message_factory,
    "uma.message": uma_message_factory
}


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

        resp = Redirect("%sopresult#%s" % (CONF.BASE, _tid[3]))
        return resp(self.environ, self.start_response)

if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='mailaddr')
    parser.add_argument('-t', dest='target')
    parser.add_argument('-r', dest='role')
    parser.add_argument('-d', dest='directory')
    parser.add_argument('-p', dest='profile')
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

    oprp = UMAoprp(LOOKUP, CONF, TEST_FLOWS, CACHE, TEST_PROFILE)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', CONF.PORT),
                                        SessionMiddleware(oprp.application,
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
