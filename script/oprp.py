#!/usr/bin/env python
import importlib
import argparse
import logging
import sys

from jwkest.jws import alg2keytype
from mako.lookup import TemplateLookup
from urlparse import parse_qs

from oic.oauth2 import rndstr
from oic.oauth2 import ResponseError
from oic.utils.http_util import NotFound
from oic.utils.http_util import get_post
from oic.utils.http_util import BadRequest
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect
from oic.oic.message import AccessTokenResponse
from oic.oic.message import factory as message_factory
from oic.oic.message import OpenIDSchema

from oictest.graph import flatten
from oictest.graph import in_tree
from oictest.graph import node_cmp
from oictest.base import Conversation
from oictest.check import factory as check_factory
from oictest.check import CheckEndpoint
from oictest.check import CheckTokenEndpointAuthMethod
from oictest.check import CheckSupportedTrue
from oictest.check import CheckRequestURIParameterSupported
from oictest.check import get_protocol_response
from oictest.check import CheckOPSupported
from oictest.graph import sort_flows_into_graph
from oictest.oidcrp import test_summation
from oictest.oidcrp import OIDCTestSetup
from oictest.oidcrp import request_and_return

from rrtest import Trace, exception_trace

LOGGER = logging.getLogger("")

LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

SERVER_ENV = {}


def setup_logging(logfile):
    hdlr = logging.FileHandler(logfile)
    base_formatter = logging.Formatter(
        "%(asctime)s %(name)s:%(levelname)s %(message)s")

    hdlr.setFormatter(base_formatter)
    LOGGER.addHandler(hdlr)
    LOGGER.setLevel(logging.DEBUG)


def static(environ, start_response, logger, path):
    logger.info("[static]sending: %s" % (path,))

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


def opchoice(environ, start_response, clients):
    resp = Response(mako_template="opchoice.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "op_list": clients.keys()
    }
    return resp(environ, start_response, **argv)


def opresult(environ, start_response, conv, session):
    _sum = test_summation(conv, session["testid"])
    session["node"].state = _sum["status"]
    if _sum["status"] <= 2:  # don't break for warning
        resp = Response(mako_template="flowlist.mako",
                        template_lookup=LOOKUP,
                        headers=[])
        argv = {
            "flows": session["tests"],
            "flow": session["testid"],
            "test_info": session["test_info"].keys(),
            "base": CONF.BASE
        }
    else:
        resp = Response(mako_template="failed.mako",
                        template_lookup=LOOKUP,
                        headers=[])
        argv = {
            "trace": conv.trace,
            "output": conv.test_output,
        }
    return resp(environ, start_response, **argv)


def operror(environ, start_response, error=None):
    resp = Response(mako_template="operror.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "error": error
    }
    return resp(environ, start_response, **argv)


def opresult_fragment(environ, start_response):
    resp = Response(mako_template="opresult_repost.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {}
    return resp(environ, start_response, **argv)


def flow_list(environ, start_response, flows):
    resp = Response(mako_template="flowlist.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {"base": CONF.BASE, "flows": flows, "flow": "", "test_info": []}

    return resp(environ, start_response, **argv)


def test_error(environ, start_response, conv, exc):
    resp = Response(mako_template="testerror.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "trace": conv.trace,
        "output": conv.test_output,
        "exception": exc
    }

    return resp(environ, start_response, **argv)


def test_info(environ, start_response, testid, info):
    resp = Response(mako_template="testinfo.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
        "id": testid,
        "trace": info["trace"],
        "output": info["test_output"],
    }

    return resp(environ, start_response, **argv)


def not_found(environ, start_response):
    """Called if no URL matches."""
    resp = NotFound()
    return resp(environ, start_response)


#
def get_id_token(client, conv):
    return client.grant[conv.AuthorizationRequest["state"]].get_id_token()


# Produce a JWS, a signed JWT, containing a previously received ID token
def id_token_as_signed_jwt(client, id_token, alg="RS256"):
    ckey = client.keyjar.get_signing_key(alg2keytype(alg), "")
    _signed_jwt = id_token.to_jwt(key=ckey, algorithm=alg)
    return _signed_jwt


def clear_session(session):
    for key in session:
        session.pop(key, None)
    session.invalidate()


def session_setup(session, path, index=0):
    _keys = session.keys()
    for key in _keys:
        if key.startswith("_"):
            continue
        elif key in ["tests", "graph", "flow_names", "response_type",
                     "test_info"]:
            continue
        else:
            del session[key]

    ots = OIDCTestSetup(CONF, TEST_FLOWS, str(CONF.PORT))
    session["testid"] = path
    session["node"] = in_tree(session["graph"], path)
    sequence_info = ots.make_sequence(path)
    sequence_info = ots.add_init(sequence_info)
    session["seq_info"] = sequence_info
    trace = Trace()
    client_conf = ots.config.CLIENT
    conv = Conversation(ots.client, client_conf, trace, None,
                        message_factory, check_factory)
    conv.cache = CACHE
    session["ots"] = ots
    session["conv"] = conv
    session["index"] = index
    session["response_type"] = ""

    return conv, sequence_info, ots, trace, index


def verify_support(conv, ots, graph):
    """
    Verifies whether a OP is likely to be able to pass a specific test.
    All based on the checks that are run before the requests within a
    slow is sent.

    :param conv: The conversation
    :param ots: The OIDC RP setup.
    :param graph: A graph representation of the possible test flows.
    """
    for key, val in ots.test_defs.FLOWS.items():
        sequence_info = ots.make_sequence(key)
        for op in sequence_info["sequence"]:
            try:
                req, resp = op
            except TypeError:
                continue

            conv.req = req(conv)
            if issubclass(req, TEST_FLOWS.AccessTokenRequest):
                chk = CheckTokenEndpointAuthMethod()
                res = chk(conv)
                if res["status"] > 1:
                    node = in_tree(graph, key)
                    node.state = 4

            if "pre" in conv.req.tests:
                for test in conv.req.tests["pre"]:
                    do_check = False
                    for check in [CheckTokenEndpointAuthMethod,
                                  CheckOPSupported,
                                  CheckSupportedTrue, CheckEndpoint,
                                  CheckRequestURIParameterSupported,
                                  CheckTokenEndpointAuthMethod]:
                        if issubclass(test, check):
                            do_check = True
                            break

                    if do_check:
                        chk = test()
                        res = chk(conv)
                        if res["status"] > 1:
                            node = in_tree(graph, key)
                            node.state = 4


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

    try:
        inst = resp_c()
        _tests = inst.tests["post"]
    except KeyError:
        pass
    else:
        if _tests:
            conv.test_output.append((resp_c.response, "post"))
            conv.test_sequence(_tests)


def err_response(environ, start_response, session, where, err):
    session["node"].state = 3
    exception_trace(where, err)
    return flow_list(environ, start_response, session["tests"])


def none_request_response(sequence_info, index, session, conv, environ,
                          start_response):
    req = sequence_info["sequence"][index]()
    if isinstance(req, TEST_FLOWS.Notice):
        kwargs = {
            "url": "%scontinue?path=%s&index=%d" % (
                CONF.BASE, session["testid"], session["index"]),
            "back": CONF.BASE}
        try:
            kwargs["note"] = sequence_info["note"]
        except KeyError:
            pass
        try:
            kwargs["op"] = conv.client.provider_info["issuer"]
        except (KeyError, TypeError):
            pass

        if isinstance(req, TEST_FLOWS.DisplayUserInfo):
            for presp, _ in conv.protocol_response:
                if isinstance(presp, OpenIDSchema):
                    kwargs["table"] = presp
                    break
        elif isinstance(req, TEST_FLOWS.DisplayIDToken):
            instance, _ = get_protocol_response(
                conv, AccessTokenResponse)[0]
            kwargs["table"] = instance["id_token"]

        try:
            key = req.cache(CACHE, conv, sequence_info["cache"])
        except KeyError:
            pass
        else:
            kwargs["url"] += "&key=%s" % key

        return req(LOOKUP, environ, start_response, **kwargs)
    else:
        try:
            req(conv)
            return None
        except TEST_FLOWS.RequirementsNotMet as err:
            return err_response(environ, start_response, session,
                                "run_sequence", err)


def run_sequence(sequence_info, session, conv, ots, environ, start_response,
                 trace, index):
    while index < len(sequence_info["sequence"]):
        session["index"] = index
        try:
            req_c, resp_c = sequence_info["sequence"][index]
        except (ValueError, TypeError):  # Not a tuple
            ret = none_request_response(sequence_info, index, session, conv,
                                        environ, start_response)
            if ret:
                return ret
        else:
            req = req_c(conv)
            try:
                if req.tests["pre"]:
                    conv.test_output.append((req.request, "pre"))
                    conv.test_sequence(req.tests["pre"])
            except KeyError:
                pass

            conv.request_spec = req

            if req_c == TEST_FLOWS.Discover:
                # Special since it's just a GET on a URL
                _r = req.discover(
                    ots.client, issuer=ots.config.CLIENT["srv_discovery_url"])
                conv.position, conv.last_response, conv.last_content = _r
                logging.debug("Provider info: %s" % conv.last_content._dict)
                verify_support(conv, ots, session["graph"])
            else:
                LOGGER.info("request: %s" % req.request)
                if req.request == "AuthorizationRequest":
                    # New state for each request
                    kwargs = {"request_args": {"state": rndstr()}}
                elif req.request in ["AccessTokenRequest", "UserInfoRequest",
                                     "RefreshAccessTokenRequest"]:
                    kwargs = {"state": conv.AuthorizationRequest["state"]}
                else:
                    kwargs = {}

                # Extra arguments outside the OIDC spec
                try:
                    _extra = ots.config.CLIENT["extra"][req.request]
                except KeyError:
                    pass
                else:
                    try:
                        kwargs["request_args"].update(_extra)
                    except KeyError:
                        kwargs["request_args"] = _extra

                req.call_setup()
                url, body, ht_args = req.construct_request(ots.client, **kwargs)

                if req.request == "AuthorizationRequest":
                    session["response_type"] = req.request_args["response_type"]
                    LOGGER.info("redirect.url: %s" % url)
                    LOGGER.info("redirect.header: %s" % ht_args)
                    resp = Redirect(str(url))
                    return resp(environ, start_response)
                else:
                    _kwargs = {"http_args": ht_args}
                    try:
                        _kwargs["state"] = conv.AuthorizationRequest["state"]
                    except AttributeError:
                        pass

                    response = request_and_return(
                        conv, url, message_factory(resp_c.response), req.method,
                        body, resp_c.ctype, **_kwargs)
                    trace.info(response.to_dict())
                    LOGGER.info(response.to_dict())
                    if resp_c.response == "RegistrationResponse":
                        ots.client.store_registration_info(response)

            post_tests(conv, req_c, resp_c)

        index += 1
        _tid = session["testid"]
        session["test_info"][_tid] = {"trace": conv.trace,
                                      "test_output": conv.test_output}

    # wrap it up
    # Any after the fact tests ?
    try:
        if sequence_info["tests"]:
            conv.test_output.append(("After completing the test", ""))
            conv.test_sequence(sequence_info["tests"])
    except KeyError:
        pass

    _tid = session["testid"]
    session["test_info"][_tid] = {"trace": conv.trace,
                                  "test_output": conv.test_output}

    resp = Redirect("%sopresult#%s" % (CONF.BASE, _tid[3]))
    return resp(environ, start_response)


def init_session(session):
    graph = sort_flows_into_graph(TEST_FLOWS.FLOWS)
    session["graph"] = graph
    session["tests"] = [x for x in flatten(graph)]
    session["tests"].sort(node_cmp)
    session["flow_names"] = [x.name for x in session["tests"]]
    session["response_type"] = []
    session["test_info"] = {}


def reset_session(session):
    _keys = session.keys()
    for key in _keys:
        if key.startswith("_"):
            continue
        else:
            del session[key]
    init_session(session)


def session_init(session):
    if "graph" not in session:
        init_session(session)
        return True
    else:
        for
        return False


def application(environ, start_response):
    LOGGER.info("Connection from: %s" % environ["REMOTE_ADDR"])
    session = environ['beaker.session']

    path = environ.get('PATH_INFO', '').lstrip('/')
    LOGGER.info("path: %s" % path)

    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")
    elif path == "favicon.ico":
        return static(environ, start_response, LOGGER, "static/favicon.ico")

    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    if path.startswith("export/"):
        return static(environ, start_response, LOGGER, path)

    if path == "":  # list
        if session_init(session):
            return flow_list(environ, start_response, session["tests"])
        else:
            try:
                resp = Redirect("%sopresult#%s" % (CONF.BASE,
                                                   session["testid"][0]))
            except KeyError:
                return flow_list(environ, start_response, session["tests"])
            else:
                return resp(environ, start_response)
    elif "flow_names" not in session:
        session_init(session)
    elif path == "reset":
        reset_session(session)
        return flow_list(environ, start_response, session["tests"])
    elif path.startswith("test_info"):
        p = path.split("/")
        try:
            return test_info(environ, start_response, p[1],
                             session["test_info"][p[1]])
        except KeyError:
            return not_found(environ, start_response)
    if path == "continue":
        try:
            sequence_info = session["seq_info"]
        except KeyError:  # Cookie delete broke session
            query = parse_qs(environ["QUERY_STRING"])
            path = query["path"][0]
            index = int(query["index"][0])
            conv, sequence_info, ots, trace, index = session_setup(session,
                                                                   path, index)
            try:
                conv.cache_key = query["key"][0]
            except KeyError:
                pass
        else:
            index = session["index"]
            ots = session["ots"]
            conv = session["conv"]

        index += 1
        try:
            return run_sequence(sequence_info, session, conv, ots, environ,
                                start_response, conv.trace, index)
        except Exception, err:
            return err_response(environ, start_response, session,
                                "run_sequence", err)
    elif path == "opresult":
        conv = session["conv"]
        return opresult(environ, start_response, conv, session)
    # expected path format: /<testid>[/<endpoint>]
    elif path in session["flow_names"]:
        conv, sequence_info, ots, trace, index = session_setup(session, path)

        try:
            return run_sequence(sequence_info, session, conv, ots, environ,
                                start_response, trace, index)
        except Exception, err:
            return err_response(environ, start_response, session,
                                "run_sequence", err)
    elif path in ["authz_cb", "authz_post"]:
        if path != "authz_post":
            if not session["response_type"] == ["code"]:
                return opresult_fragment(environ, start_response)
        sequence_info = session["seq_info"]
        index = session["index"]
        ots = session["ots"]
        conv = session["conv"]
        req_c, resp_c = sequence_info["sequence"][index]

        if resp_c:  # None in cases where no OIDC response is expected
            # parse the response
            if path == "authz_post":
                query = parse_qs(get_post(environ))
                info = query["fragment"][0]
            elif resp_c.where == "url":
                info = environ["QUERY_STRING"]
            else:  # resp_c.where == "body"
                info = get_post(environ)

            LOGGER.info("Response: %s" % info)
            resp_cls = message_factory(resp_c.response)
            try:
                response = ots.client.parse_response(
                    resp_cls, info, resp_c.ctype,
                    conv.AuthorizationRequest["state"],
                    keyjar=ots.client.keyjar)
            except ResponseError as err:
                return err_response(environ, start_response, session,
                                    "run_sequence", err)

            LOGGER.info("Parsed response: %s" % response.to_dict())
            conv.protocol_response.append((response, info))

        post_tests(conv, req_c, resp_c)

        index += 1
        try:
            return run_sequence(sequence_info, session, conv, ots, environ,
                                start_response, conv.trace, index)
        except Exception as err:
            return err_response(environ, start_response, session,
                                "run_sequence", err)
    else:
        resp = BadRequest()
        return resp(environ, start_response)

if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='mailaddr')
    parser.add_argument('-t', dest='testflows')
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
    CONF = importlib.import_module(sys.argv[1])

    if args.testflows:
        TEST_FLOWS = importlib.import_module(args.testflows)
    else:
        TEST_FLOWS = importlib.import_module("oictest.testflows")

    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": CONF.BASE})

    setup_logging("rp_%s.log" % CONF.PORT)

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
