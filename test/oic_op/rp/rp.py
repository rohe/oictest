#!/usr/bin/env python
import importlib
import argparse
from jwkest.jws import alg2keytype
from mako.lookup import TemplateLookup
from urlparse import parse_qs
from oic.oauth2 import rndstr

from oic.utils.http_util import NotFound, get_post
from oic.utils.http_util import Response
from oic.utils.http_util import Redirect

import logging
import sys
from oictest.graph import flatten, in_tree, node_cmp
from oictest import testflows
from oictest.base import Conversation
from oic.oic.message import factory as message_factory
from oictest.check import factory as check_factory
from oictest.testflows import Discover, Notice
from rrtest import Trace, exception_trace
from script.oic_flow_tests import sort_flows_into_graph

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'rp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

CPC = ('%(asctime)s %(name)s:%(levelname)s '
       '[%(client)s,%(path)s,%(cid)s] %(message)s')
cpc_formatter = logging.Formatter(CPC)

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

SERVER_ENV = {}


#noinspection PyUnresolvedReferences
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
    if _sum["status"] <= 1:
        resp = Response(mako_template="flowlist.mako",
                        template_lookup=LOOKUP,
                        headers=[])
        argv = {
            "flows": session["tests"],
            "flow": session["testid"],
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
    argv = {"base": CONF.BASE, "flows": flows, "flow": ""}

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


#
def get_id_token(client, session):
    return client.grant[session["state"]].get_id_token()


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
    ots = OIDCTestSetup(CONF, testflows)
    session["testid"] = path
    session["node"] = in_tree(session["graph"], path)
    sequence_info = ots.make_sequence(path)
    sequence_info = ots.add_init(sequence_info)
    session["seq_info"] = sequence_info
    trace = Trace()
    client_conf = ots.config.CLIENT
    conv = Conversation(ots.client, client_conf, trace, None,
                        message_factory, check_factory)
    session["ots"] = ots
    session["conv"] = conv
    session["index"] = index
    session["response_type"] = ""

    return conv, sequence_info, ots, trace, index


def run_sequence(sequence_info, session, conv, ots, environ, start_response, 
                 trace, index):
    while index < len(sequence_info["sequence"]):
        session["index"] = index
        try:
            req_c, resp_c = sequence_info["sequence"][index]
        except (ValueError, TypeError):  # Not a tuple
            req = sequence_info["sequence"][index]()
            if isinstance(req, Notice):
                return req(LOOKUP, environ, start_response,
                           **{"url": "%scontinue" % CONF.BASE,
                              "op": conv.client.provider_info["issuer"]})
            else:
                req(conv)
        else:
            req = req_c(conv)
            try:
                conv.test_sequence(req.tests["pre"])
            except KeyError, err:
                pass

            conv.request_spec = req

            if req_c == Discover:  # Special since it's just a GET on a URL
                _r = req.discover(
                    ots.client, issuer=ots.config.CLIENT["srv_discovery_url"])
                conv.position, conv.last_response, conv.last_content = _r
                conv.provider_info = ots.client.provider_info
            else:
                if req.request == "AuthorizationRequest":
                    session["state"] = rndstr()  # New state for each request
                    kwargs = {"request_args": {"state": session["state"]}}
                elif req.request in ["AccessTokenRequest", "UserInfoRequest",
                                     "RefreshAccessTokenRequest"]:
                    kwargs = {"state": session["state"]}
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
                    resp = Redirect(str(url))
                    return resp(environ, start_response)
                else:
                    _kwargs = {"http_args": ht_args}
                    if "state" in session:
                        _kwargs["state"] = session["state"]

                    response = request_and_return(
                        conv, url, message_factory(resp_c.response), req.method,
                        body, resp_c.ctype, **_kwargs)
                    trace.info(response.to_dict())
                    if resp_c.response == "RegistrationResponse":
                        ots.client.store_registration_info(response)

        try:
            conv.test_sequence(req.tests["post"])
        except KeyError:
            pass

        index += 1

    # wrap it up
    try:
        conv.test_sequence(sequence_info["tests"]["post"])
    except KeyError:
        pass
    return opresult(environ, start_response, conv, session)


def session_init(session):
    graph = sort_flows_into_graph(testflows.FLOWS)
    session["graph"] = graph
    session["tests"] = [x for x in flatten(graph)]
    session["tests"].sort(node_cmp)
    session["flow_names"] = [x.name for x in session["tests"]]


def application(environ, start_response):
    session = environ['beaker.session']

    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)

    if path.startswith("export/"):
        return static(environ, start_response, LOGGER, path)

    if path == "":  # list
        session_init(session)
        return flow_list(environ, start_response, session["tests"])
    elif "flow_names" not in session:
        session_init(session)

    if path == "continue":
        try:
            sequence_info = session["seq_info"]
        except KeyError:  # Cookie delete broke session
            query = parse_qs(environ["QUERY_STRING"])
            path = query["path"][0]
            index = query["index"][0]
            conv, sequence_info, ots, trace, index = session_setup(session,
                                                                   path, index)
        else:
            index = session["index"]
            ots = session["ots"]
            conv = session["conv"]

        index += 1
        try:
            return run_sequence(sequence_info, session, conv, ots, environ,
                                start_response, conv.trace, index)
        except Exception, err:
            return test_error(environ, start_response, conv, err)
    # expected path format: /<testid>[/<endpoint>]
    elif path in session["flow_names"]:
        conv, sequence_info, ots, trace, index = session_setup(session, path)
        try:
            conv.test_sequence(sequence_info["tests"]["pre"])
        except KeyError:
            pass

        try:
            return run_sequence(sequence_info, session, conv, ots, environ,
                                start_response, trace, index)
        except Exception, err:
            session["node"].state = 3
            exception_trace("run_sequence", err, trace)
            return test_error(environ, start_response, conv, err)
    else:
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

            resp_cls = message_factory(resp_c.response)
            response = ots.client.parse_response(resp_cls, info, resp_c.ctype,
                                                 session["state"],
                                                 keyjar=ots.client.keyjar)

            conv.protocol_response.append((response, info))

        try:
            req = req_c(conv)
            _tests = req.tests["post"][:]  # make a copy
        except KeyError:
            pass
        else:
            conv.test_sequence(_tests)

        index += 1
        try:
            return run_sequence(sequence_info, session, conv, ots, environ,
                                start_response, conv.trace, index)
        except Exception, err:
            return test_error(environ, start_response, conv, err)

if __name__ == '__main__':
    from oidc import OIDCTestSetup, request_and_return, test_summation
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver

    parser = argparse.ArgumentParser()
    parser.add_argument('-m', dest='mailaddr')
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

    CONF = importlib.import_module(sys.argv[1])

    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": CONF.BASE})

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', CONF.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    if CONF.BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            CONF.SERVER_CERT, CONF.SERVER_KEY, CONF.CA_BUNDLE)

    LOGGER.info("RP server starting listening on port:%s" % CONF.PORT)
    print "RP server starting listening on port:%s" % CONF.PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
