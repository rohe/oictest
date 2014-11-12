#!/usr/bin/env python
import importlib
import logging
from urlparse import parse_qs
import argparse
from mako.lookup import TemplateLookup
from oic.utils.http_util import get_post
from rp import static
from rp import session_init
from rp import flow_list
from rp import session_setup
from rp import run_sequence
from rp import test_error
from rp import opresult_fragment
from rrtest import exception_trace
from uma.message import factory
import rs_vs_as_tests

__author__ = 'roland'

SERVER_ENV = {}

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

from beaker.middleware import SessionMiddleware
from cherrypy import wsgiserver


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
        session_init(session, CONF, LOOKUP, testflows=rs_vs_as_tests)
        return flow_list(environ, start_response, session["tests"], session)
    elif "flow_names" not in session:
        session_init(session, CONF, LOOKUP, testflows=rs_vs_as_tests)

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
            return test_error(environ, start_response, conv, err, session)
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
                return opresult_fragment(environ, start_response, session)
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
            resp_cls = factory(resp_c.response)
            response = ots.client.parse_response(resp_cls, info, resp_c.ctype,
                                                 session["state"],
                                                 keyjar=ots.client.keyjar)

            LOGGER.info("Parsed response: %s" % response.to_dict())
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
            return test_error(environ, start_response, conv, err, session)


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

LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')

CONF = importlib.import_module(args.config)

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
