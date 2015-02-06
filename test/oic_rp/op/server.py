#!/usr/bin/env python
# -*- coding: utf-8 -*-
import json
import re
import os
import sys
import traceback

from exceptions import KeyError
from exceptions import Exception
from exceptions import OSError
from exceptions import IndexError
from exceptions import AttributeError
from exceptions import KeyboardInterrupt
from urlparse import parse_qs
from urlparse import urlparse
from beaker.middleware import SessionMiddleware
from dirg_util.http_util import HttpHandler

from oic.oic.provider import EndSessionEndpoint
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import *
from oic.utils.keyio import keyjar_init
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo
from oic.utils.webfinger import WebFinger
from oic.utils.webfinger import OIC_ISSUER
from rrtest import Trace
from oictest.mode import extract_mode
from oictest.mode import setup_op
from oictest.mode import mode2path
from response_encoder import ResponseEncoder
from oic.utils.client_management import CDB
__author__ = 'rohe0002'

from mako.lookup import TemplateLookup

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'oc.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

CPC = ('%(asctime)s %(name)s:%(levelname)s '
       '[%(client)s,%(path)s,%(cid)s] %(message)s')
cpc_formatter = logging.Formatter(CPC)

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

URLMAP = {}
NAME = "pyoic"
OAS = None

PASSWD = {
    "diana": "krall",
    "babs": "howes",
    "upper": "crust"
}

HEADER = "---------- %s ----------"

# ----------------------------------------------------------------------------


#noinspection PyUnusedLocal
def safe(environ, start_response):
    _oas = environ["oic.oas"]
    _srv = _oas.server
    _log_info = _oas.logger.info

    _log_info("- safe -")
    #_log_info("env: %s" % environ)
    #_log_info("handle: %s" % (handle,))

    try:
        _authz = environ["HTTP_AUTHORIZATION"]
        (_typ, code) = _authz.split(" ")
        assert _typ == "Bearer"
    except KeyError:
        resp = BadRequest("Missing authorization information")
        return resp(environ, start_response)

    try:
        _sinfo = _srv.sdb[code]
    except KeyError:
        resp = Unauthorized("Not authorized")
        return resp(environ, start_response)

    _info = "'%s' secrets" % _sinfo["sub"]
    resp = Response(_info)
    return resp(environ, start_response)


#noinspection PyUnusedLocal
def css(environ, start_response, session):
    try:
        _info = open(environ["PATH_INFO"]).read()
        resp = Response(_info)
    except (OSError, IOError):
        resp = NotFound(environ["PATH_INFO"])

    return resp(environ, start_response)

# ----------------------------------------------------------------------------


def display_log(environ, start_response):
    path = environ.get('PATH_INFO', '').lstrip('/')
    if path == "log":
        tail = environ["REMOTE_ADDR"]
        path = os.path.join(path, tail)
    elif path == "logs":
        path = "log"

    if os.path.isfile(path):
        return static(environ, start_response, path)
    elif os.path.isdir(path):
        item = []
        for (dirpath, dirnames, filenames) in os.walk(path):
            if dirnames:
                item = [(fn, os.path.join(path, fn)) for fn in dirnames]
                break
            if filenames:
                item = [(fn, os.path.join(path, fn)) for fn in filenames]
                break

        item.sort()
        resp = Response(mako_template="logs.mako",
                        template_lookup=LOOKUP,
                        headers=[])
        argv = {"logs": item}

        return resp(environ, start_response, **argv)
    else:
        resp = Response("No saved logs")
        return resp(environ, start_response)


def dump_log(session, trace):
    try:
        _path = session["path"]
    except KeyError:
        base = "log"
        addr = session._environ["REMOTE_ADDR"]
        _base = os.path.join(base, addr)

        if not os.path.isdir(_base):
            os.makedirs(_base)

        _path = os.path.join(base, addr, session["test_id"])

    output = "%s" % trace
    output += "\n\n"

    fil = open(_path, "a")
    fil.write(output)
    fil.close()
    return _path


def wsgi_wrapper(environ, start_response, func, session, trace):
    kwargs = extract_from_request(environ)
    trace.request(kwargs["request"])
    args = func(**kwargs)

    try:
        resp, state = args
        trace.reply(resp.message)
        dump_log(session, trace)
        return resp(environ, start_response)
    except TypeError:
        resp = args
        trace.reply(resp.message)
        dump_log(session, trace)
        return resp(environ, start_response)
    except Exception as err:
        LOGGER.error("%s" % err)
        trace.error("%s" % err)
        dump_log(session, trace)
        raise

# ----------------------------------------------------------------------------


#noinspection PyUnusedLocal
def token(environ, start_response, session, trace):
    trace.info(HEADER % "AccessToken")
    _oas = session["op"]

    return wsgi_wrapper(environ, start_response, _oas.token_endpoint, session,
                        trace)


#noinspection PyUnusedLocal
def authorization(environ, start_response, session, trace):
    trace.info(HEADER % "Authorization")
    _oas = session["op"]

    return wsgi_wrapper(environ, start_response, _oas.authorization_endpoint,
                        session, trace)


#noinspection PyUnusedLocal
def userinfo(environ, start_response, session, trace):
    trace.info(HEADER % "UserInfo")
    _oas = session["op"]
    return wsgi_wrapper(environ, start_response, _oas.userinfo_endpoint,
                        session, trace)


#noinspection PyUnusedLocal
def op_info(environ, start_response, session, trace):
    trace.info(HEADER % "ProviderConfiguration")
    trace.request("PATH: %s" % environ["PATH_INFO"])
    try:
        trace.request("QUERY: %s" % environ["QUERY_STRING"])
    except KeyError:
        pass
    _oas = session["op"]
    return wsgi_wrapper(environ, start_response, _oas.providerinfo_endpoint,
                        session, trace)


#noinspection PyUnusedLocal
def registration(environ, start_response, session, trace):
    trace.info(HEADER % "ClientRegistration")
    _oas = session["op"]

    if environ["REQUEST_METHOD"] == "POST":
        return wsgi_wrapper(environ, start_response, _oas.registration_endpoint,
                            session, trace)
    elif environ["REQUEST_METHOD"] == "GET":
        return wsgi_wrapper(environ, start_response, _oas.read_registration,
                            session, trace)
    else:
        resp = ServiceError("Method not supported")
        return resp(environ, start_response)


#noinspection PyUnusedLocal
def check_id(environ, start_response, session, trace):
    _oas = session["op"]

    return wsgi_wrapper(environ, start_response, _oas.check_id_endpoint,
                        session, trace)


#noinspection PyUnusedLocal
def endsession(environ, start_response, session, trace):
    _oas = session["op"]
    return wsgi_wrapper(environ, start_response, _oas.endsession_endpoint,
                        session, trace)


def find_identifier(uri):
    if uri.startswith("http"):
        p = urlparse(uri)
        return p.path[1:]  # Skip leading "/"
    elif uri.startswith("acct:"):
        a = uri[5:]
        l, d = a.split("@")
        return l


def webfinger(environ, start_response, session, trace):
    query = parse_qs(environ["QUERY_STRING"])

    # Find the identifier
    session["test_id"] = find_identifier(query["resource"][0])

    trace.info(HEADER % "WebFinger")
    trace.request(environ["QUERY_STRING"])
    trace.info("QUERY: %s" % (query,))

    try:
        assert query["rel"] == [OIC_ISSUER]
        resource = query["resource"][0]
    except AssertionError:
        errmsg = "Wrong 'rel' value: %s" % query["rel"][0]
        trace.error(errmsg)
        resp = BadRequest(errmsg)
    except KeyError:
        errmsg = "Missing 'rel' parameter in request"
        trace.error(errmsg)
        resp = BadRequest(errmsg)
    else:
        wf = WebFinger()
        p = urlparse(resource)
        mode, part = extract_mode(p[2])
        if mode:
            resp = Response(wf.response(subject=resource,
                                        base=OP_ARG["baseurl"]+p[2][1:]))
        else:
            resp = Response(wf.response(subject=resource,
                                        base=OP_ARG["baseurl"]))

        trace.reply(resp.message)

    dump_log(session, trace)
    return resp(environ, start_response)


#noinspection PyUnusedLocal
def verify(environ, start_response, session, trace):
    _oas = session["op"]
    return wsgi_wrapper(environ, start_response, _oas.verify_endpoint)


def static_file(path):
    try:
        os.stat(path)
        return True
    except OSError:
        return False


#noinspection PyUnresolvedReferences
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
        elif path.endswith(".txt"):
            start_response('200 OK', [('Content-Type', 'text/plain')])
        elif path.endswith(".css"):
            start_response('200 OK', [('Content-Type', 'text/css')])
        else:
            start_response('200 OK', [('Content-Type', 'text/plain')])
        return [text]
    except IOError:
        resp = NotFound()
        return resp(environ, start_response)

# ----------------------------------------------------------------------------
from oic.oic.provider import AuthorizationEndpoint
from oic.oic.provider import TokenEndpoint
from oic.oic.provider import UserinfoEndpoint
from oic.oic.provider import RegistrationEndpoint

ENDPOINTS = [
    AuthorizationEndpoint(authorization),
    TokenEndpoint(token),
    UserinfoEndpoint(userinfo),
    RegistrationEndpoint(registration),
    EndSessionEndpoint(endsession),
]

URLS = [
    (r'^verify', verify),
    (r'.well-known/openid-configuration', op_info),
    (r'.well-known/webfinger', webfinger),
    (r'.+\.css$', css),
    (r'safe', safe),
    (r'log', display_log)
]

def add_endpoints(extra):
    global URLS

    for endp in extra:
        URLS.append(("^%s" % endp.etype, endp))

# ----------------------------------------------------------------------------

ROOT = './'

LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')

# ----------------------------------------------------------------------------

def rp_test_list(environ, start_response):
    resp = Response(mako_template="rp_test_list.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    return resp(environ, start_response)

def registration(environ, start_response):
    resp = Response(mako_template="registration.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    return resp(environ, start_response)

def generate_static_client_credentials(parameters):
    redirect_uris = parameters['redirect_uris']
    cdb = CDB(config.CLIENT_DB + ".db")
    static_client = cdb.create(redirect_uris=redirect_uris, policy_uri="example.com",logo_uri="example.com")
    return static_client['client_id'], static_client['client_secret']


def application(environ, start_response):
    """
    :param environ: The HTTP application environment
    :param start_response: The application to run when the handling of the
        request is done
    :return: The response as a list of lines
    """
    global OAS
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')
    http_helper = HttpHandler(environ, start_response, session, LOGGER)
    response_encoder = ResponseEncoder(environ=environ, start_response=start_response)
    parameters = http_helper.query_dict()

    if path == "robots.txt":
        return static(environ, start_response, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, path)
    elif path.startswith("export/"):
        return static(environ, start_response, path)
    elif path.startswith("log"):
        return display_log(environ, start_response)
    elif path.startswith("_static/"):
        return static(environ, start_response, path)
    
    trace = Trace()

    mode, endpoint = extract_mode(path)

    if mode:
        session["test_id"] = mode["test_id"]

    if path == "test_list":
        return rp_test_list(environ, start_response)
    elif path == "":
        return registration(environ, start_response)
    elif path == "generate_client_credentials":
        client_id, client_secret = generate_static_client_credentials(parameters)
        return response_encoder.returnJSON(json.dumps({"client_id": client_id, "client_secret": client_secret}))


    if "op" not in session:
        session["op"] = setup_op(mode, COM_ARGS, OP_ARG)
        session["mode_path"] = mode2path(mode)
    else:  # may be a new mode
        _path = mode2path(mode)
        if session["mode_path"] != _path:
            session["op"] = setup_op(mode, COM_ARGS, OP_ARG)
            session["mode_path"] = _path

    for regex, callback in URLS:
        match = re.search(regex, endpoint)
        if match is not None:
            trace.request("PATH: %s" % endpoint)
            trace.request("METHOD: %s" % environ["REQUEST_METHOD"])
            try:
                trace.request(
                    "HTTP_AUTHORIZATION: %s" % environ["HTTP_AUTHORIZATION"])
            except KeyError:
                pass

            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = endpoint

            LOGGER.info("callback: %s" % callback)
            try:
                return callback(environ, start_response, session, trace)
            except Exception as err:
                print >> sys.stderr, "%s" % err
                message = traceback.format_exception(*sys.exc_info())
                print >> sys.stderr, message
                LOGGER.exception("%s" % err)
                resp = ServiceError("%s" % err)
                return resp(environ, start_response)

    LOGGER.debug("unknown side: %s" % endpoint)
    resp = NotFound("Couldn't find the side you asked for!")
    return resp(environ, start_response)


# ----------------------------------------------------------------------------


if __name__ == '__main__':
    import argparse
    import shelve
    import importlib

    from cherrypy import wsgiserver
    from cherrypy.wsgiserver import ssl_pyopenssl

    from oic.oic.provider import Provider

    parser = argparse.ArgumentParser()
    parser.add_argument('-v', dest='verbose', action='store_true')
    parser.add_argument('-d', dest='debug', action='store_true')
    parser.add_argument('-p', dest='port', default=80, type=int)
    parser.add_argument('-k', dest='insecure', action='store_true')
    parser.add_argument(dest="config")
    args = parser.parse_args()

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    config.issuer = config.issuer % args.port
    config.SERVICE_URL = config.SERVICE_URL % args.port

    # Client data base
    cdb = shelve.open(config.CLIENT_DB, writeback=True)

    SETUP = {}

    ac = AuthnBroker()

    for authkey, value in config.AUTHENTICATION.items():
        authn = None
        # if "UserPassword" == authkey:
        #     from oic.utils.authn.user import UsernamePasswordMako
        #     authn = UsernamePasswordMako(None, "login.mako", LOOKUP, PASSWD,
        #                                  "authorization")

        if "NoAuthn" == authkey:
            from oic.utils.authn.user import NoAuthn

            authn = NoAuthn(None, user=config.AUTHENTICATION[authkey]["user"])

        if authn is not None:
            ac.add(config.AUTHENTICATION[authkey]["ACR"], authn,
                   config.AUTHENTICATION[authkey]["WEIGHT"])

    # dealing with authorization
    authz = AuthzHandling()

    kwargs = {
        "template_lookup": LOOKUP,
        "template": {"form_post": "form_response.mako"},
        #"template_args": {"form_post": {"action": "form_post"}}
    }

    if config.USERINFO == "SIMPLE":
        # User info is a simple dictionary in this case statically defined in
        # the configuration file
        userinfo = UserInfo(config.USERDB)
    else:
        userinfo = None

    # Should I care about verifying the certificates used by other entities
    if args.insecure:
        kwargs["verify_ssl"] = False
    else:
        kwargs["verify_ssl"] = True

    COM_ARGS = {
        "name": config.issuer,
        "sdb": SessionDB(config.baseurl),
        "cdb": cdb,
        "authn_broker": ac,
        "userinfo": userinfo,
        "authz": authz,
        "client_authn": verify_client,
        "symkey": config.SYM_KEY,
    }

    OP_ARG = {}

    try:
        OP_ARG["cookie_ttl"] = config.COOKIETTL
    except AttributeError:
        pass

    try:
        OP_ARG["cookie_name"] = config.COOKIENAME
    except AttributeError:
        pass

    #print URLS
    if args.debug:
        OP_ARG["debug"] = True

    # All endpoints the OpenID Connect Provider should answer on
    add_endpoints(ENDPOINTS)
    OP_ARG["endpoints"] = ENDPOINTS

    if args.port == 80:
        _baseurl = config.baseurl
    else:
        if config.baseurl.endswith("/"):
            config.baseurl = config.baseurl[:-1]
        _baseurl = "%s:%d" % (config.baseurl, args.port)

    if not _baseurl.endswith("/"):
        _baseurl += "/"

    OP_ARG["baseurl"] = _baseurl

    # Add own keys for signing/encrypting JWTs
    try:
        OAS = Provider(**COM_ARGS)
        jwks = keyjar_init(OAS, config.keys)
    except KeyError:
        pass
    else:
        # export JWKS
        p = urlparse(config.KEY_EXPORT_URL % args.port)
        f = open("."+p.path, "w")
        f.write(json.dumps(jwks))
        f.close()
        OP_ARG["keyjar"] = OAS.keyjar
        OP_ARG["jwks_uri"] = p.geturl()

    # Setup the web server
    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', args.port),
                                        SessionMiddleware(application,
                                                          session_opts))

    https = ""
    if config.SERVICE_URL.startswith("https"):
        https = " using HTTPS"
        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            config.SERVER_CERT, config.SERVER_KEY, config.CERT_CHAIN)

    LOGGER.info("OC server starting listening on port:%s%s" % (args.port,
                                                               https))
    print "OC server starting listening on port:%s%s" % (args.port, https)
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
