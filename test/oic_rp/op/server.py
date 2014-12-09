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
from beaker.session import Session

from oic.oic.provider import EndSessionEndpoint
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client, CLIENT_AUTHN_METHOD
from oic.utils.authz import AuthzHandling
from oic.utils.http_util import *
from oic.utils.keyio import keyjar_init
from oic.utils.sdb import SessionDB
from oic.utils.userinfo import UserInfo
from oic.utils.webfinger import WebFinger
from oic.utils.webfinger import OIC_ISSUER
from oictest.mode import extract_mode
from oictest.mode import setup_op
from oictest.mode import mode2path

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


# ----------------------------------------------------------------------------

#noinspection PyUnusedLocal
def token(environ, start_response, session):
    _oas = session["op"]

    return wsgi_wrapper(environ, start_response, _oas.token_endpoint)


#noinspection PyUnusedLocal
def authorization(environ, start_response, session):
    _oas = session["op"]

    return wsgi_wrapper(environ, start_response, _oas.authorization_endpoint)


#noinspection PyUnusedLocal
def userinfo(environ, start_response, session):
    _oas = session["op"]
    return wsgi_wrapper(environ, start_response, _oas.userinfo_endpoint)


#noinspection PyUnusedLocal
def op_info(environ, start_response, session):
    _oas = session["op"]
    return wsgi_wrapper(environ, start_response, _oas.providerinfo_endpoint)


#noinspection PyUnusedLocal
def registration(environ, start_response, session):
    _oas = session["op"]

    if environ["REQUEST_METHOD"] == "POST":
        return wsgi_wrapper(environ, start_response, _oas.registration_endpoint)
    elif environ["REQUEST_METHOD"] == "GET":
        return wsgi_wrapper(environ, start_response, _oas.read_registration)
    else:
        resp = ServiceError("Method not supported")
        return resp(environ, start_response)


#noinspection PyUnusedLocal
def check_id(environ, start_response, session):
    _oas = session["op"]

    return wsgi_wrapper(environ, start_response, _oas.check_id_endpoint)


#noinspection PyUnusedLocal
def swd_info(environ, start_response, session):
    _oas = session["op"]

    return wsgi_wrapper(environ, start_response, _oas.discovery_endpoint)


#noinspection PyUnusedLocal
def endsession(environ, start_response, session):
    _oas = session["op"]
    return wsgi_wrapper(environ, start_response, _oas.endsession_endpoint)


#noinspection PyUnusedLocal
def meta_info(environ, start_response):
    """
    Returns something like this::

         {"links":[
             {
                "rel":"http://openid.net/specs/connect/1.0/issuer",
                "href":"https://openidconnect.info/"
             }
         ]}

    """
    pass


def webfinger(environ, start_response, _):
    query = parse_qs(environ["QUERY_STRING"])
    try:
        assert query["rel"] == [OIC_ISSUER]
        resource = query["resource"][0]
    except KeyError:
        resp = BadRequest("Missing parameter in request")
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

    return resp(environ, start_response)


#noinspection PyUnusedLocal
def verify(environ, start_response, session):
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
            start_response('200 OK', [('Content-Type', "text/xml")])
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
    #(r'^.well-known/simple-web-discovery', swd_info),
    #(r'^.well-known/host-meta.json', meta_info),
    (r'.well-known/webfinger', webfinger),
#    (r'^.well-known/webfinger', webfinger),
    (r'.+\.css$', css),
    (r'safe', safe),
#    (r'tracelog', trace_log),
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

    if path == "robots.txt":
        return static(environ, start_response, "static/robots.txt")

    if path.startswith("static/"):
        return static(environ, start_response, path)

    mode, endpoint = extract_mode(path)

    if "op" not in session:
        session["op"] = setup_op(mode, COM_ARGS, OP_ARG)
        session["mode_path"] = mode2path(mode)
    else:  # may be a new mode
        if session["mode_path"] != mode2path(mode):
            session["op"] = setup_op(mode)
            session["mode_path"] = mode2path(mode)

    for regex, callback in URLS:
        match = re.search(regex, endpoint)
        if match is not None:
            try:
                environ['oic.url_args'] = match.groups()[0]
            except IndexError:
                environ['oic.url_args'] = endpoint

            LOGGER.info("callback: %s" % callback)
            try:
                return callback(environ, start_response, session)
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

    from provider import Provider

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

    # Client data base
    cdb = shelve.open("client_db", writeback=True)

    sys.path.insert(0, ".")
    config = importlib.import_module(args.config)
    config.issuer = config.issuer % args.port
    config.SERVICE_URL = config.SERVICE_URL % args.port

    SETUP = {}

    ac = AuthnBroker()

    for authkey, value in config.AUTHENTICATION.items():
        authn = None
        if "UserPassword" == authkey:
            from oic.utils.authn.user import UsernamePasswordMako
            authn = UsernamePasswordMako(None, "login.mako", LOOKUP, PASSWD,
                                         "authorization")
        if authn is not None:
            ac.add(config.AUTHENTICATION[authkey]["ACR"], authn,
                   config.AUTHENTICATION[authkey]["WEIGHT"],
                   config.AUTHENTICATION[authkey]["URL"])

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
        "userinfo": None,
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
        jwks = keyjar_init(OAS, kwargs["keys"])
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
