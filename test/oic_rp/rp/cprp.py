#!/usr/bin/env python
import json
import logging
from urlparse import parse_qs, urlparse
from mako.lookup import TemplateLookup
from oic.oauth2 import ResponseError
from oic.oic import Client, AuthorizationResponse
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.http_util import Response, get_post, ServiceError, NotFound
from oic.utils.keyio import build_keyjar

__author__ = 'roland'

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'cprp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

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


def opresult_fragment(environ, start_response):
    resp = Response(mako_template="opresult_repost.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {}
    return resp(environ, start_response, **argv)


def application(environ, start_response):
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')

    try:
        _cli = session["client"]
    except KeyError:
        _cli = session["client"] = Client(
            client_authn_method=CLIENT_AUTHN_METHOD, keyjar=KEYJAR)
        _cli.kid = KIDD
        _cli.jwks_uri = JWKS_URI
        for arg, val in CONF.CLIENT_INFO.items():
            setattr(_cli, arg, val)
        session["done"] = []

    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")
    elif path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)
    elif path.startswith("export/"):
        return static(environ, start_response, LOGGER, path)

    # elif path in FLOWS.FLOWS.keys():
    #     session["flow"] = FLOWS.FLOWS[path]
    #     session["index"] = 0
    #     session["item"] = path
    #     test_id = "%s-%s" % (TESTID, path)
    #     session["test_id"] = test_id
    #
    #     try:
    #         resp = run_flow(_cli, session["index"], session, test_id)
    #     except Exception as err:
    #         resp = ServiceError("%s" % err)
    #         return resp(environ, start_response)
    #     else:
    #         if resp:
    #             return resp(environ, start_response)
    #         else:
    #             return flow_list(environ, start_response, FLOWS.FLOWS,
    #                              session["done"])
    elif path in ["authz_cb", "authz_post"]:
        if path != "authz_post":
            args = session["flow"]["flow"][session["index"]-1]["args"]
            if args["response_type"] != ["code"]:
                return opresult_fragment(environ, start_response)

        # Got a real Authn response
        ctype = "urlencoded"
        if path == "authz_post":
            query = parse_qs(get_post(environ))
            info = query["fragment"][0]
        else:
            info = environ["QUERY_STRING"]

        LOGGER.info("Response: %s" % info)
        try:
            _cli = session["client"]
            response = _cli.parse_response(AuthorizationResponse, info, ctype,
                                           session["state"], keyjar=_cli.keyjar)
        except ResponseError as err:
            LOGGER.error("%s" % err)
            resp = ServiceError("%s" % err)
            return resp(environ, start_response)
        except Exception as err:
            _spec = session["flow"]["flow"][session["index"]-1]
            try:
                assert isinstance(err, _spec["error"])
            except KeyError:
                raise
        else:
            pass

        try:
            resp = run_flow(_cli, session["index"], session, session["test_id"])
        except Exception as err:
            LOGGER.error("%s" % err)
            resp = ServiceError("%s" % err)
            return resp(environ, start_response)
        else:
            if resp:
                return resp(environ, start_response)
            else:
                return flow_list(environ, start_response, FLOWS.FLOWS,
                                 session["done"])
    else:
        LOGGER.debug("unknown side: %s" % path)
        resp = NotFound("Couldn't find the side you asked for!")
        return resp(environ, start_response)


if __name__ == '__main__':
    from beaker.middleware import SessionMiddleware
    from cherrypy import wsgiserver
    import argparse
    import importlib

    parser = argparse.ArgumentParser()
    parser.add_argument('-f', dest='flows')
    parser.add_argument('-i', dest='identifier')
    parser.add_argument(dest="config")
    cargs = parser.parse_args()

    # global ACR_VALUES
    # ACR_VALUES = CONF.ACR_VALUES

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        'session.auto': True,
        'session.timeout': 900
    }

    FLOWS = importlib.import_module(cargs.flows)
    CONF = importlib.import_module(cargs.config)
    if cargs.identifier:
        TESTID = cargs.identifier
    else:
        TESTID = "ITS"

    SERVER_ENV.update({"template_lookup": LOOKUP, "base_url": CONF.BASE})

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', CONF.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    # Add own keys for signing/encrypting JWTs
    try:
        jwks, KEYJAR, KIDD = build_keyjar(CONF.keys)
    except KeyError:
        pass
    else:
        # export JWKS
        p = urlparse(CONF.KEY_EXPORT_URL)
        f = open("."+p.path, "w")
        f.write(json.dumps(jwks))
        f.close()
        JWKS_URI = p.geturl()

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

