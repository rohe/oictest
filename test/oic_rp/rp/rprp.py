import copy
import importlib
import json
import logging
from urlparse import parse_qs, urlparse
import argparse
from mako.lookup import TemplateLookup
from oic.oauth2 import rndstr
from oic.oauth2 import ResponseError

from oic.oic import AuthorizationRequest
from oic.oic import AuthorizationResponse
from oic.oic import AccessTokenResponse
from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD, BearerHeader
from oic.utils.http_util import Response, get_post
from oic.utils.http_util import Redirect
from oic.utils.http_util import ServiceError
from oic.utils.http_util import NotFound
from oic.utils.keyio import build_keyjar

__author__ = 'roland'

LOGGER = logging.getLogger("")
LOGFILE_NAME = 'rprp.log'
hdlr = logging.FileHandler(LOGFILE_NAME)
base_formatter = logging.Formatter(
    "%(asctime)s %(name)s:%(levelname)s %(message)s")

hdlr.setFormatter(base_formatter)
LOGGER.addHandler(hdlr)
LOGGER.setLevel(logging.DEBUG)

SERVER_ENV = {}
LOOKUP = TemplateLookup(directories=['templates', 'htdocs'],
                        module_directory='modules',
                        input_encoding='utf-8',
                        output_encoding='utf-8')


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


def flow_list(environ, start_response, flows, done):
    resp = Response(mako_template="flowlist.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {"base": CONF.BASE, "flows": flows, "done": done}

    return resp(environ, start_response, **argv)


def include(url, test_id):
    p = urlparse(url)
    return "%s://%s/%s%s_/_/_/normal" % (p.scheme, p.netloc, test_id, p.path)


def get_claims(client):
    resp = {}
    for src in client.userinfo["_claim_names"].values():
        spec = client.userinfo["_claim_sources"][src]
        ht_args = BearerHeader(client).construct(**spec)

        try:
            part = client.http_request(spec["endpoint"], "GET", **ht_args)
        except Exception:
            raise
        resp.update(json.loads(part.content))

    return resp


def catch_exception(spec, func, **kwargs):
    try:
        res = func(**kwargs)
    except Exception as err:
        try:
            assert isinstance(err, spec["error"])
        except AssertionError:
            raise
        else:
            res = None

    return res


def run_flow(client, index, session, test_id):
    if index < len(session["flow"]["flow"]):
        session["index"] = index
        for spec in session["flow"]["flow"][index:]:

            session["index"] += 1  # next to run

            if spec["args"]:
                if isinstance(spec['args'], basestring):
                    _args = spec["args"]
                else:
                    _args = copy.deepcopy(spec["args"])
            else:
                _args = {}

            if spec["action"] == "discover":
                if isinstance(_args, basestring):
                    session["issuer"] = client.discover(_args % test_id)
                else:
                    session["issuer"] = client.discover(CONF.ISSUER+test_id)
            elif spec["action"] == "provider_info":
                if _args:
                    _args["issuer"] = include(_args["issuer"], test_id)
                    catch_exception(spec, client.provider_config, **_args)
                else:
                    catch_exception(spec, client.provider_config,
                                    issuer=include(session["issuer"], test_id))
            elif spec["action"] == "registration":
                _endp = client.provider_info["registration_endpoint"]
                if _args:
                    if "jwks_uri" in _args:
                        _args["jwks_uri"] = JWKS_URI
                    catch_exception(spec, client.register, url=_endp, **_args)
                else:
                    catch_exception(spec, client.register, url=_endp)
                client.client_prefs = _args
            elif spec["action"] == "static_registration":
                client.store_registration_info(_args)
            elif spec["action"] == "authn_req":
                _endp = client.provider_info["authorization_endpoint"]
                session["state"] = rndstr()
                session["nonce"] = rndstr()
                _args["nonce"] = session["nonce"]
                url, body, ht_args, csi = client.request_info(
                    AuthorizationRequest, method="GET", request_args=_args,
                    state=session["state"], endpoint=_endp)
                return Redirect(str(url))
            elif spec["action"] == "token_req":
                _args["state"] = session["state"]
                _args["request_args"] = {
                    "redirect_uri": client.redirect_uris[0]}
                atr = client.do_access_token_request(**_args)
                assert isinstance(atr, AccessTokenResponse)
            elif spec["action"] == "userinfo_req":
                _args["state"] = session["state"]
                userinfo = client.do_user_info_request(**_args)
                assert userinfo
                client.userinfo = userinfo
            elif spec["action"] == "fetch_claims":
                res = get_claims(client)
                assert res

    session["done"].append(session["item"])
    return None


def application(environ, start_response):
    session = environ['beaker.session']
    path = environ.get('PATH_INFO', '').lstrip('/')

    try:
        _cli = session["client"]
    except KeyError:
        _cli = session["client"] = Client(
            client_authn_method=CLIENT_AUTHN_METHOD, keyjar=KEYJAR)
        _cli.kid = KIDD
        #_cli.allow["issuer_mismatch"] = True
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

    if path == "":  # list
        return flow_list(environ, start_response, FLOWS.FLOWS, session["done"])
    elif path in FLOWS.FLOWS.keys():
        session["flow"] = FLOWS.FLOWS[path]
        session["index"] = 0
        session["item"] = path
        test_id = "%s-%s" % (TESTID, path)
        session["test_id"] = test_id

        try:
            resp = run_flow(_cli, session["index"], session, test_id)
        except Exception as err:
            resp = ServiceError("%s" % err)
            return resp(environ, start_response)
        else:
            if resp:
                return resp(environ, start_response)
            else:
                return flow_list(environ, start_response, FLOWS.FLOWS,
                                 session["done"])
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
