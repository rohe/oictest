#!/usr/bin/env python
import json
import logging
import socket
from urlparse import parse_qs

from cherrypy import wsgiserver
from mako.lookup import TemplateLookup
from oic.oic import AuthorizationResponse, AuthorizationRequest
from oic.utils.authn.authn_context import AuthnBroker
from oic.utils.authn.client import verify_client
from oic.utils.authn.client import BearerHeader
from oic.utils.authn.client import ClientSecretPost
from oic.utils.authn.client import ClientSecretBasic
from oic.utils.authn.user import UsernamePasswordMako
from oic.utils.authn.user import UserAuthnMethod
from oic.utils.authn.user import BasicAuthn
from oic.utils.authz import Implicit
from oic.utils.http_util import Response
from oic.utils.http_util import InvalidCookieSign
from oic.utils.http_util import ServiceError
from oic.utils.http_util import R2C
from oic.utils.http_util import CookieDealer
from oic.utils.http_util import BadRequest
from oic.utils.http_util import NotFound
from oic.utils.sdb import SessionDB
from oic.utils.webfinger import WebFinger
from oic.utils.webfinger import OIC_ISSUER
from uma import client, UMAError
from uma.authzsrv import OAuth2UmaAS
from uma.message import PermissionRegistrationResponse
from uma.message import RPTResponse
from umatest.util import TraceHandler

__author__ = 'rolandh'

logger = logging.getLogger("")
h = TraceHandler()
logger.addHandler(h)
logger.setLevel(logging.INFO)

AUTHZSRV = None
CLIENT = None

CookieHandler = CookieDealer(None)
COOKIE_NAME = "as_uma"


def get_body(environ):
    length = int(environ["CONTENT_LENGTH"])
    try:
        body = environ["wsgi.input"].read(length)
    except Exception, excp:
        logger.exception("Exception while reading post: %s" % (excp,))
        raise

    # restore what I might have upset
    from StringIO import StringIO

    environ['wsgi.input'] = StringIO(body)

    return body


# -----------------------------------------------------------------------------
# Callbacks
# -----------------------------------------------------------------------------
#noinspection PyUnresolvedReferences
CTYPE_MAP = {
    "ico": "image/x-icon",
    "html": "text/html",
    "json": 'application/json',
    "txt": 'text/plain',
    "css": 'text/css',
    "xml": "text/xml",
    "js": "text/javascript"
}


#noinspection PyUnusedLocal
def static(environ, session, path):
    logger.info("[static]sending: %s" % (path,))

    try:
        text = open(path).read()
        ext = path.rsplit(".", 1)[-1]
        try:
            ctype = CTYPE_MAP[ext]
        except KeyError:
            ctype = CTYPE_MAP["txt"]

        resp = Response(text, headers=[('Content-Type', ctype)])
    except IOError:
        resp = NotFound()

    return resp

# ........................................................................


def pre_trace(direction, func, **kwargs):
    logger.info(direction)
    logger.info("@%s" % func)
    logger.info(json.dumps(kwargs))


def post_trace(direction, **kwargs):
    logger.info(direction)
    logger.info(json.dumps(kwargs))


def repack_response(resp):
    res = {}
    try:
        res["status"] = resp.status
    except AttributeError:
        res["status"] = resp.status_code
    try:
        res["message"] = resp.message
    except AttributeError:
        res["reason"] = resp.reason

    try:
        res["headers"] = resp.headers
    except AttributeError:
        pass

    return res


def wrap(func, prepath, kwargs):
    _inp = dict([(k, v) for k, v in kwargs.items() if v and k != "environ"])

    # Works as long as I don't do client authentication at registration

    _inp["environ"] = {}
    try:
        request = _inp["query"]
    except KeyError:
        try:
            request = _inp["body"]
        except KeyError:
            request = ""
    else:
        if not request:
            try:
                request = _inp["body"]
            except KeyError:
                pass

    _inp["request"] = request

    pre_trace("AS<--", "%s" % prepath, **_inp)
    resp = func(**_inp)
    post_trace("AS-->", **repack_response(resp))
    return resp


def trace():
    resp = None
    for handler in logger.handlers:
        if isinstance(handler, TraceHandler):
            msg = [(e["created"], e["msg"]) for e in handler.buffer]
            resp = Response(json.dumps(msg))
            break

    # Should I flush the buffer ?
    #handler.flush()
    if resp:
        return resp
    else:
        return Response([])


class Client(object):
    def __init__(self, resource_srv, client_id=None, ca_certs=None,
                 client_authn_method=None, keyjar=None, server_info=None,
                 authz_page="", flow_type="", password=None,
                 registration_info=None, response_type="", scope=""):
        self.client = client.Client(client_id, ca_certs, client_authn_method,
                                    keyjar, server_info, authz_page, flow_type,
                                    password, registration_info, response_type,
                                    scope)
        self.redirect_uris = registration_info["redirect_uris"]
        self.resource_srv = resource_srv
        self.srv = None
        self.token = self.client.token

    def register_permission(self, resp, requester):
        prr = PermissionRegistrationResponse().from_json(resp.text)
        kwargs = self.client.create_authorization_data_request(
            requester, prr["ticket"])
        pre_trace("C-->AS", "authorization_request", **kwargs)

        resp = self.srv.authorization_request_endpoint(
            kwargs["data"], authn=kwargs["headers"]["Authorization"])

        post_trace("C<--AS", **repack_response(resp))

        return resp

    def rs_query(self, requestor, path):
        try:
            rpt = self.client.token[requestor]["RPT"]
        except KeyError:
            rpt = None

        url = "%s/%s" % (self.resource_srv, path)

        if rpt:
            kwargs = {"headers": [("Authorization", "Bearer %s" % rpt)]}
        else:
            kwargs = {}

        pre_trace("C-->", "rs_query", **kwargs)
        resp = self.client.send(url, "GET", **kwargs)
        post_trace("C<--", **repack_response(resp))
        return resp

    def get_info(self, requester, path, state=""):
        """

        :param requester: requester
        """
        resp = self.rs_query(requester, path)

        if resp.status_code == 200:
            return Response(resp.text)

        if resp.status_code == 401:  # No RPT
            as_uri = resp.headers["as_uri"]
            if as_uri == self.srv.baseurl:
                # It's me as it should be, means get a RPT from myself
                self.srv.get_aat(requester)
                self.srv.get_rpt(requester)

                return self.get_info(requester, path, state)

            else:
                return R2C[500]("Wrong AS")

        if resp.status_code == 403:  # Permission registered, got ticket
            resp = self.register_permission(resp, requester)
            if resp.status == "200 OK":
                return self.get_info(requester, path)

        raise UMAError()

    def get_tokens(self, query):
        aresp = AuthorizationResponse().from_urlencoded(query)
        uid = self.client.acquire_access_token(aresp, "AAT")
        self.client.get_rpt(uid)
        return uid

    def get_uma_scope(self, token_type):
        return self.client.get_uma_scope(token_type)


class AuthorizationServer(object):
    def __init__(self, name, sdb, cdb, authn_broker, authz,
                 client_authn, symkey, urlmap=None, keyjar=None,
                 hostname="", configuration=None, base_url="",
                 client_authn_methods=None, authn_at_registration="",
                 client_info_url="", secret_lifetime=86400):
        self.srv = OAuth2UmaAS(name, sdb, cdb, authn_broker, authz,
                               client_authn, symkey, urlmap, keyjar,
                               hostname, configuration, base_url,
                               client_authn_methods, authn_at_registration,
                               client_info_url, secret_lifetime)
        self.baseurl = base_url
        self.client = None

    def authorization_endpoint(self, request, **kwargs):
        return self.srv.authorization_endpoint(request, **kwargs)

    def authorization_request_endpoint(self, request, **kwargs):
        if "authn" in kwargs:
            return self.srv.authorization_request_endpoint(request,
                                                           kwargs["authn"])
        else:
            return self.srv.authorization_request_endpoint(request)

    def introspection_endpoint(self, request, **kwargs):
        return self.srv.introspection_endpoint(request, **kwargs)

    def permission_registration_endpoint(self, request, **kwargs):
        return self.srv.permission_registration_endpoint(request, **kwargs)

    def providerinfo_endpoint(self, **kwargs):
        return self.srv.providerinfo_endpoint_()

    def registration_endpoint(self, request, **kwargs):
        return self.srv.registration_endpoint(request, **kwargs)

    def resource_set_registration_endpoint(self, **kwargs):
        return self.srv.resource_set_registration_endpoint(**kwargs)

    def resource_sets_by_user(self, uid, **kwargs):
        return self.srv.resource_sets_by_user(uid)

    def rpt_endpoint(self, **kwargs):
        return self.srv.rpt_endpoint(**kwargs)

    def store_permission(self, **kwargs):
        _args = [kwargs[k] for k in ["user", "requestor", "resource_id",
                                     "scopes"]]
        return self.srv.store_permission(*_args)

    def token_endpoint(self, request, **kwargs):
        try:
            authn = kwargs["authn"]
        except KeyError:
            authn = ""
        return self.srv.token_endpoint(authn, request=request, **kwargs)

    def user_endpoint(self, **kwargs):
        return self.authorization_endpoint(**kwargs)

    def dynamic_client_endpoint(self, request, **kwargs):
        return self.srv.dynamic_client_endpoint(request, **kwargs)

    def service(self, path):
        return getattr(self, "%s_endpoint" % path)

    def get_aat(self, user):
        request_args = {"response_type": "code",
                        "client_id": "internal",
                        "redirect_uri": self.client.redirect_uris[0],
                        "scope": [self.client.get_uma_scope("AAT")],
                        "state": "_state"}

        areq = AuthorizationRequest(**request_args)
        pre_trace("C-->AS", "get_aat", query=areq.to_dict(), user=user)
        sid = self.srv.sdb.create_authz_session(user, areq)
        grant = self.srv.sdb[sid]["code"]
        self.client.token[user] = {
            "AAT": self.srv.sdb.upgrade_to_token(grant)}
        post_trace(
            "C<--AS",
            AAT=self.client.token[user]["AAT"]["access_token"])

    def get_rpt(self, user):
        authn = "Bearer %s" % self.client.token[user]["AAT"]["access_token"]
        pre_trace("C-->AS", "*get_rpt", authn=authn)
        resp = self.srv.rpt_endpoint(authn)
        rtr = RPTResponse().from_json(resp.message)
        self.client.token[user]["RPT"] = rtr["rpt"]
        post_trace("C<--AS", RPT=self.client.token[user]["RPT"])


# ........................................................................


def get_authn_info(environ):
    try:
        return environ["HTTP_AUTHORIZATION"]
    except KeyError:
        return ""


def get_cookie(environ):
    try:
        return environ["HTTP_COOKIE"]
    except KeyError:
        return ""


def get_if_match(environ):
    try:
        return environ["HTTP_IF_MATCH"]
    except KeyError:
        return ""


# def get_query(environ):
#     try:
#         ret = environ["QUERY_STRING"]
#     except KeyError:
#         return get_body(environ)
#     else:
#         if not ret:
#             return get_body(environ)


def get_args(environ):
    return {
        "query": environ.get('QUERY_STRING', ''),
        "body": get_body(environ),
        "cookie": get_cookie(environ),
        "path": environ.get('PATH_INFO', '').lstrip('/'),
        "if_match": get_if_match(environ),
        "method": environ["REQUEST_METHOD"],
        "authn": get_authn_info(environ),
        "environ": environ
    }


def webfinger(environ):
    query = parse_qs(environ["QUERY_STRING"])
    try:
        assert query["rel"] == [OIC_ISSUER]
        resource = query["resource"][0]
    except KeyError:
        resp = BadRequest("Missing parameter in request")
    else:
        wf = WebFinger()
        resp = Response(wf.response(subject=resource,
                                    base=AUTHZSRV.baseurl))
    return resp


def application(environ, start_response):
    path = environ.get('PATH_INFO', '').lstrip('/')

    session = {}
    try:
        cookie = environ["HTTP_COOKIE"]
        try:
            _tmp = CookieHandler.get_cookie_value(cookie, COOKIE_NAME)
        except InvalidCookieSign:
            _tmp = None
        if _tmp:
            # 3-tuple (val, timestamp, type)
            session = eval(_tmp[0])
        else:
            try:
                (uid, _, typ) = CookieHandler.get_cookie_value(cookie, "pyoidc")
                if typ == "sso":
                    session = {"user": uid}
            except (InvalidCookieSign, TypeError):
                pass
    except KeyError:
        pass
    except Exception, err:
        pass

    argv = {}

    if path == "robots.txt":
        resp = static(environ, session, "static/robots.txt")
    elif path.startswith("static/"):
        resp = static(environ, session, path)
    elif path == "resource_set":
        query = parse_qs(environ["QUERY_STRING"])
        uid = query["user"][0]
        res = AUTHZSRV.resource_sets_by_user(uid)
        resp = Response(json.dumps([r.to_dict() for r in res]))
    elif path == "perm_reg":
        query = parse_qs(environ["QUERY_STRING"])
        for key, val in query.items():
            if key in ["requestor", "resource_id", "user"]:
                query[key] = val[0]
        pre_trace("-->AS", "store_permission", query=query)
        try:
            AUTHZSRV.store_permission(**query)
        except Exception, err:
            post_trace("<--AS", exception="%s" % err)
            resp = ServiceError("%s" % err)
        else:
            post_trace("<--AS", status="OK")
            resp = Response("OK")
    elif path.startswith("access/info"):
        query = parse_qs(environ["QUERY_STRING"])
        path = path[len("access/"):]
        pre_trace("C-->", "Access info", query=query, path=path)
        try:
            resp = CLIENT.get_info(query["requester"][0], path)
        except Exception, err:
            post_trace("C<--", exception="%s" % err)
            resp = ServiceError("%s" % err)
        else:
            post_trace("C<--", **repack_response(resp))
    else:
        if path == ".well-known/uma-configuration":
            resp = AUTHZSRV.providerinfo_endpoint(**get_args(environ))
        elif path == ".well-known/webfinger":
            resp = webfinger(environ)
        elif path == "trace":
            resp = trace()
        else:
            prepath = path.split("/")[0]
            resp = None
            try:
                func = AUTHZSRV.service(prepath)
            except Exception, err:
                pass
            else:
                if func:
                    try:
                        resp = wrap(func, prepath, get_args(environ))
                    except Exception, err:
                        resp = ServiceError("%s" % err)

    if isinstance(resp, Response):
        pass
    else:
        resp = NotFound(path)

    return resp(environ, start_response, **argv)

# -----------------------------------------------------------------------------


AUTHZ = Implicit("PERMISSION")
CDB = {}

PASSWD = {
    "alice": "krall",
    "hans": "thetake",
    "user": "howes",
    "https://sp.example.org/": "code"
}

class DummyAuthn(UserAuthnMethod):
    def __init__(self, srv, uid="Linda"):
        UserAuthnMethod.__init__(self, srv)
        self.user = uid

    def authenticated_as(self, cookie=None, **kwargs):
        return {"uid": self.user}


class BasicAuthnExtra(BasicAuthn):
    def __init__(self, srv, symkey):
        BasicAuthn.__init__(self, srv, None, 0)
        self.symkey = symkey

    def verify_password(self, user, password):
        assert password == "hemligt"


ROOT = './'
LOOKUP = TemplateLookup(directories=[ROOT + 'templates', ROOT + 'htdocs'],
                        module_directory=ROOT + 'modules',
                        input_encoding='utf-8', output_encoding='utf-8')


if __name__ == '__main__':
    SERVER_CERT = "pki/server.crt"
    SERVER_KEY = "pki/server.key"
    CA_BUNDLE = None
    PORT = 8088
    #BASE = "https://lingon.catalogix.se:%s" % PORT
    BASE = "http://localhost:%s/" % PORT
    RESOURCE_SERVER = "https://localhost:8089"

    # The UMA AS=C combo
    as_conf = {
        "version": "1.0",
        "issuer": BASE,
        "pat_profiles_supported": ["bearer"],
        "aat_profiles_supported": ["bearer"],
        "rpt_profiles_supported": ["bearer"],
        "pat_grant_types_supported": ["authorization_code"],
        "aat_grant_types_supported": ["authorization_code"],
        "claim_profiles_supported": ["openid"],
    }

    ab = AuthnBroker()
    ab.add("alice", DummyAuthn(None, "alice"))
    ab.add("UserPwd",
           UsernamePasswordMako(None, "login2.mako", LOOKUP, PASSWD,
                                "%s/authorization" % BASE),
           10, "http://%s" % socket.gethostname())
    ab.add("BasicAuthn", BasicAuthnExtra(None, PASSWD), 10,
           "http://%s" % socket.gethostname())

    AUTHZSRV = AuthorizationServer(
        BASE, SessionDB(), CDB, ab, AUTHZ, verify_client, "1234567890123456",
        keyjar=None, configuration=as_conf, base_url=BASE,
        client_info_url="%s/" % BASE,
        client_authn_methods={
            "client_secret_post": ClientSecretPost,
            "client_secret_basic": ClientSecretBasic,
            "bearer_header": BearerHeader})

    registration_info = {
        "redirect_uris": ["%scallback" % BASE],
        "client_name": "My Example Client",
        "token_endpoint_auth_method": "client_secret_basic",
        #"subject_types_supported": ['public', 'pairwise']
        #"scope": ""
    }

    CLIENT = Client(RESOURCE_SERVER,
                    client_authn_method={
                        "client_secret_post": ClientSecretPost,
                        "client_secret_basic": ClientSecretBasic,
                        "bearer_header": BearerHeader},
                    registration_info=registration_info)

    # Connect them
    AUTHZSRV.client = CLIENT
    CLIENT.srv = AUTHZSRV

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', PORT), application)


    if BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            SERVER_CERT, SERVER_KEY, CA_BUNDLE)

    #logger.info("RP server starting listening on port:%s" % rp_conf.PORT)
    print "C=AS started, listening on port:%s" % PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
