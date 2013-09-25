import base64
import hashlib
import uuid
from oic.oic import Client
from oic.utils.authn.client import CLIENT_AUTHN_METHOD
from oic.utils.keyio import KeyBundle, dump_jwks, KeyJar
import requests
from rrtest import Trace
import action

from beaker.middleware import SessionMiddleware
from cherrypy import wsgiserver
from mako.lookup import TemplateLookup
from urlparse import parse_qs

from oic.utils.http_util import NotFound
from oic.utils.http_util import ServiceError
from oic.utils.http_util import BadRequest
from oic.utils.http_util import R2C
from oic.utils.http_util import Redirect
from oic.utils.http_util import Response
from oictest.oic_operations import PHASES
from oidc import OpenIDConnect

from oictest import oic_operations

import rp_conf

import logging

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
RP = None
FLOWS = None
FLOW_SEQUENCE = []
CLIENT_CONFIG = {
    "redirect_uris": ["%sauthorization"],
    "contacts": ["roland.hedberg@adm.umu.se"],
    "application_type": "web",
    "client_name": "OIC test tool",
    "key_export_url": "%skeys",
    "keys": {
        "RSA": {
            "key": "keys/pyoidc",
            "use": ["enc", "sig"]
        }
    },
    #"request_object_alg": "RS256",
    #"userinfo_signed_response_alg": "RS256",
    #"id_token_signed_response_alg": "RS256"
    "preferences": {
        "subject_types": ["pairwise", "public"],
        "request_object_signing_algs": [
            "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
        ],
        "token_endpoint_auth_methods": [
            "client_secret_basic", "client_secret_post",
            "client_secret_jwt", "private_key_jwt"],
        "response_types": [
            "code", "token", "id_token", "token id_token",
            "code id_token", "code token", "code token id_token"
        ],
        "grant_types": ["authorization_code", "implicit", "refresh_token",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer:"],
        "userinfo_signed_response_algs": [
            "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
        ],
        #"userinfo_encrypted_response_alg",
        #"userinfo_encrypted_response_enc",
        #"userinfo_encrypted_response_int",
        "id_token_signed_response_algs": [
            "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
        ],
        #"id_token_encrypted_response_alg",
        #"id_token_encrypted_response_enc",
        #"id_token_encrypted_response_int",
        "default_max_age": 3600,
        "require_auth_time": True,
        "default_acr_values": ["2", "1"]
    }
}


def export_keys(keys):
    kbl = []
    keyjar = KeyJar()
    for typ, info in keys.items():
        kb = KeyBundle(source="file://%s" % info["key"], fileformat="der",
                       keytype=typ)
        keyjar.add_kb("", kb)
        kbl.append(kb)

    try:
        new_name = "static/jwks.json"
        dump_jwks(kbl, new_name)
    except KeyError:
        pass

    return keyjar


def setup_server_env(rp_conf):
    global SERVER_ENV
    global logger

    SERVER_ENV = dict([(k, v) for k, v in rp_conf.__dict__.items()
                       if not k.startswith("__")])
    SERVER_ENV["template_lookup"] = LOOKUP
    SERVER_ENV["base_url"] = rp_conf.BASE
    #SERVER_ENV["CACHE"] = {}
    SERVER_ENV["OIC_CLIENT"] = {}
    if "KEYS" in SERVER_ENV:
        SERVER_ENV["KEYJAR"] = export_keys(SERVER_ENV["KEYS"])


class Session(object):
    def __init__(self, session):
        self.session = session

    def __getitem__(self, item):
        if item == "state":
            return self.session.get("state", uuid.uuid4().urn)
        else:
            return self.session.get(item, None)

    def __setitem__(self, key, value):
        self.session[key] = value


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


def opbyuid(environ, start_response):
    resp = Response(mako_template="opbyuid.mako",
                    template_lookup=LOOKUP,
                    headers=[])
    argv = {
    }
    return resp(environ, start_response, **argv)


def display_result(trace):
    return Response("<pre>%s</pre>" % trace)


def do_response(phase, cli, trace, session, flow, environ=None, reqi=None):
    respi = action.Response(phase, cli, CLIENT_CONFIG, trace, session,
                            verbose=False, keyjar=None, accept_exception=False)
    if reqi:
        respi.last_response = reqi.last_response
        respi.last_content = reqi.last_content

    respi.parse_response(environ)
    trace.info("{%s}%s" % (respi.response_type, respi.test_output))

    _phase = resp = _flow = None
    # are there more to do = step to next phase in the flow
    session["phase_index"] += 1
    try:
        _phase = PHASES[flow["sequence"][session["phase_index"]]]
    except IndexError:
        # next flow
        session["flow_index"] += 1
        session["phase_index"] = 0
        try:
            _flow = FLOWS[FLOW_SEQUENCE[session["flow_index"]]]
        except (KeyError, IndexError):
            resp = display_result(trace)

    return _phase, _flow, resp


def application(environ, start_response):
    session = Session(environ['beaker.session'])

    path = environ.get('PATH_INFO', '').lstrip('/')
    client = link = None
    if path == "robots.txt":
        return static(environ, start_response, LOGGER, "static/robots.txt")
    elif path.startswith("static/"):
        return static(environ, start_response, LOGGER, path)
    elif path == "keys":
        return static(environ, start_response, LOGGER, "keys/jwk")
    elif path == "":
        return opbyuid(environ, start_response)
    elif path == "rp":
        query = parse_qs(environ["QUERY_STRING"])
        if "uid" in query:
            try:
                link = RP.find_srv_discovery_url(resource=query["uid"][0])
            except requests.ConnectionError:
                resp = ServiceError("Webfinger lookup failed, connection error")
                return resp(environ, start_response)

            client = Client(client_authn_method=CLIENT_AUTHN_METHOD)

            try:
                client.keyjar = SERVER_ENV["KEYJAR"]
            except KeyError:
                pass

            client.redirect_uris = CLIENT_CONFIG["redirect_uris"]
            session["srv_discovery_url"] = link
            md5 = hashlib.md5()
            md5.update(link)
            opkey = base64.b16encode(md5.digest())
            SERVER_ENV["OIC_CLIENT"][opkey] = client
            session["opkey"] = opkey
        else:
            resp = BadRequest()
            return resp(environ, start_response)
    elif path.startswith("test/"):
        _test = path[5:]
        session["flow_index"] = FLOW_SEQUENCE.index(_test)
        session["phase_index"] = 0
        session["start"] = 0
        resp = Redirect("/")
        return resp(environ, start_response)

    try:
        flow = FLOWS[FLOW_SEQUENCE[session["flow_index"]]]
        if session["start"]:
            request = False
        else:
            request = True
    except (KeyError, TypeError):
        session["flow_index"] = 0
        session["phase_index"] = 0
        session["trace"] = Trace()
        request = True
        flow = FLOWS[FLOW_SEQUENCE[session["flow_index"]]]

    _phase = PHASES[flow["sequence"][session["phase_index"]]]

    _trace = session["trace"]
    if _trace is None:
        _trace = session["trace"] = Trace()
    _cli = resp = None
    if not request:  # Do response first
        _cli = SERVER_ENV["OIC_CLIENT"][session["opkey"]]
        _phase, _flow, resp = do_response(_phase, _cli, _trace,
                                          session, flow, environ)
        if resp:
            return resp(environ, start_response)
        if _phase is None:  # end of a flow
            resp = display_result(_trace)
            return resp(environ, start_response)

    # The request in a phase
    if _cli:
        client = _cli
    if link:
        kwargs = {"endpoint": link}
    else:
        kwargs = {}
    while True:
        reqi = action.Request(_phase, client, CLIENT_CONFIG, _trace, **kwargs)
        session["start"] = 1
        resp = reqi.do_query()

        if resp:
            return resp(environ, start_response)

        _trace.info("{%s}%s" % (reqi.req.__class__.__name__, reqi.test_output))
        if reqi.last_response.status_code == 200:
            if "<html>" in reqi.last_content and "</html>" in reqi.last_content:
                resp = Response(reqi.last_content)
                return resp(environ, start_response)

            _phase, _flow, resp = do_response(_phase, client, _trace, session,
                                              flow, None, reqi)
            if resp:
                break
            if _phase is None:  # end of a flow
                resp = display_result(_trace)
                break
        elif 300 <= reqi.last_response.status_code < 400:
            resp = R2C[reqi.last_response.status_code]()

    if not resp:
        resp = Response()
    return resp(environ, start_response)


if __name__ == '__main__':
    setup_server_env(rp_conf)

    session_opts = {
        'session.type': 'memory',
        'session.cookie_expires': True,
        #'session.data_dir': './data',
        'session.auto': True,
        'session.timeout': 900
    }

    FLOWS = oic_operations.FLOWS
    FLOW_SEQUENCE = FLOWS.keys()
    FLOW_SEQUENCE.sort()
    REGISTER = True
    DYNAMIC = True

    CLIENT_CONFIG["redirect_uris"] = [
        a % rp_conf.BASE for a in CLIENT_CONFIG["redirect_uris"]]

    for tag in FLOW_SEQUENCE:
        _seq = FLOWS[tag]["sequence"]
        if REGISTER:
            if "oic-registration" not in _seq:
                _seq.insert(0, "oic-registration")
        if DYNAMIC:
            if "provider-info" not in _seq:
                _seq.insert(0, "provider-info")

    RP = OpenIDConnect(registration_info=rp_conf.ME,
                       ca_bundle=rp_conf.CA_BUNDLE)

    SRV = wsgiserver.CherryPyWSGIServer(('0.0.0.0', rp_conf.PORT),
                                        SessionMiddleware(application,
                                                          session_opts))

    if rp_conf.BASE.startswith("https"):
        from cherrypy.wsgiserver import ssl_pyopenssl

        SRV.ssl_adapter = ssl_pyopenssl.pyOpenSSLAdapter(
            rp_conf.SERVER_CERT, rp_conf.SERVER_KEY, rp_conf.CA_BUNDLE)

    LOGGER.info("RP server starting listening on port:%s" % rp_conf.PORT)
    print "RP server starting listening on port:%s" % rp_conf.PORT
    try:
        SRV.start()
    except KeyboardInterrupt:
        SRV.stop()
