#!/usr/bin/env python
from oic.oic import OIDCONF_PATTERN
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import dump_jwks
from oic.utils.http_util import Response
from oic.utils.webfinger import WebFinger
from oic.utils.webfinger import OIC_ISSUER

import copy
from oic.oauth2.consumer import ConfigurationError
from oic.oauth2.message import SchemeError

from rrtest.request import BodyResponse
from rrtest.request import GetRequest
from rrtest.request import PostRequest
from rrtest.request import Process
from rrtest.request import UrlResponse

__author__ = 'rohe0002'

# ========================================================================

import time

from oic.oauth2 import JSON_ENCODED, PBase

# Used upstream, not in this module so don't remove
from oictest.check import *
from rrtest.opfunc import *

# ========================================================================

LOCAL_PATH = "export/"


class MissingResponseClaim(Exception):
    pass


class NotSupported(Exception):
    pass


class RequirementsNotMet(Exception):
    pass


def get_base(cconf=None):
    """
    Make sure a '/' terminated URL is returned
    """
    try:
        part = urlparse(cconf["_base_url"])
    except KeyError:
        part = urlparse(cconf["base_url"])
    # part = urlparse(cconf["redirect_uris"][0])

    if part.path:
        if not part.path.endswith("/"):
            _path = part.path[:] + "/"
        else:
            _path = part.path[:]
    else:
        _path = "/"

    return "%s://%s%s" % (part.scheme, part.netloc, _path, )


def response_claim(conv, respcls, claim):
    for (instance, msg) in conv.protocol_response:
        if isinstance(instance, respcls):
            return instance[claim]

    return None


# -----------------------------------------------------------------------------


class TimeDelay(Process):
    def __init__(self):
        self.delay = 30
        self.tests = {"post": [], "pre": []}

    def __call__(self, *args, **kwargs):
        time.sleep(self.delay)
        return None


class Notice(Process):
    def __init__(self):
        self.tests = {"post": [], "pre": []}
        self.template = ""

    def __call__(self, lookup, environ, start_response, **kwargs):
        resp = Response(mako_template=self.template,
                        template_lookup=lookup,
                        headers=[])
        return resp(environ, start_response, **kwargs)

    def cache(self, cache, conv, items):
        return None


class ExpectError(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "expect_err.mako"


class RmCookie(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "rmcookie.mako"

    def cache(self, cache, conv, items):
        pack = {}
        for item in items:
            if item == "id_token":
                pack[item] = conv.id_token

        key = hash("%s%f" % (items, time.time()))
        cache[str(key)] = pack
        return key


class Note(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "note.mako"


class DisplayUserInfo(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "userinfo.mako"


class DisplayIDToken(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "idtoken.mako"


class FetchKeys(Process):
    def __call__(self, conv, **kwargs):
        pi = conv.client.provider_info
        kb = KeyBundle(source=pi["jwks_uri"])
        kb.verify_ssl = False
        kb.update()

        try:
            conv.keybundle.append(kb)
        except AttributeError:
            conv.keybundle = [kb]


class CacheIdToken(Process):
    def __call__(self, conv, **kwargs):
        res = get_id_tokens(conv)
        try:
            conv.cache["id_token"] = res
        except KeyError:
            conv.cache = {"id_token": res}


class AuthorizationRequest(GetRequest):
    request = "AuthorizationRequest"
    endpoint = "authorization_endpoint"
    _request_args = {"scope": ["openid"]}
    _tests = {"pre": [CheckResponseType, CheckEndpoint],
              "post": []}


class AccessTokenRequest(PostRequest):
    request = "AccessTokenRequest"
    endpoint = "token_endpoint"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.tests["post"] = []
        # self.kw_args = {"authn_method": "client_secret_basic"}

    def call_setup(self):
        _pinfo = self.conv.client.provider_info
        try:
            _supported = _pinfo["token_endpoint_auth_methods_supported"]
        except KeyError:
            _supported = None

        if "authn_method" not in self.kw_args:
            if _supported:
                for meth in ["client_secret_basic", "client_secret_post",
                             "client_secret_jwt", "private_key_jwt"]:
                    if meth in _supported:
                        self.kw_args = {"authn_method": meth}
                        break
            else:
                self.kw_args = {"authn_method": "client_secret_basic"}
        elif _supported:
            try:
                assert self.kw_args["authn_method"] in _supported
            except AssertionError:
                raise NotSupported("Authn_method '%s' not supported" % (
                    self.kw_args["authn_method"]))


class DResponse(object):
    def __init__(self, status, ctype, text=""):
        self.content_type = ctype
        self.status = status
        self.text = text

    def __getattr__(self, item):
        if item == "content-type":
            return self.content_type


class Discover(Operation):
    conv_param = "provider_info"
    request = "DiscoveryRequest"

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.request = "DiscoveryRequest"
        self.function = self.discover
        self.do_postop = True
        self.tests = {}

    def discover(self, client, issuer=""):
        # Allow statically over-riding dynamic info
        over_ride = client.provider_info
        self.trace.info("Provider info discover from '%s'" % issuer)
        if issuer.endswith("/"):
            self.trace.request("URL: %s" % OIDCONF_PATTERN % issuer[:-1])
        else:
            self.trace.request("URL: %s" % OIDCONF_PATTERN % issuer)

        pcr = client.provider_config(issuer)
        if over_ride:
            pcr.update(over_ride)
            for key, val in over_ride.items():
                setattr(client, key, val)

        self.trace.response(pcr)

        try:
            pcr.verify()
        except SchemeError:
            try:
                if client.allow["no_https_issuer"]:
                    pass
                else:
                    raise
            except KeyError:
                raise

        #self.trace.info("Client behavior: %s" % client.behaviour)

        try:
            client.match_preferences(pcr)
        except ConfigurationError as err:
            return "", DResponse(400, "text/html", str(err)), pcr
        else:
            return "", DResponse(200, "application/json"), pcr

    def post_op(self, result, conv, args):
        # Update the conv with the provider information
        # This overwrites what's there before. In some cases this might not
        # be preferable.

        if self.do_postop:
            attr = getattr(conv, self.conv_param, None)
            if attr is None:
                setattr(conv, self.conv_param, result[2].to_dict())
            else:
                attr.update(result[2].to_dict())


class Webfinger(Operation):
    # tests = {"post": [OidcIssuer]}
    request = None
    tests = {"post": [], "pre": []}

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.request = "WebFinger"
        self.function = self.discover
        self.do_postop = False

    def discover(self, *arg, **kwargs):
        wf = WebFinger(OIC_ISSUER)
        wf.httpd = PBase()
        _url = wf.query(kwargs["principal"])
        self.trace.request("URL: %s" % _url)
        url = wf.discovery_query(kwargs["principal"])
        return url

    def call_setup(self):
        pass


class UserInfoRequestGetBearerHeader(GetRequest):
    request = "UserInfoRequest"
    endpoint = "userinfo_endpoint"

    def __init__(self, conv):
        GetRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "bearer_header"}
        #self.tests["post"] = [VerifyIDTokenUserInfoSubSame]


class RefreshAccessToken(PostRequest):
    request = "RefreshAccessTokenRequest"
    endpoint = "token_endpoint"


class ReadRegistration(GetRequest):
    def call_setup(self):
        _client = self.conv.client
        self.request_args["access_token"] = _client.registration_access_token
        self.kw_args["authn_method"] = "bearer_header"
        self.kw_args["endpoint"] = _client.registration_response[
            "registration_client_uri"]


# ========== RESPONSE MESSAGES ========

class ProviderConfigurationResponse(BodyResponse):
    response = "ProviderConfigurationResponse"


class RegistrationResponse(BodyResponse):
    response = "RegistrationResponse"

    def __call__(self, conv, response):
        _client = conv.client
        for prop in ["client_id"]:
            try:
                setattr(_client, prop, response[prop])
            except KeyError:
                pass


class AuthzResponse(UrlResponse):
    response = "AuthorizationResponse"


class AccessTokenResponse(BodyResponse):
    response = "AccessTokenResponse"

    def __init__(self):
        BodyResponse.__init__(self)


class UserinfoResponse(BodyResponse):
    response = "OpenIDSchema"

    def __init__(self):
        BodyResponse.__init__(self)


# ============================================================================

PHASES = {
    "provider-discovery": (Discover, ProviderConfigurationResponse),
    "oic-registration": (RegistrationRequest, RegistrationResponse),
    "oic-login": (AuthorizationRequest, AuthzResponse),
    "access-token-request": (AccessTokenRequest, AccessTokenResponse),
    "refresh-access-token": (RefreshAccessToken, AccessTokenResponse),
    "userinfo": (UserInfoRequestGetBearerHeader, UserinfoResponse),
    "read-registration": (ReadRegistration, RegistrationResponse),
    "intermission": TimeDelay,
    "rotate_sign_keys": RotateSigKeys,
    "rotate_enc_keys": RotateEncKeys,
    "note": Note,
    "rm_cookie": RmCookie,
    "expect_err": ExpectError,
    "webfinger": (Webfinger, None),
    "display_userinfo": DisplayUserInfo,
    "display_idtoken": DisplayIDToken,
    "fetch_keys": FetchKeys,
    "cache-id_token": CacheIdToken
}