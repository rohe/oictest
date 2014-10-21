#!/usr/bin/env python
import copy
from jwkest.jwk import SerializationNotPossible
from oic.exception import UnSupported
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import dump_jwks
from oic.oauth2.message import SchemeError
from oic.utils.webfinger import OIC_ISSUER
from oic.utils.webfinger import WebFinger
from oic.utils.http_util import Response
from uma import AAT, PAT

from rrtest.request import BodyResponse
from rrtest.request import GetRequest
from rrtest.request import UrlResponse
from rrtest.request import PostRequest
from rrtest.request import Process
from rrtest.check import VerifyBadRequestResponse

__author__ = 'rohe0002'

# ========================================================================

import time

from oic.oauth2 import JSON_ENCODED, PBase

# Used upstream not in this module so don't remove
from oictest.check import *
from rrtest.opfunc import *

# ========================================================================

LOCAL_PATH = "export/"


class MissingResponseClaim(Exception):
    pass


def _get_base(cconf=None):
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


# noinspection PyUnusedLocal


def store_sector_redirect_uris(args, alla=True, extra=False, cconf=None):
    _base = _get_base(cconf)

    sector_identifier_url = "%s%s%s" % (_base, LOCAL_PATH, "siu.json")
    f = open("%ssiu.json" % LOCAL_PATH, 'w')
    if all:
        f.write(json.dumps(args["redirect_uris"]))
    else:
        f.write(json.dumps(args["redirect_uris"][:-1]))
    f.close()

    if extra:
        args["redirect_uris"].append("%scb" % _base)

    args["sector_identifier_uri"] = sector_identifier_url


def response_claim(conv, respcls, claim):
    val = None
    for (instance, msg) in conv.protocol_response:
        if isinstance(instance, respcls):
            val = json.loads(msg)[claim]
            break
    return val


# -----------------------------------------------------------------------------


class TimeDelay(Process):
    def __init__(self):
        self.delay = 2
        self.tests = {"post": [], "pre": []}

    def __call__(self, *args, **kwargs):
        time.sleep(self.delay)
        return None


class Notice(Process):
    def __init__(self):
        self.tests = {"post": [], "pre": []}

    def __call__(self, *args, **kwargs):
        pass


class ExpectError(Process):
    def __init__(self):
        Process.__init__(self)
        self.template = "expect_err.mako"

    def __call__(self, *args, **kwargs):
        pass


class RmCookie(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "rmcookie.mako"

    def __call__(self, lookup, environ, start_response, **kwargs):
        resp = Response(mako_template=self.template,
                        template_lookup=lookup,
                        headers=[])
        return resp(environ, start_response, **kwargs)


class RotateKeys(Process):
    def __init__(self):
        self.new_keys = {"RSA": "../keys/second.key"}
        self.kid_template = "b%d"
        self.jwk_name = "export/jwk.json"
        self.tests = {"post": [], "pre": []}

    def __call__(self, conv, **kwargs):
        kid = 0
        # only one key
        for typ, file_name in self.new_keys.items():
            kb = KeyBundle(source="file://%s" % file_name, fileformat="der",
                           keytype=typ)
            for k in kb.keys():
                k.serialize()
                k.kid = self.kid_template % kid
                kid += 1
                conv.client.kid[k.use][k.kty] = k.kid
            conv.client.keyjar.add_kb("", kb)

        dump_jwks(conv.client.keyjar[""], self.jwk_name)


# -----------------------------------------------------------------------------


class ProviderRequest(GetRequest):
    request = ""
    _tests = {"pre": [], "post": []}

    def __call__(self, *args, **kwargs):
        if "endpoint" in kwargs:
            kwargs["endpoint"] += ".well-known/openid-configuration"

        url, response, text = GetRequest.__call__(self, *args, **kwargs)
        return url, response, text


class MissingResponseType(GetRequest):
    request = "AuthorizationRequest"
    _request_args = {"response_type": [], "scope": ["openid"]}
    lax = True
    _tests = {"post": [VerifyBadRequestResponse]}


class AuthorizationRequest(GetRequest):
    request = "AuthorizationRequest"
    _request_args = {"scope": ["openid"]}
    _tests = {"pre": [CheckResponseType, CheckEndpoint],
              "post": []}
    interaction_check = True


class AuthorizationRequestCode(AuthorizationRequest):
    request = "AuthorizationRequest"
    _request_args = {"response_type": ["code"], "scope": ["openid"]}


class AuthorizationRequestCodeAAT(AuthorizationRequest):
    request = "AuthorizationRequest"
    _request_args = {"response_type": ["code"], "scope": [AAT]}


class AuthorizationRequestCodePAT(AuthorizationRequest):
    request = "AuthorizationRequest"
    _request_args = {"response_type": ["code"], "scope": [PAT]}

# =============================================================================


class RegistrationRequest(PostRequest):
    request = "RegistrationRequest"
    content_type = JSON_ENCODED
    _request_args = {}

    def __init__(self, conv):
        PostRequest.__init__(self, conv)

        for arg in message.RegistrationRequest().parameters():
            try:
                val = conv.client_config[arg]
            except KeyError:
                try:
                    val = conv.client_config["preferences"][arg]
                except KeyError:
                    try:
                        val = conv.client_config["client_info"][arg]
                    except KeyError:
                        continue
            self.request_args[arg] = copy.copy(val)
        try:
            del self.request_args["key_export_url"]
        except KeyError:
            pass

        # verify the registration info
        self.tests["post"].append(RegistrationInfo)


class ReadRegistration(GetRequest):
    def call_setup(self):
        _client = self.conv.client
        self.request_args["access_token"] = _client.registration_access_token
        self.kw_args["authn_method"] = "bearer_header"
        self.kw_args["endpoint"] = _client.registration_response[
            "registration_client_uri"]


# =============================================================================


class AccessTokenRequest(PostRequest):
    request = "AccessTokenRequest"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.tests["post"] = []
        #self.kw_args = {"authn_method": "client_secret_basic"}

    def call_setup(self):
        if "authn_method" not in self.kw_args:
            _pinfo = self.conv.provider_info
            if "token_endpoint_auth_methods_supported" in _pinfo:
                for meth in ["client_secret_basic", "client_secret_post",
                             "client_secret_jwt", "private_key_jwt"]:
                    if meth in _pinfo["token_endpoint_auth_methods_supported"]:
                        self.kw_args = {"authn_method": meth}
                        break
            else:
                self.kw_args = {"authn_method": "client_secret_basic"}


class AccessTokenRequestCSPost(AccessTokenRequest):
    def __init__(self, conv):
        AccessTokenRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "client_secret_post"}


class AccessTokenRequestCSJWT(AccessTokenRequest):
    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "client_secret_jwt"}


class AccessTokenRequestPKJWT(AccessTokenRequest):
    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "private_key_jwt"}


class ResourceSetRegistration(PostRequest):
    request = "ResourceSetDescription"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.kw_args = {"authn_method": ""}


class RefreshAccessToken(PostRequest):
    request = "RefreshAccessTokenRequest"

    def call_setup(self):
        # make sure there is a refresh_token
        try:
            _ = response_claim(self.conv, message.AccessTokenResponse,
                               "refresh_token")
        except MissingResponseClaim:
            raise UnSupported("No refresh_token")

        if "authn_method" not in self.kw_args:
            _pinfo = self.conv.provider_info
            if "token_endpoint_auth_methods_supported" in _pinfo:
                for meth in ["client_secret_basic", "client_secret_post",
                             "client_secret_jwt", "private_key_jwt"]:
                    if meth in _pinfo["token_endpoint_auth_methods_supported"]:
                        self.kw_args = {"authn_method": meth}
                        break
            else:
                self.kw_args = {"authn_method": "client_secret_basic"}


class RefreshAccessTokenPKJWT(PostRequest):
    request = "RefreshAccessTokenRequest"

    def call_setup(self):
        # make sure there is a refresh_token
        try:
            _ = response_claim(self.conv, message.AccessTokenResponse,
                               "refresh_token")
        except MissingResponseClaim:
            raise UnSupported("No refresh_token")

        self.kw_args = {"authn_method": "private_key_jwt"}

# -----------------------------------------------------------------------------


class AuthzResponse(UrlResponse):
    response = "AuthorizationResponse"
    _tests = {"post": [CheckAuthorizationResponse]}


class AuthzFormResponse(UrlResponse):
    response = "AuthorizationResponse"
    where = "body"
    _tests = {"post": [CheckAuthorizationResponse]}


class ImplicitAuthzResponse(AuthzResponse):
    _tests = {"post": [CheckAuthorizationResponse, VerifyImplicitResponse]}


class AuthzErrResponse(UrlResponse):
    response = "AuthorizationErrorResponse"


class RegistrationResponse(BodyResponse):
    response = "RegistrationResponse"

    def __call__(self, conv, response):
        _client = conv.client
        for prop in ["client_id"]:
            try:
                setattr(_client, prop, response[prop])
            except KeyError:
                pass


class AccessTokenResponse(BodyResponse):
    response = "AccessTokenResponse"

    def __init__(self):
        BodyResponse.__init__(self)
        self.tests = {"post": [VerifyAccessTokenResponse, VerifyISS]}


class CheckIdResponse(BodyResponse):
    response = "IdToken"


class ProviderConfigurationResponse(BodyResponse):
    response = "ProviderConfigurationResponse"


class ClientRegistrationErrorResponse(BodyResponse):
    response = "ClientRegistrationErrorResponse"


class AuthorizationErrorResponse(BodyResponse):
    response = "AuthorizationErrorResponse"


# ----------------------------------------------------------------------------


class DResponse(object):
    def __init__(self, status, ctype):
        self.content_type = ctype
        self.status = status

    def __getattr__(self, item):
        if item == "content-type":
            return self.content_type


class Discover(Operation):
    _tests = {"post": [ProviderConfigurationInfo, VerfyMTIEncSigAlgorithms,
                       CheckEncSigAlgorithms]}
    conv_param = "provider_info"
    request = None
    _path = ""

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.request = "DiscoveryRequest"
        self.function = self.discover
        self.do_postop = True
        self.tests = self._tests.copy()

    def discover(self, client, issuer, **kwargs):
        # Allow statically over-riding dynamic info
        over_ride = client.provider_info
        pcr = client.provider_config(issuer+self._path)
        if over_ride:
            pcr.update(over_ride)
            for key, val in over_ride.items():
                setattr(client, key, val)

        try:
            self.trace.info("%s" % client.keyjar)
        except SerializationNotPossible:
            pass

        self.trace.info("Provider info: %s" % pcr.to_dict())

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

        client.match_preferences(pcr)
        self.trace.info("Client behavior: %s" % client.behaviour)
        return "", DResponse(status=200, ctype="application/json"), pcr

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


class DiscoverCHashErr(Discover):
    path = "_/_/ch/normal"


class Webfinger(Operation):
    #tests = {"post": [OidcIssuer]}
    request = None
    format = ""

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.request = "WebFinger"
        self.function = self.finger
        self.do_postop = False

    @staticmethod
    def finger(**kwargs):
        wf = WebFinger(OIC_ISSUER)
        wf.httpd = PBase()
        return wf.discovery_query(kwargs["principal"])


class WebfingerEmail(Webfinger):
    format = "email"


class WebfingerURL(Webfinger):
    format = "url"


# ===========================================================================

PHASES = {
    "login": (AuthorizationRequestCode, AuthzResponse),
    "oic-login": (AuthorizationRequestCode, AuthzResponse),
    "oic-login-aat": (AuthorizationRequestCodeAAT, ImplicitAuthzResponse),
    "oic-login-pat": (AuthorizationRequestCodePAT, ImplicitAuthzResponse),
    "access-token-request_csp": (AccessTokenRequestCSPost, AccessTokenResponse),
    "access-token-request": (AccessTokenRequest, AccessTokenResponse),
    "access-token-request_csj": (AccessTokenRequestCSJWT, AccessTokenResponse),
    "access-token-request_pkj": (AccessTokenRequestPKJWT, AccessTokenResponse),
    "oic-registration": (RegistrationRequest, RegistrationResponse),
    "provider-discovery": (Discover, ProviderConfigurationResponse),
    "provider-info": (ProviderRequest, ProviderConfigurationResponse),
    "read-registration": (ReadRegistration, RegistrationResponse),
    "intermission": TimeDelay,
    "rotate_keys": RotateKeys,
    "notice": Notice,
    "rm_cookie": RmCookie,
    "expect_err": ExpectError,
    "webfinger_email": (WebfingerEmail, None),
    "webfinger_url": (WebfingerURL, None),
}
OWNER_OPS = []

FLOWS = {
    'webfinger-email': {
        "name": 'Can Discover Identifiers using E-Mail Syntax',
        "sequence": ["webfinger_email"],
        "block": ["registration", "key_export"],
    },
    'webfinger-url': {
        "name": 'Can Discover Identifiers using URL Syntax',
        "sequence": ["webfinger_url"],
        "block": ["registration", "key_export"],
    },
    'FT-*-get_config-data': {
        "name": 'Uses openid-configuration Discovery Information',
        "sequence": ["provider-discovery"],
        "block": ["registration", "key_export"],
    },
    'FT-*-get-dyn-client-creds': {
        "name": 'Uses Dynamic Registration',
        "sequence": ["provider-discovery", "oic-registration"],
        "block": ["registration", "key_export"],
    },
    'FT-rs-get-pat': {
        "name": "Can Make Access Token Request with 'client_secret_basic' "
                "Authentication and receive a PAT",
        "sequence": ["oic-login-pat", 'access-token-request']
    },
    'FT-as-require-pat': {
        "name": "AS allows RSs to make protection API calls IFF they present "
                "protection API scope",
        "sequence": ["resource_set_registration-no-pat"]
    },
    'FT-c-get-aat': {
        "name": "Can Make Access Token Request with 'client_secret_basic' "
                "Authentication and receive a AAT",
        "sequence": ["oic-login-aat", 'access-token-request']
    },
}

if __name__ == "__main__":
    for name, spec in FLOWS.items():
        try:
            for dep in spec["depends"]:
                try:
                    assert dep in FLOWS
                except AssertionError:
                    print "%s missing in FLOWS" % dep
                    raise
        except KeyError:
            pass
        for op in spec["sequence"]:
            try:
                assert op in PHASES
            except AssertionError:
                print "%s missing in PHASES" % op
                raise
