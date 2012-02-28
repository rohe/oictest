#!/usr/bin/env python

__author__ = 'rohe0002'

# ========================================================================

import time
from importlib import import_module

from oictest.check import *
# Used upstream not in this module so don't remove
from oictest.opfunc import *
from oic.oic.consumer import Consumer

# ========================================================================

class Request():
    request = ""
    method = ""
    request_args= {}
    kw_args = {}
    tests = {"post": [CheckHTTPResponse], "pre":[]}

    def __init__(self, message_mod):
        self.message_mod = message_mod

    #noinspection PyUnusedLocal
    def __call__(self, environ, trace, location, response, content):
        _client = environ["client"]
        if isinstance(self.request, tuple):
            (mod, klass) = self.request
            imod = import_module(mod)
            cls = getattr(imod, klass)
        else:
            cls = getattr(self.message_mod, self.request)

        try:
            kwargs = self.kw_args.copy()
        except KeyError:
            kwargs = {}

        try:
            kwargs["request_args"] = self.request_args.copy()
            _req = kwargs["request_args"]
        except KeyError:
            _req = {}

        cis = getattr(_client, "construct_%s" % cls.__name__)(cls, **kwargs)

        ht_add = None

        if "authn_method" in kwargs:
            h_arg = _client.init_authentication_method(cis, **kwargs)
        else:
            h_arg = None

        url, body, ht_args, cis = _client.uri_and_body(cls, cis,
                                                      method=self.method,
                                                      request_args=_req)

        environ["cis"].append(cis)
        if h_arg:
            ht_args.update(h_arg)
        if ht_add:
            ht_args.update({"headers": ht_add})

        if trace:
            trace.request("URL: %s" % url)
            trace.request("BODY: %s" % body)

        response, content = _client.http_request(url, method=self.method,
                                                body=body, trace=trace,
                                                **ht_args)

        if trace:
            trace.reply("RESPONSE: %s" % response)
            trace.reply("CONTENT: %s" % unicode(content, encoding="utf-8"))

        return url, response, content

    def update(self, dic):
        _tmp = {"request": self.request_args, "kw": self.kw_args}
        for key, val in self.rec_update(_tmp, dic).items():
            setattr(self, "%s_args" % key, val)

    def rec_update(self, dic0, dic1):
        res = {}
        for key, val in dic0.items():
            if key not in dic1:
                res[key] = val
            else:
                if isinstance(val, dict):
                    res[key] = self.rec_update(val, dic1[key])
                else:
                    res[key] = dic1[key]

        for key, val in dic1.items():
            if key in dic0:
                continue
            else:
                res[key] = val

        return res

class GetRequest(Request):
    method = "GET"

class AuthorizationRequestCode(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"]}

class OpenIDRequestCode(GetRequest):
    request = "OpenIDRequest"
    request_args = {"response_type": ["code"], "scope": ["openid"]}
    tests = {"pre": [CheckResponseType],"post": [CheckHTTPResponse]}

class ConnectionVerify(GetRequest):
    request = "OpenIDRequest"
    request_args = {"response_type": ["code"], "scope": ["openid"]}
    tests = {"pre": [CheckResponseType],"post": [CheckHTTPResponse]}
    interaction_check = True

class OpenIDRequestCodeDisplayPage(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["display"] = "page"

class OpenIDRequestCodeDisplayPopUp(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["display"] = "popup"

class OpenIDRequestCodePromptNone(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["prompt"] = "none"
        self.tests["post"] = [verifyErrResponse]

class OpenIDRequestCodePromptLogin(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["prompt"] = "login"


class OpenIDRequestCodeScopeProfile(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["scope"].append("profile")

class OpenIDRequestCodeScopeEMail(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["scope"].append("email")

class OpenIDRequestCodeScopeAddress(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["scope"].append("address")

class OpenIDRequestCodeScopePhone(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["scope"].append("phone")

class OpenIDRequestCodeScopeAll(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["scope"].extend(["phone", "address", "email",
                                           "profile"])

class OpenIDRequestCodeUIClaim1(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["userinfo_claims"] = {"claims": {"name": None}}


class OpenIDRequestCodeUIClaim2(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["userinfo_claims"] = {"claims": {
                                                "picture": {"optional":True},
                                                "email": {"optional": True}}}

class OpenIDRequestCodeUIClaim3(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["userinfo_claims"] = {"claims": {
                                                "name": None,
                                                "picture": {"optional":True},
                                                "email": {"optional": True}}}

class OpenIDRequestCodeIDTClaim1(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["idtoken_claims"] = {"claims": {"auth_time": None}}

class OpenIDRequestCodeIDTClaim2(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["idtoken_claims"] = {"claims": {"acr": {"values":
                                                                      ["2"]}}}

class OpenIDRequestCodeIDTClaim3(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["idtoken_claims"] = {"claims": {"acr": None}}

class OpenIDRequestCodeIDTMaxAge1(OpenIDRequestCode):

    def __init__(self, message_mod):
        time.sleep(2)
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["idtoken_claims"] = {"max_age": 1}

class OpenIDRequestCodeIDTMaxAge10(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["idtoken_claims"] = {"max_age": 10}

class OpenIDRequestToken(GetRequest):
    request = "OpenIDRequest"
    request_args = {"response_type": ["token"], "scope": ["openid"]}
    tests = {"pre": [CheckResponseType],"post": [CheckHTTPResponse]}

class OpenIDRequestIDToken(GetRequest):
    request = "OpenIDRequest"
    request_args = {"response_type": ["id_token"], "scope": ["openid"]}
    tests = {"pre": [CheckResponseType],"post": [CheckHTTPResponse]}

class OpenIDRequestCodeToken(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["response_type"].append("token")

class OpenIDRequestCodeIDToken(OpenIDRequestCode):

    def __init__(self, message_mod):
        OpenIDRequestCode.__init__(self, message_mod)
        self.request_args["response_type"].append("id_token")

class OpenIDRequestIDTokenToken(OpenIDRequestIDToken):

    def __init__(self, message_mod):
        OpenIDRequestIDToken.__init__(self, message_mod)
        self.request_args["response_type"].append("token")

class OpenIDRequestCodeIDTokenToken(OpenIDRequestCodeIDToken):

    def __init__(self, message_mod):
        OpenIDRequestCodeIDToken.__init__(self, message_mod)
        self.request_args["response_type"].append("token")

class PostRequest(Request):
    method = "POST"

class RegistrationRequest(PostRequest):
    request = "RegistrationRequest"

    def __init__(self, message_mod):
        PostRequest.__init__(self, message_mod)

        self.request_args = {"type": "client_associate",
                             "redirect_uris": ["https://example.com/authz_cb"],
                             "contact": ["roland@example.com"],
                             "application_type": "web",
                             "application_name": "OIC test tool"}

        self.tests["post"].append(RegistrationInfo)

class AccessTokenRequestCSBasic(PostRequest):
    request = "AccessTokenRequest"

    def __init__(self, message_mod):
        PostRequest.__init__(self, message_mod)
        self.kw_args = {"authn_method": "client_secret_basic"}

class AccessTokenRequestCSPost(AccessTokenRequestCSBasic):

    def __init__(self, message_mod):
        PostRequest.__init__(self, message_mod)
        self.kw_args = {"authn_method": "client_secret_post"}

class UserInfoRequestGetBearerHeader(GetRequest):
    request = "UserInfoRequest"

    def __init__(self, message_mod):
        GetRequest.__init__(self, message_mod)
        self.kw_args = {"authn_method": "bearer_header"}

class UserInfoRequestPostBearerHeader(PostRequest):
    request = "UserInfoRequest"

    def __init__(self, message_mod):
        PostRequest.__init__(self, message_mod)
        self.kw_args = {"authn_method": "bearer_header"}

class UserInfoRequestPostBearerBody(PostRequest):
    request = "UserInfoRequest"

    def __init__(self, message_mod):
        PostRequest.__init__(self, message_mod)
        self.kw_args = {"authn_method": "bearer_body"}

class CheckIDRequestGetBearerHeader(GetRequest):
    request = "CheckIDRequest"

    def __init__(self, message_mod):
        GetRequest.__init__(self, message_mod)
        self.kw_args = {"authn_method": "bearer_header"}

class CheckIDRequestPostBearerHeader(PostRequest):
    request = "CheckIDRequest"

    def __init__(self, message_mod):
        PostRequest.__init__(self, message_mod)
        self.kw_args = {"authn_method": "bearer_header"}

class CheckIDRequestPostBearerBody(PostRequest):
    request = "CheckIDRequest"

    def __init__(self, message_mod):
        PostRequest.__init__(self, message_mod)
        self.kw_args = {"authn_method": "bearer_body"}

# -----------------------------------------------------------------------------

class Response():
    response = ""
    tests = {}

    def __init__(self):
        pass

    def __call__(self, environ, response):
        pass

class UrlResponse(Response):
    where = "url"
    type = "urlencoded"

class AuthzResponse(UrlResponse):
    response = "AuthorizationResponse"
    tests = {"post": [CheckAuthorizationResponse]}

class AuthzErrResponse(UrlResponse):
    response = "AuthorizationErrorResponse"
    tests = {"post": [LoginRequired]}

class BodyResponse(Response):
    where = "body"
    type = "json"

class RegistrationResponse(BodyResponse):
    response = "RegistrationResponse"

    def __call__(self, environ, response):
        _client = environ["client"]
        for prop in ["client_id", "client_secret"]:
            try:
                _val = getattr(response, prop)
                setattr(_client, prop, _val)
            except KeyError:
                pass

class AccessTokenResponse(BodyResponse):
    response = "AccessTokenResponse"

    def __init__(self):
        BodyResponse.__init__(self)
        self.tests = {"post": [VerifyAccessTokenResponse]}

class UserinfoResponse(BodyResponse):
    response = "OpenIDSchema"

    def __init__(self):
        BodyResponse.__init__(self)
        self.tests = {"post": [ScopeWithClaims]}

class CheckIdResponse(BodyResponse):
    response = "IdToken"

class ProviderConfigurationResponse(BodyResponse):
    response = "ProviderConfigurationResponse"

# ----------------------------------------------------------------------------
class DResponse(object):
    def __init__(self, status, type):
        self.content_type = type
        self.status = status

    def __getattr__(self, item):
        if item == "content-type":
            return self.content_type


#noinspection PyUnusedLocal
def discover(self, client, orig_response, content, issuer, location, _trace_):
    pcr = client.provider_config(issuer)
    return "", DResponse(200, "application/json"), pcr


class Discover(Operation):
    tests = {"post": [ProviderConfigurationInfo]}
    function = discover
    environ_param = "provider_info"

    def post_op(self, result, environ, args):
        # Update the environ with the provider information
        # This overwrites what's there before. In some cases this might not
        # be preferable.

        environ[self.environ_param].update(result[2].dictionary(True))

# ===========================================================================

PHASES= {
    "login": (AuthorizationRequestCode, AuthzResponse),
    "verify": (ConnectionVerify, AuthzResponse),
    "oic-login": (OpenIDRequestCode, AuthzResponse),
    "oic-login+profile": (OpenIDRequestCodeScopeProfile, AuthzResponse),
    "oic-login+email": (OpenIDRequestCodeScopeEMail, AuthzResponse),
    "oic-login+phone": (OpenIDRequestCodeScopePhone, AuthzResponse),
    "oic-login+address": (OpenIDRequestCodeScopeAddress, AuthzResponse),
    "oic-login+all": (OpenIDRequestCodeScopeAll, AuthzResponse),
    "oic-login+spec1": (OpenIDRequestCodeUIClaim1, AuthzResponse),
    "oic-login+spec2": (OpenIDRequestCodeUIClaim2, AuthzResponse),
    "oic-login+spec3": (OpenIDRequestCodeUIClaim3, AuthzResponse),

    "oic-login+idtc1": (OpenIDRequestCodeIDTClaim1, AuthzResponse),
    "oic-login+idtc2": (OpenIDRequestCodeIDTClaim2, AuthzResponse),
    "oic-login+idtc3": (OpenIDRequestCodeIDTClaim3, AuthzResponse),
    "oic-login+idtc4": (OpenIDRequestCodeIDTMaxAge1, AuthzResponse),
    "oic-login+idtc5": (OpenIDRequestCodeIDTMaxAge10, AuthzResponse),

    "oic-login+disp_page": (OpenIDRequestCodeDisplayPage, AuthzResponse),
    "oic-login+disp_popup": (OpenIDRequestCodeDisplayPopUp, AuthzResponse),

    "oic-login+prompt_none": (OpenIDRequestCodePromptNone, None),
    "oic-login+prompt_login": (OpenIDRequestCodePromptLogin, AuthzResponse),

    "oic-login-token": (OpenIDRequestToken, AuthzResponse),
    "oic-login-idtoken": (OpenIDRequestIDToken, AuthzResponse),
    "oic-login-code+token": (OpenIDRequestCodeToken, AuthzResponse),
    "oic-login-code+idtoken": (OpenIDRequestCodeIDToken, AuthzResponse),
    "oic-login-idtoken+token": (OpenIDRequestIDTokenToken, AuthzResponse),
    "oic-login-code+idtoken+token": (OpenIDRequestCodeIDTokenToken,
                                     AuthzResponse),
#
    "access-token-request_basic":(AccessTokenRequestCSPost,
                                  AccessTokenResponse),
    "access-token-request":(AccessTokenRequestCSBasic, AccessTokenResponse),
    "check-id-request_gbh":(CheckIDRequestGetBearerHeader, CheckIdResponse),
    "check-id-request_pbh":(CheckIDRequestPostBearerHeader, CheckIdResponse),
    "check-id-request_pbb":(CheckIDRequestPostBearerBody, CheckIdResponse),
    "user-info-request":(UserInfoRequestGetBearerHeader, UserinfoResponse),
    "user-info-request_pbh":(UserInfoRequestPostBearerHeader, UserinfoResponse),
    "user-info-request_pbb":(UserInfoRequestPostBearerBody, UserinfoResponse),
    "oic-registration": (RegistrationRequest, RegistrationResponse),
    "provider-discovery": (Discover, ProviderConfigurationResponse)
}


FLOWS = {
    'oic-verify': {
        "name": 'Special flow used to find necessary user interactions',
        "descr": ('Request with response_type=code'),
        "sequence": ["verify"],
        "endpoints": ["authorization_endpoint"]
    },
    'oic-code': {
        "name": 'Request with response_type=code',
        "descr": ('Request with response_type=code'),
        "sequence": ["oic-login"],
        "endpoints": ["authorization_endpoint"]
    },
    'oic-token': {
        "name": 'Request with response_type=token',
        "descr": ('Request with response_type=token'),
        "sequence": ["oic-login-token"],
        "endpoints": ["authorization_endpoint"]
    },
    'oic-idtoken': {
        "name": 'Request with response_type=id_token',
        "descr": ('Request with response_type=id_token'),
        "sequence": ["oic-login-idtoken"],
        "endpoints": ["authorization_endpoint"]
    },
    'oic-code+token': {
        "name": 'Request with response_type=code token',
        "descr": ("Request with response_type=code token"),
        "sequence": ["oic-login-code+token"],
        "endpoints": ["authorization_endpoint"],
        },
    'oic-code+idtoken': {
        "name": 'Request with response_type=code id_token',
        "descr": ("Request with response_type=code id_token"),
        "sequence": ['oic-login-code+idtoken'],
        "endpoints": ["authorization_endpoint"],
        },
    'oic-idtoken+token': {
        "name": 'Request with response_type=id_token token',
        "descr": ("Request with response_type=id_token token"),
        "sequence": ['oic-login-idtoken+token'],
        "endpoints": ["authorization_endpoint"],
        },
    'oic-code+idtoken+token': {
        "name": 'Request with response_type=code id_token token',
        "descr": ("Request with response_type=code id_token token"),
        "sequence": ['oic-login-code+idtoken+token'],
        "endpoints": ["authorization_endpoint",],
        },
    # -------------------------------------------------------------------------
    'oic-code-token': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code'],
        "sequence": ["oic-login", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+token-token': {
        "name": "",
        "descr": ("1) Request with response_type='code token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code+token'],
        "sequence": ["oic-login-code+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken-token': {
        "name": "",
        "descr": ("1) Request with response_type='code id_token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code+idtoken'],
        "sequence": ["oic-login-code+idtoken", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken+token-token': {
        "name": "",
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code+idtoken+token'],
        "sequence": ["oic-login-code+idtoken+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # -------------------------------------------------------------------------
    'oic-code-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'oic-code+profile-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'profile']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+profile", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+email-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'email']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+email", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+address-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'address']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+address", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+phone-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'phone']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+phone", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+all-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'email', 'phone', 'address', 'profile']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+all", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+spec1-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+spec1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+spec2-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+spec2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+spec3-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+spec3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtc1-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+idtc1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "tests": [("verifyIDToken", {"claims":{"auth_time": None}})]
        },
    'oic-code+idtc2-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+idtc2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtc3-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+idtc3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type='token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-token'],
        "sequence": ['oic-login-token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type='code token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code+token'],
        "sequence": ['oic-login-code+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken-token-userinfo': {
        "name": 'Implicit flow with Code+IDToken ',
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code+idtoken-token'],
        "sequence": ['oic-login-code+idtoken', "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'oic-idtoken+token-userinfo': {
        "name": 'Implicit flow with Token+IDToken ',
        "descr": ("1) Request with response_type='id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-idtoken+token'],
        "sequence": ['oic-login-idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-userinfo': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends":["oic-code+idtoken+token"],
        "sequence": ['oic-login-code+idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-token-userinfo': {
        "name": ("Get an accesstoken using access code with 'token' and ",
                 "'idtoken' in response type"),
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code+idtoken+token-token'],
        "sequence": ["oic-login-code+idtoken+token", "access-token-request",
                     'user-info-request'],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },

    # -------------------------------------------------------------------------
    'oic-code-token-check_id': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request", "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'oic-code-token-check_id_pbh': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'oic-code-token-check_id_pbb': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'oic-idtoken+token-check_id': {
        "name": '',
        "descr": ("1) Request with response_type='id_token token'",
                  "2) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-idtoken+token'],
        "sequence": ['oic-login-idtoken+token', "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
    },
    'oic-code+idtoken-check_id': {
        "name": '',
        "descr": ("1) Request with response_type='code id_token'",
                  "2) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends":["oic-code+idtoken"],
        "sequence": ['oic-login-code+idtoken', "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": ["compare-idoken-received-with-check_id-response"]
    },
    'oic-code+idtoken+token-check_id': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends":["oic-code+idtoken+token"],
        "sequence": ['oic-login-code+idtoken+token', "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": ["compare-idoken-received-with-check_id-response"]
    },
    # beared body authentication
    'oic-code-token-userinfo_bb': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'oic-token-userinfo_bb': {
        "name": '',
        "descr": ("1) Request with response_type='token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-token'],
        "sequence": ['oic-login-token', "user-info-request_pbb"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'mj-00': {
        "name": 'Client registration Request',
        "sequence": ["oic-registration"],
        "endpoints": ["registration_endpoint"]
    },
    'mj-01': {
        "name": 'Request with response_type=code',
        "sequence": ["oic-login"],
        "endpoints": ["authorization_endpoint"]
    },
    'mj-02': {
        "name": 'Request with response_type=token',
        "sequence": ["oic-login-token"],
        "endpoints": ["authorization_endpoint"]
    },
    'mj-03': {
        "name": 'Request with response_type=id_token',
        "sequence": ["oic-login-idtoken"],
        "endpoints": ["authorization_endpoint"]
    },
    'mj-04': {
        "name": 'Request with response_type=code token',
        "sequence": ["oic-login-code+token"],
        "endpoints": ["authorization_endpoint"],
        },
    'mj-05': {
        "name": 'Request with response_type=code id_token',
        "sequence": ['oic-login-code+idtoken'],
        "endpoints": ["authorization_endpoint"],
        },
    'mj-06': {
        "name": 'Request with response_type=id_token token',
        "sequence": ['oic-login-idtoken+token'],
        "endpoints": ["authorization_endpoint"],
        },
    'mj-07': {
        "name": 'Request with response_type=code id_token token',
        "sequence": ['oic-login-code+idtoken+token'],
        "endpoints": ["authorization_endpoint",],
        },
    # -------------------------------------------------------------------------
    'mj-08': {
        "name": 'Check ID Endpoint Access with GET and bearer_header',
        "sequence": ["oic-login", "access-token-request", "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'mj-09': {
        "name": 'Check ID Endpoint Access with POST and bearer_header',
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'mj-10': {
        "name": 'Check ID Endpoint Access with POST and bearer_body',
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    # -------------------------------------------------------------------------
    'mj-11': {
        "name": 'UserInfo Endpoint Access with GET and bearer_header',
        "sequence": ["oic-login", "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-12': {
        "name": 'UserInfo Endpoint Access with POST and bearer_header',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_pbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-13': {
        "name": 'UserInfo Endpoint Access with POST and bearer_body',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    # -------------------------------------------------------------------------
    'mj-14': {
        "name": 'Scope Requesting profile Claims',
        "sequence": ["oic-login+profile", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-15': {
        "name": 'Scope Requesting email Claims',
        "sequence": ["oic-login+email", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-16': {
        "name": 'Scope Requesting address Claims',
        "sequence": ["oic-login+address", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-17': {
        "name": 'Scope Requesting phone Claims',
        "sequence": ["oic-login+phone", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-18': {
        "name": 'Scope Requesting all Claims',
        "sequence": ["oic-login+all", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-19': {
        "name": 'OpenID Request Object with Required name Claim',
        "sequence": ["oic-login+spec1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-20': {
        "name": 'OpenID Request Object with Optional email and picture Claim',
        "sequence": ["oic-login+spec2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-21': {
        "name": ('OpenID Request Object with Required name and Optional email and picture Claim'),
        "sequence": ["oic-login+spec3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-22': {
        "name": 'Requesting ID Token with auth_time Claim',
        "sequence": ["oic-login+idtc1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"claims":{"auth_time": None}})]
        },
    'mj-23': {
        "name": 'Requesting ID Token with Required acr Claim',
        "sequence": ["oic-login+idtc2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"claims":{"acr": {"values": ["2"]}}})]
        },
    'mj-24': {
        "name": 'Requesting ID Token with Optional acr Claim',
        "sequence": ["oic-login+idtc3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"claims":{"acr": None}})]
        },
    'mj-25a': {
        "name": 'Requesting ID Token with max_age=1 seconds Restriction',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request", "oic-login+idtc4",
                     "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("multiple-sign-on", {})]
        },
    'mj-25b': {
        "name": 'Requesting ID Token with max_age=10 seconds Restriction',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request", "oic-login+idtc5",
                     "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("single-sign-on", {})]
    },
    # ---------------------------------------------------------------------
    'mj-26': {
        "name": 'Request with display=page',
        "sequence": ["oic-login+disp_page", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-27': {
        "name": 'Request with display=popup',
        "sequence": ["oic-login+disp_popup", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-28': {
        "name": 'Request with prompt=none',
        "sequence": ["oic-login+prompt_none"],
        "endpoints": ["authorization_endpoint"],
        },
    'mj-29': {
        "name": 'Request with prompt=login',
        "sequence": ["oic-login+prompt_login", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # ---------------------------------------------------------------------
    'x-30': {
        "name": 'Scope Requesting profile Claims with aggregated Claims',
        "sequence": ["oic-login+profile", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("unpack-aggregated-claims", {})]

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