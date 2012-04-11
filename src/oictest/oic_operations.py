#!/usr/bin/env python

__author__ = 'rohe0002'

# ========================================================================

import time
import socket

from oic.oic.message import SCHEMA
from oictest.check import *
# Used upstream not in this module so don't remove
from oictest.opfunc import *
from oic.oic.consumer import Consumer

# ========================================================================

class Request():
    request = ""
    method = ""
    lax = False
    request_args= {}
    kw_args = {}
    tests = {"post": [CheckHTTPResponse], "pre":[]}

    def __init__(self):
        pass

    #noinspection PyUnusedLocal
    def __call__(self, environ, trace, location, response, content):
        _client = environ["client"]
        if isinstance(self.request, basestring):
            schema = SCHEMA[self.request]
        else:
            schema = self.request

        try:
            kwargs = self.kw_args.copy()
        except KeyError:
            kwargs = {}

        try:
            kwargs["request_args"] = self.request_args.copy()
            _req = kwargs["request_args"]
        except KeyError:
            _req = {}

        cis = getattr(_client, "construct_%s" % schema["name"])(schema,
                                                                **kwargs)

        try:
            cis.lax = self.lax
        except AttributeError:
            pass

        ht_add = None

        if "authn_method" in kwargs:
            h_arg = _client.init_authentication_method(cis, **kwargs)
        else:
            h_arg = None

        url, body, ht_args, cis = _client.uri_and_body(schema["name"], cis,
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
            try:
                trace.request("HEADERS: %s" % ht_args["headers"])
            except KeyError:
                pass

        response = _client.http_request(url, method=self.method,
                                            data=body, **ht_args)

        if trace:
            trace.reply("RESPONSE: %s" % response)
            trace.reply("CONTENT: %s" % response.text)

        return url, response, response.text

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

class MissingResponseType(GetRequest):
    request = "AuthorizationRequest"
    request_args = {"response_type": []}
    lax = True
    tests = {"post": [CheckRedirectErrorResponse]}

class AuthorizationRequestCode(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"]}

class AuthorizationRequestCode_WQC(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"],
                   "query": "component"}
    tests = {"pre": [CheckResponseType],
             "post": [CheckHTTPResponse]}

class AuthorizationRequestCode_RUWQC(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"],
            "redirect_uri": "https://smultron.catalogix.se/authz_cb?foo=bar"}
    tests = {"pre": [CheckResponseType],
             "post": [CheckHTTPResponse]}

    def __call__(self, environ, trace, location, response, content):
        _client = environ["client"]
        base_url = _client.redirect_uris[0]
        self.request_args["redirect_uri"] = base_url + "?foo=bar"
        return Request.__call__(self, environ, trace, location, response,
                                content)

class AuthorizationRequest_Mismatching_Redirect_uri(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"],
                   "redirect_uri": "https://hallon.catalogix.se/authz_cb"}
    tests = {"pre": [CheckResponseType],
             "post": [CheckErrorResponse]}

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

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["display"] = "page"

class OpenIDRequestCodeDisplayPopUp(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["display"] = "popup"

class OpenIDRequestCodePromptNone(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["prompt"] = "none"
        self.tests["post"] = [VerifyErrResponse]

class OpenIDRequestCodePromptLogin(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["prompt"] = "login"


class OpenIDRequestCodeScopeProfile(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["scope"].append("profile")

class OpenIDRequestCodeScopeEMail(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["scope"].append("email")

class OpenIDRequestCodeScopeAddress(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["scope"].append("address")

class OpenIDRequestCodeScopePhone(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["scope"].append("phone")

class OpenIDRequestCodeScopeAll(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["scope"].extend(["phone", "address", "email",
                                           "profile"])

class OpenIDRequestCodeUIClaim1(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["userinfo_claims"] = {"claims": {"name": None}}


class OpenIDRequestCodeUIClaim2(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["userinfo_claims"] = {"claims": {
                                                "picture": {"optional":True},
                                                "email": {"optional": True}}}

class OpenIDRequestCodeUIClaim3(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["userinfo_claims"] = {"claims": {
                                                "name": None,
                                                "picture": {"optional":True},
                                                "email": {"optional": True}}}

class OpenIDRequestCodeIDTClaim1(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["idtoken_claims"] = {"claims": {"auth_time": None}}

class OpenIDRequestCodeIDTClaim2(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["idtoken_claims"] = {"claims": {"acr": {"values":
                                                                      ["2"]}}}

class OpenIDRequestCodeIDTClaim3(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["idtoken_claims"] = {"claims": {"acr": None}}

class OpenIDRequestCodeIDTMaxAge1(OpenIDRequestCode):

    def __init__(self):
        time.sleep(2)
        OpenIDRequestCode.__init__(self)
        self.request_args["idtoken_claims"] = {"max_age": 1}

class OpenIDRequestCodeIDTMaxAge10(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
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

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["response_type"].append("token")

class OpenIDRequestCodeIDToken(OpenIDRequestCode):

    def __init__(self):
        OpenIDRequestCode.__init__(self)
        self.request_args["response_type"].append("id_token")

class OpenIDRequestIDTokenToken(OpenIDRequestIDToken):

    def __init__(self):
        OpenIDRequestIDToken.__init__(self)
        self.request_args["response_type"].append("token")

class OpenIDRequestCodeIDTokenToken(OpenIDRequestCodeIDToken):

    def __init__(self):
        OpenIDRequestCodeIDToken.__init__(self)
        self.request_args["response_type"].append("token")

class PostRequest(Request):
    method = "POST"

class RegistrationRequest(PostRequest):
    request = "RegistrationRequest"

    def __init__(self):
        PostRequest.__init__(self)

        self.request_args = {"type": "client_associate",
                             "redirect_uris": ["https://example.com/authz_cb"],
                             "contact": ["roland@example.com"],
                             "application_type": "web",
                             "application_name": "OIC test tool"}

        self.tests["post"].append(RegistrationInfo)

class RegistrationRequest_WQC(PostRequest):
    request = "RegistrationRequest"

    def __init__(self):
        PostRequest.__init__(self)

        self.request_args = {"type": "client_associate",
                    "redirect_uris": ["https://example.com/authz_cb?foo=bar"],
                    "contact": ["roland@example.com"],
                    "application_type": "web",
                    "application_name": "OIC test tool"}

        self.tests["post"].append(RegistrationInfo)

from oictest import key_export
from oictest import start_script

class RegistrationRequest_WF(PostRequest):
    request = "RegistrationRequest"
    tests = {"post": [CheckErrorResponse]}

    def __init__(self):
        PostRequest.__init__(self)

        self.request_args = {"type": "client_associate",
                     "redirect_uris": ["https://example.com/authz_cb#foobar"],
                     "contact": ["roland@example.com"],
                     "application_type": "web",
                     "application_name": "OIC test tool"}



class RegistrationRequest_KeyExp(PostRequest):
    request = "RegistrationRequest"

    def __init__(self):
        PostRequest.__init__(self)

        self.request_args = {"type": "client_associate",
                             "redirect_uris": ["https://example.com/authz_cb"],
                             "contact": ["roland@example.com"],
                             "application_type": "web",
                             "application_name": "OIC test tool"}

        self.export_info = {
            "script": "../../script/static_provider.py",
            "server": "http://%s:8090/export" % socket.gethostname(),
            "local_path": "./keys",
            "sign": {
                "alg":"rsa",
                "create_if_missing": True,
                "format": "jwk",
            }}


    def __call__(self, environ, trace, location, response, content):
        _client = environ["client"]
        part, res = key_export(**self.export_info)

        # Do the redirect_uris dynamically
        self.request_args["redirect_uris"] = _client.redirect_uris

        for name, (url, keyspecs) in res.items():
            self.request_args[name] = url
            for key, typ, usage in keyspecs:
                _client.keystore.add_key(key, typ, usage)

        if "keyprovider" not in environ:
            try:
                (host, port) = part.netloc.split(":")
            except ValueError:
                host = part.netloc
                port = 80

            _pop = start_script(self.export_info["script"], host, port)
            environ["keyprovider"] = _pop
            trace.info("Started key provider")
            time.sleep(1)

        return PostRequest.__call__(self, environ, trace, location, response,
                              content)

class AccessTokenRequest(PostRequest):
    request = "AccessTokenRequest"

    def __init__(self):
        PostRequest.__init__(self)
        #self.kw_args = {"authn_method": "client_secret_basic"}

    def __call__(self, environ, trace, location, response, content):
        if "authn_method" not in self.kw_args:
            _pinfo = environ["provider_info"]
            if "token_endpoint_auth_types_supported" in _pinfo:
                for meth in ["client_secret_basic", "client_secret_post",
                             "client_secret_jwt", "private_key_jwt"]:
                    if meth in _pinfo["token_endpoint_auth_types_supported"]:
                        self.kw_args = {"authn_method": meth}
                        break
            else:
                self.kw_args = {"authn_method": "client_secret_basic"}
        return Request.__call__(self, environ, trace, location, response,
                              content)
        
        
class AccessTokenRequestCSPost(AccessTokenRequest):

    def __init__(self):
        PostRequest.__init__(self)
        self.kw_args = {"authn_method": "client_secret_post"}

class AccessTokenRequestCSJWT(AccessTokenRequest):

    def __init__(self):
        PostRequest.__init__(self)
        self.kw_args = {"authn_method": "client_secret_jwt"}

class AccessTokenRequestPKJWT(AccessTokenRequest):

    def __init__(self):
        PostRequest.__init__(self)
        self.kw_args = {"authn_method": "private_key_jwt"}

class AccessTokenRequest_err(AccessTokenRequest):

    def __init__(self):
        PostRequest.__init__(self)
        self.tests["post"]=[]

class UserInfoRequestGetBearerHeader(GetRequest):
    request = "UserInfoRequest"

    def __init__(self):
        GetRequest.__init__(self)
        self.kw_args = {"authn_method": "bearer_header"}

class UserInfoRequestGetBearerHeader_err(GetRequest):
    request = "UserInfoRequest"

    def __init__(self):
        GetRequest.__init__(self)
        self.kw_args = {"authn_method": "bearer_header"}
        self.tests["post"]=[CheckErrorResponse]

class UserInfoRequestPostBearerHeader(PostRequest):
    request = "UserInfoRequest"

    def __init__(self):
        PostRequest.__init__(self)
        self.kw_args = {"authn_method": "bearer_header"}

class UserInfoRequestPostBearerBody(PostRequest):
    request = "UserInfoRequest"

    def __init__(self):
        PostRequest.__init__(self)
        self.kw_args = {"authn_method": "bearer_body"}

class CheckIDRequestGetBearerHeader(GetRequest):
    request = "CheckIDRequest"

    def __init__(self):
        GetRequest.__init__(self)
        self.kw_args = {"authn_method": "bearer_header"}

class CheckIDRequestPostBearerHeader(PostRequest):
    request = "CheckIDRequest"

    def __init__(self):
        PostRequest.__init__(self)
        self.kw_args = {"authn_method": "bearer_header"}

class CheckIDRequestPostBearerBody(PostRequest):
    request = "CheckIDRequest"

    def __init__(self):
        PostRequest.__init__(self)
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
    #tests = {"post": [LoginRequired]}

#class RedirectedErrorResponse(UrlResponse):
#    response = "AuthorizationErrorResponse"
#    tests = {"post": [InvalidRequest]}

class BodyResponse(Response):
    where = "body"
    type = "json"

class RegistrationResponse(BodyResponse):
    response = "RegistrationResponse"

    def __call__(self, environ, response):
        _client = environ["client"]
        _client.keystore.remove_key_type("hmac")
        for prop in ["client_id", "client_secret"]:
            try:
                setattr(_client, prop, response[prop])
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

class ClientRegistrationErrorResponse(BodyResponse):
    response = "ClientRegistrationErrorResponse"

class AuthorizationErrorResponse(BodyResponse):
    response = "AuthorizationErrorResponse"

class ErrorResponse(BodyResponse):
    response = "ErrorResponse"

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

        environ[self.environ_param].update(result[2].to_dict())

# ===========================================================================

PHASES= {
    "login": (AuthorizationRequestCode, AuthzResponse),
    "login-wqc": (AuthorizationRequestCode_WQC, AuthzResponse),
    "login-ruwqc": (AuthorizationRequestCode_RUWQC, AuthzResponse),
    "login-redirect-fault": (AuthorizationRequest_Mismatching_Redirect_uri,
                             AuthorizationErrorResponse),
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

    "oic-login+prompt_none": (OpenIDRequestCodePromptNone, AuthzErrResponse),
    "oic-login+prompt_login": (OpenIDRequestCodePromptLogin, AuthzResponse),

    "oic-login-token": (OpenIDRequestToken, AuthzResponse),
    "oic-login-idtoken": (OpenIDRequestIDToken, AuthzResponse),
    "oic-login-code+token": (OpenIDRequestCodeToken, AuthzResponse),
    "oic-login-code+idtoken": (OpenIDRequestCodeIDToken, AuthzResponse),
    "oic-login-idtoken+token": (OpenIDRequestIDTokenToken, AuthzResponse),
    "oic-login-code+idtoken+token": (OpenIDRequestCodeIDTokenToken,
                                     AuthzResponse),
#
    "access-token-request_csp":(AccessTokenRequestCSPost,
                                  AccessTokenResponse),
    "access-token-request":(AccessTokenRequest, AccessTokenResponse),
    "access-token-request_csj":(AccessTokenRequestCSJWT,
                                  AccessTokenResponse),
    "access-token-request_pkj":(AccessTokenRequestPKJWT,
                                AccessTokenResponse),
    "access-token-request_err" : (AccessTokenRequest_err, ErrorResponse),
    "check-id-request_gbh":(CheckIDRequestGetBearerHeader, CheckIdResponse),
    "check-id-request_pbh":(CheckIDRequestPostBearerHeader, CheckIdResponse),
    "check-id-request_pbb":(CheckIDRequestPostBearerBody, CheckIdResponse),
    "user-info-request":(UserInfoRequestGetBearerHeader, UserinfoResponse),
    "user-info-request_pbh":(UserInfoRequestPostBearerHeader, UserinfoResponse),
    "user-info-request_pbb":(UserInfoRequestPostBearerBody, UserinfoResponse),
    "user-info-request_err":(UserInfoRequestGetBearerHeader_err,
                             ErrorResponse),
    "oic-registration": (RegistrationRequest, RegistrationResponse),
    "oic-registration-wqc": (RegistrationRequest_WQC, RegistrationResponse),
    "oic-registration-wf": (RegistrationRequest_WF,
                            ClientRegistrationErrorResponse),
    "oic-registration-ke": (RegistrationRequest_KeyExp, RegistrationResponse),
    "provider-discovery": (Discover, ProviderConfigurationResponse),
    "oic-missing_response_type": (MissingResponseType, AuthzErrResponse)
}


FLOWS = {
    'oic-verify': {
        "name": 'Special flow used to find necessary user interactions',
        "descr": ('Request with response_type=code'),
        "sequence": ["verify"],
        "endpoints": ["authorization_endpoint"]
    },

    # -------------------------------------------------------------------------
    'oic-code-token': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['mj-01'],
        "sequence": ["oic-login", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+token-token': {
        "name": "",
        "descr": ("1) Request with response_type='code token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['mj-04'],
        "sequence": ["oic-login-code+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken-token': {
        "name": "",
        "descr": ("1) Request with response_type='code id_token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['mj-05'],
        "sequence": ["oic-login-code+idtoken", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken+token-token': {
        "name": "",
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['mj-07'],
        "sequence": ["oic-login-code+idtoken+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # -------------------------------------------------------------------------

    'oic-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type='token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['mj-02'],
        "sequence": ['oic-login-token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type='code token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['mj-04'],
        "sequence": ['oic-login-code+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken-token-userinfo': {
        "name": 'Implicit flow with Code+IDToken ',
        "descr": ("1) Request with response_type='code id_token'",
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
        "depends": ['mj-06'],
        "sequence": ['oic-login-idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-userinfo': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends":["mj-07"],
        "sequence": ['oic-login-code+idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-token-userinfo': {
        "name": """Get an accesstoken using access code with 'token' and
    'idtoken' in response type""",
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
        "depends": ['mj-06'],
        "sequence": ['oic-login-idtoken+token', "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
    },
    'oic-code+idtoken-check_id': {
        "name": '',
        "descr": ("1) Request with response_type='code id_token'",
                  "2) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends":["mj-05"],
        "sequence": ['oic-login-code+idtoken', "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": [("compare-idoken-received-with-check_id-response", {})]
    },
    'oic-code+idtoken+token-check_id': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends":["mj-07"],
        "sequence": ['oic-login-code+idtoken+token', "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": [("compare-idoken-received-with-check_id-response", {})]
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
        "depends": ['mj-02'],
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
        "tests":[("verify-error", {"error":"login_required"})]
        },
    'mj-29': {
        "name": 'Request with prompt=login',
        "sequence": ["oic-login+prompt_login", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # ---------------------------------------------------------------------
    'mj-30': {
        "name": 'Access token request with client_secret_basic authentication',
        "sequence": ["oic-login", "access-token-request_csp"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-31': {
        "name": 'Request with response_type=code and extra query component',
        "sequence": ["login-wqc"],
        "endpoints": ["authorization_endpoint"]
    },
    'mj-32': {
        "name": 'Request with redirect_uri with query component',
        "sequence": ["login-ruwqc"],
        "endpoints": ["authorization_endpoint"],
        "tests": [("verify-redirect_uri-query_component",
                {"redirect_uri":
                     PHASES["login-ruwqc"][0].request_args["redirect_uri"]})]
    },
    'mj-33': {
        "name": 'Registration where a redirect_uri has a query component',
        "sequence": ["oic-registration-wqc"],
        "endpoints": ["registration_endpoint"],
    },
    'mj-34': {
        "name": 'Registration where a redirect_uri has a fragment',
        "sequence": ["oic-registration-wf"],
        "endpoints": ["registration_endpoint"],
        },
    'mj-35': {
        "name": "Authorization request missing the 'response_type' parameter",
        "sequence": ["oic-missing_response_type"],
        "endpoints": ["authorization_endpoint"],
        "tests":[("verify-error", {"error":"invalid_request"})]
    },
    'mj-36': {
        "name": "The sent redirect_uri does not match the registered",
        "sequence": ["login-redirect-fault"],
        "endpoints": ["authorization_endpoint"]
    },
    'mj-37': {
        "name": 'Access token request with client_secret_jwt authentication',
        "sequence": ["oic-registration-ke", "oic-login",
                     "access-token-request_csj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-38': {
        "name": 'Access token request with public_key_jwt authentication',
        "sequence": ["oic-registration-ke", "oic-login",
                     "access-token-request_pkj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-39': {
        "name": 'Trying to use access code twice should result in an error',
        "sequence": ["oic-login", "access-token-request",
                     "access-token-request_err"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "tests": [("verify-bad-request-response", {})],
        "depends":["oic-code-token"],
    },
    'mj-40': {
        "name": 'Trying to use access code twice should result in '
                'revoking previous issued tokens',
        "sequence": ["oic-login", "access-token-request",
                     "access-token-request_err", "user-info-request_err"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-bad-request-response", {})],
        "depends":["mj-39"],
    },
}

NEW = {
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