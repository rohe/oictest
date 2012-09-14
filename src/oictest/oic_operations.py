#!/usr/bin/env python
from urllib import urlencode, quote
from oic.oauth2.message import AuthorizationRequest
from oic import jwt
from oic.oic import message
from oic.utils.keystore import proper_path

__author__ = 'rohe0002'

# ========================================================================

import time
import socket
from urlparse import urlparse

from oic.oic.message import factory as msgfactory, OpenIDRequest
from oictest.check import *
# Used upstream not in this module so don't remove
from oictest.opfunc import *

# ========================================================================

LOCAL_PATH = "export/"

def _get_base(cconf=None):
    part = urlparse(cconf["_base_url"])

    if part.path:
        if part.path == "/":
            _path = ""
        elif not part.path.endswith("/"):
            _path = part.path[:] + "/"
        else:
            _path = part.path[:]
    else:
        _path = ""

    return "%s://%s/%s" % (part.scheme, part.netloc, _path, )

def store_sector_redirect_uris(args, all=True, extra=False, cconf=None):
    _base = _get_base(cconf)

    if extra:
        args["redirect_uris"].append("%s/cb" % _base)

    sector_identifier_url = "%s%s%s" % (_base, LOCAL_PATH,"siu.json")
    f = open("%ssiu.json" % LOCAL_PATH, 'w')
    if all:
        f.write(json.dumps(args["redirect_uris"]))
    else:
        f.write(json.dumps(args["redirect_uris"][:-1]))
    f.close()
    args["sector_identifier_url"] = sector_identifier_url

#def do_sector_identifier_url(self, server_url_pattern, cconf):
#    _url = server_url_pattern % (self.args.host,)
#    part = urlparse.urlsplit(_url)
#
#    if part.path.endswith("/"):
#        _path = part.path[:-1]
#    else:
#        _path = part.path[:]
#
#    _export_filename = "%ssiu.json" % proper_path("%s/%s/" % (_path,
#                                                              KEY_EXPORT_ARGS["local_path"]))
#
#    f = open(_export_filename, "w")
#    f.write(json.dumps(cconf["redirect_uris"]))
#    f.close()
#
#    cconf["sector_identifier_url"] = "%s://%s%s" % (part.scheme, part.netloc,
#                                                    _export_filename[1:])

class Request():
    request = ""
    method = ""
    lax = False
    request_args= {}
    kw_args = {}
    tests = {"post": [CheckHTTPResponse], "pre":[]}

    def __init__(self, cconf=None):
        self.cconf = cconf

    #noinspection PyUnusedLocal
    def __call__(self, environ, trace, location, response, content, features):
        _client = environ["client"]
        if isinstance(self.request, basestring):
            request = msgfactory(self.request)
        else:
            request = self.request

        try:
            kwargs = self.kw_args.copy()
        except KeyError:
            kwargs = {}

        try:
            kwargs["request_args"] = self.request_args.copy()
            _req = kwargs["request_args"].copy()
        except KeyError:
            _req = {}

        if request in [OpenIDRequest, AuthorizationRequest]:
            if "use_nonce" in features and features["use_nonce"]:
                if not "nonce" in kwargs:
                    _nonce = "dummy_nonce"
                    try:
                        kwargs["request_args"]["nonce"] = _nonce
                    except KeyError:
                        kwargs["request_args"] = {"nonce": _nonce}

                    _client.nonce = _nonce

        cis = getattr(_client, "construct_%s" % request.__name__)(request,
                                                                  **kwargs)
        # Remove parameters with None value
        for key, val in cis.items():
            if val == None:
                del cis[key]

        environ[request.__name__] = cis
        try:
            cis.lax = self.lax
        except AttributeError:
            pass

        ht_add = None

        if "authn_method" in kwargs:
            h_arg = _client.init_authentication_method(cis, **kwargs)
        else:
            h_arg = None

        url, body, ht_args, cis = _client.uri_and_body(request, cis,
                                                      method=self.method,
                                                      request_args=_req)

        environ["cis"].append(cis)
        if h_arg:
            ht_args.update(h_arg)
        if ht_add:
            ht_args.update({"headers": ht_add})

        if trace:
            try:
                oro = jwt.unpack(cis["request"])[1]
                trace.request("OpenID Request Object: %s" % oro)
            except KeyError:
                pass
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
            trace.reply("COOKIES: %s" % response.cookies)
#            try:
#                trace.reply("HeaderCookies: %s" % response.headers["set-cookie"])
#            except KeyError:
#                pass

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
    request_args = {"response_type": [], "scope": ["openid"]}
    lax = True
    tests = {"post": [CheckRedirectErrorResponse]}

class AuthorizationRequestCode(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"], "scope": ["openid"]}

class AuthorizationRequestCode_WQC(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"], "scope": ["openid"],
                   "query": "component"}
    tests = {"pre": [CheckResponseType],
             "post": [CheckHTTPResponse]}

class AuthorizationRequestCode_RUWQC(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"], "scope": ["openid"]}
    tests = {"pre": [CheckResponseType],
             "post": [CheckHTTPResponse]}

    def __call__(self, environ, trace, location, response, content, features):
        _client = environ["client"]
        base_url = _client.redirect_uris[0]
        self.request_args["redirect_uri"] = quote("%s?%s" % (base_url,
                                                       urlencode({"fox":"bat"})))
        return Request.__call__(self, environ, trace, location, response,
                                content, features)

class AuthorizationRequestCode_RUWQC_Err(AuthorizationRequestCode_RUWQC):
    def __init__(self, cconf):
        AuthorizationRequestCode_RUWQC.__init__(self, cconf)
        self.tests["post"] = [CheckErrorResponse]

class AuthorizationRequest_Mismatching_Redirect_uri(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"], "scope": ["openid"],
                   "redirect_uri": "https://foo.example.se/authz_cb"}
    tests = {"pre": [CheckResponseType],
             "post": [CheckErrorResponse]}

class AuthorizationRequest_No_Redirect_uri(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"],
                   "redirect_uri": None, "scope": ["openid"]}
    tests = {"pre": [CheckResponseType],
             "post": []}

class AuthorizationRequest_with_nonce(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["code"], "scope": ["openid"],
                   "nonce": "12nonce34"}

class AuthorizationRequest_without_nonce(GetRequest):
    request = "AuthorizationRequest"
    request_args= {"response_type": ["token"], "scope": ["openid"],
                   "nonce": None}

class OpenIDRequestCode(GetRequest):
    request = "OpenIDRequest"
    request_args = {"response_type": ["code"], "scope": ["openid"]}
    tests = {"pre": [CheckResponseType],"post": [CheckHTTPResponse]}

class OpenIDRequestCodeRequestInFile(OpenIDRequestCode):
    kw_args = {"request_method": "file", "local_dir": "export"}

    def __init__(self, cconf):
        self.kw_args["base_path"] = _get_base(cconf) + "export/"

class ConnectionVerify(GetRequest):
    request = "OpenIDRequest"
    request_args = {"response_type": ["code"],
                    "scope": ["openid"]}
    tests = {"pre": [CheckResponseType],"post": [CheckHTTPResponse]}
    interaction_check = True

class OpenIDRequestCodeWithNonce(GetRequest):
    request = "OpenIDRequest"
    request_args = {"response_type": ["code"], "scope": ["openid"],
                    "nonce": "12nonce34"}
    tests = {"pre": [CheckResponseType],"post": [CheckHTTPResponse]}

class OpenIDRequestCodeDisplayPage(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["display"] = "page"

class OpenIDRequestCodeDisplayPopUp(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["display"] = "popup"

class OpenIDRequestCodePromptNone(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["prompt"] = "none"
        self.tests["post"] = [VerifyErrResponse]

class OpenIDRequestCodePromptNoneWithIdToken(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["prompt"] = "none"
        self.tests["post"].append(VerifyErrResponse)

    def __call__(self, environ, trace, location, response, content, features):
        idt = None
        for (cls, msg) in environ["responses"]:
            if cls == message.AccessTokenResponse:
                idt = json.loads(msg)["id_token"]
                break

        self.request_args["id_token"] = idt

        return OpenIDRequestCode.__call__(self, environ, trace, location,
                                          response, content, features)

class OpenIDRequestCodePromptNoneWithUserID(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["prompt"] = "none"
        self.tests["post"].append(VerifyErrResponse)

    def __call__(self, environ, trace, location, response, content, features):
        idt = None
        for (cls, msg) in environ["responses"]:
            if cls == message.AccessTokenResponse:
                idt = json.loads(msg)["id_token"]
                break

        jso = json.loads(jwt.unpack(idt)[1])
        user_id = jso["user_id"]
        self.request_args["idtoken_claims"] = {"claims": {"user_id": {
                                                            "value": user_id}}}

        return OpenIDRequestCode.__call__(self, environ, trace, location,
                                          response, content, features)

class OpenIDRequestCodePromptLogin(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["prompt"] = "login"


class OpenIDRequestCodeScopeProfile(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["scope"].append("profile")
        self.tests["pre"].append(CheckScopeSupport)

class OpenIDRequestCodeScopeEMail(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["scope"].append("email")
        self.tests["pre"].append(CheckScopeSupport)

class OpenIDRequestCodeScopeAddress(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["scope"].append("address")
        self.tests["pre"].append(CheckScopeSupport)

class OpenIDRequestCodeScopePhone(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["scope"].append("phone")
        self.tests["pre"].append(CheckScopeSupport)

class OpenIDRequestCodeScopeAll(OpenIDRequestCode):
    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["scope"].extend(["phone", "address", "email",
                                           "profile"])
        self.tests["pre"].append(CheckScopeSupport)

class OpenIDRequestCodeUIClaim1(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["userinfo_claims"] = {"claims": {"name": {"essential": True}}}


class OpenIDRequestCodeUIClaim2(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        # Picture and email optional
        self.request_args["userinfo_claims"] = {"claims": {"picture": None,
                                                           "email": None}}

class OpenIDRequestCodeUIClaim3(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        # Must name, may picture and email
        self.request_args["userinfo_claims"] = {"claims": {
                                                "name": {"essential": True},
                                                "picture": None,
                                                "email": None}}

class OpenIDRequestCodeUICombiningClaims(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        # Must name, may picture and email
        self.request_args["userinfo_claims"] = {"claims": {
            "name": {"essential": True},
            "picture": None,
            "email": None}}
        self.request_args["scope"].append("address")

class OpenIDRequestCodeIDTClaim1(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        # Must auth_time
        self.request_args["idtoken_claims"] = {"claims": {
                                                "auth_time": {"essential": True}}}

class OpenIDRequestCodeIDTClaim2(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["idtoken_claims"] = {"claims": {"acr": {"values":
                                                                      ["2"]}}}
        self.tests["pre"].append(CheckAcrSupport)

class OpenIDRequestCodeIDTClaim3(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        # Must acr
        self.request_args["idtoken_claims"] = {"claims": {
                                                    "acr": {"essential": True}}}

class OpenIDRequestCodeIDTClaim4(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        # Must acr
        self.request_args["idtoken_claims"] = {"claims": {"acr": None }}

class OpenIDRequestCodeIDTMaxAge1(OpenIDRequestCode):

    def __init__(self, cconf):
        time.sleep(2)
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["idtoken_claims"] = {"max_age": 1}

class OpenIDRequestCodeIDTMaxAge10(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["idtoken_claims"] = {"max_age": 10}

class OpenIDRequestCodeIDTEmail(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["idtoken_claims"] = {"claims": {
                                                    "email":{"essential":True}}}

class OpenIDRequestToken(GetRequest):
    request = "OpenIDRequest"
    request_args = {"response_type": ["token"], "scope": ["openid"]}
    tests = {"pre": [CheckResponseType, CheckScopeSupport],
             "post": [CheckHTTPResponse]}

class OpenIDRequestIDToken(GetRequest):
    request = "OpenIDRequest"
    request_args = {"response_type": ["id_token"], "scope": ["openid"]}
    tests = {"pre": [CheckResponseType, CheckScopeSupport],
             "post": [CheckHTTPResponse]}

class OpenIDRequestCodeToken(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["response_type"].append("token")

class OpenIDRequestCodeIDToken(OpenIDRequestCode):

    def __init__(self, cconf):
        OpenIDRequestCode.__init__(self, cconf)
        self.request_args["response_type"].append("id_token")

class OpenIDRequestIDTokenToken(OpenIDRequestIDToken):

    def __init__(self, cconf):
        OpenIDRequestIDToken.__init__(self, cconf)
        self.request_args["response_type"].append("token")

class OpenIDRequestCodeIDTokenToken(OpenIDRequestCodeIDToken):

    def __init__(self, cconf):
        OpenIDRequestCodeIDToken.__init__(self, cconf)
        self.request_args["response_type"].append("token")

class PostRequest(Request):
    method = "POST"

# =============================================================================

class RegistrationRequest(PostRequest):
    request = "RegistrationRequest"

    def __init__(self, cconf):
        PostRequest.__init__(self, cconf)

        for arg in message.RegistrationRequest().parameters():
            if arg in cconf:
                self.request_args[arg] = cconf[arg]

        try:
            del self.request_args["key_export_url"]
        except KeyError:
            pass

        # default
        self.request_args["type"] = "client_associate"
        # verify the registration info
        self.tests["post"].append(RegistrationInfo)

class RegistrationRequest_MULREDIR(RegistrationRequest):
    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)
        self.request_args["redirect_uris"].append("%s/cb" % _get_base(cconf))

class RegistrationRequest_MULREDIR_mult_host(RegistrationRequest):
    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)
        self.request_args["redirect_uris"].append("https://example.org/cb")

class RegistrationRequest_WQC(RegistrationRequest):
    """ With query component """

    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)

        ru = self.request_args["redirect_uris"][0]
        if "?" in ru:
            ru += "&foo=bar"
        else:
            ru += "?foo=bar"
        self.request_args["redirect_uris"][0] = ru

from oictest import start_key_server

class RegistrationRequest_WF(RegistrationRequest):
    """ With fragment, which is not allowed """
    tests = {"post": [CheckErrorResponse]}

    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)

        ru = self.request_args["redirect_uris"][0]
        ru += "#fragment"
        self.request_args["redirect_uris"][0] = ru

from oictest import KEY_EXPORT_ARGS

class RegistrationRequest_KeyExp(RegistrationRequest):
    """ Registration request with client key export """
    request = "RegistrationRequest"

    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)
        #self.export_server = "http://%s:8090/export" % socket.gethostname()

    def __call__(self, environ, trace, location, response, content, features):

        _client = environ["client"]
        # Do the redirect_uris dynamically
        self.request_args["redirect_uris"] = _client.redirect_uris

        for name, url in res.items():
            self.request_args[name] = url

        if "keyprovider" not in environ:
            pat = self.cconf["key_export_url"]
            p = pat.split("%s")
            str = self.cconf["jwk_url"]
            tmp = str[len(p[0]):]
            self.export_server = tmp[:tmp.index(p[1])]
            part, res = _client.keystore.key_export(self.export_server,
                                                    **KEY_EXPORT_ARGS)
            _pop = start_key_server(part)
            environ["keyprovider"] = _pop
            trace.info("Started key provider")
            time.sleep(1)

        return PostRequest.__call__(self, environ, trace, location, response,
                              content, features)

class RegistrationRequest_update(RegistrationRequest):
    """ With query component """

    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)

        self.request_args = {"type": "client_update",
                             "contacts": ["roland@example.com",
                                         "roland@example.org"]}

    def __call__(self, environ, trace, location, response, content, features):
        _client = environ["client"]

        self.request_args["client_secret"] = _client.get_client_secret()
        self.request_args["client_id"] = _client.client_id

        return PostRequest.__call__(self, environ, trace, location, response,
                                    content, features)

class RegistrationRequest_update_user_id(RegistrationRequest):
    """ With query component """

    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)

        self.request_args = {"type": "client_update",
                             "user_id_type": "pairwise"}

    def __call__(self, environ, trace, location, response, content, features):
        _client = environ["client"]

        self.request_args["client_secret"] = _client.get_client_secret()
        self.request_args["client_id"] = _client.client_id

        return PostRequest.__call__(self, environ, trace, location, response,
                                    content, features)

class RegistrationRequest_rotate_secret(RegistrationRequest):
    """ With query component """

    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)

        self.request_args = {"type": "rotate_secret"}

    def __call__(self, environ, trace, location, response, content, features):
        _client = environ["client"]

        self.request_args["client_secret"] = _client.get_client_secret()
        self.request_args["client_id"] = _client.client_id

        return PostRequest.__call__(self, environ, trace, location, response,
                                    content, features)

class RegistrationRequest_with_policy_and_logo(RegistrationRequest):

    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)

        ruri = self.request_args["redirect_uris"][0]
        p = urlparse(ruri)

        self.request_args["policy_url"] = "%s://%s/%s" % (p.scheme, p.netloc,
                                                          "policy.html")
        self.request_args["logo_url"] = "%s://%s/%s" % (p.scheme, p.netloc,
                                                        "logo.png")

class RegistrationRequest_with_public_userid(RegistrationRequest):
    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)
        self.request_args["user_id_type"] = "public"
        self.tests["pre"].append(CheckUserIdSupport)

class RegistrationRequest_with_userinfo_signed(RegistrationRequest):
    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)
        self.request_args["userinfo_signed_response_alg"] = "RS256"
        self.tests["pre"].append(CheckSignedUserInfoSupport)

class RegistrationRequest_with_pairwise_userid(RegistrationRequest):
    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)
        self.request_args["user_id_type"] = "pairwise"
        self.tests["pre"].append(CheckUserIdSupport)
        store_sector_redirect_uris(self.request_args, cconf=cconf)

class RegistrationRequest_SectorID(RegistrationRequest):
    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)
        store_sector_redirect_uris(self.request_args, cconf=cconf)

class RegistrationRequest_SectorID_Err(RegistrationRequest):
    """Sector Identifier Not Containing Registered redirect_uri Values"""

    def __init__(self, cconf):
        RegistrationRequest.__init__(self, cconf)
        store_sector_redirect_uris(self.request_args, False, True, cconf=cconf)
        self.tests["post"] = [CheckErrorResponse]

# =============================================================================

class AccessTokenRequest(PostRequest):
    request = "AccessTokenRequest"

    def __init__(self, cconf):
        PostRequest.__init__(self, cconf)
        #self.kw_args = {"authn_method": "client_secret_basic"}

    def __call__(self, environ, trace, location, response, content, features):
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
                              content, features)


class AccessTokenRequestCSPost(AccessTokenRequest):

    def __init__(self, cconf):
        AccessTokenRequest.__init__(self, cconf)
        self.kw_args = {"authn_method": "client_secret_post"}

class AccessTokenRequestCSJWT(AccessTokenRequest):
    tests = {"pre": [CheckKeys]}

    def __init__(self, cconf):
        PostRequest.__init__(self, cconf)
        self.kw_args = {"authn_method": "client_secret_jwt"}

class AccessTokenRequestPKJWT(AccessTokenRequest):
    tests = {"pre": [CheckKeys]}

    def __init__(self, cconf):
        PostRequest.__init__(self, cconf)
        self.kw_args = {"authn_method": "private_key_jwt"}

class AccessTokenRequest_err(AccessTokenRequest):

    def __init__(self, cconf):
        PostRequest.__init__(self, cconf)
        self.tests["post"]=[]

class UserInfoRequestGetBearerHeader(GetRequest):
    request = "UserInfoRequest"

    def __init__(self, cconf):
        self.request_args = {"schema": "openid"}
        GetRequest.__init__(self, cconf)
        self.kw_args = {"authn_method": "bearer_header"}

class UserInfoRequestGetBearerHeader_err(GetRequest):
    request = "UserInfoRequest"

    def __init__(self, cconf):
        self.request_args = {"schema": "openid"}
        GetRequest.__init__(self, cconf)
        self.kw_args = {"authn_method": "bearer_header"}
        self.tests["post"]=[CheckErrorResponse]

class UserInfoRequestPostBearerHeader(PostRequest):
    request = "UserInfoRequest"

    def __init__(self, cconf):
        self.request_args = {"schema": "openid"}
        PostRequest.__init__(self, cconf)
        self.kw_args = {"authn_method": "bearer_header"}

class UserInfoRequestPostBearerBody(PostRequest):
    request = "UserInfoRequest"

    def __init__(self, cconf):
        self.request_args = {"schema": "openid"}
        PostRequest.__init__(self, cconf)
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

class RegistrationResponseCARS(BodyResponse):
    response = "RegistrationResponseCARS"

    def __call__(self, environ, response):
        _client = environ["client"]
        _client.keystore.remove_key_type("hmac")
        for prop in ["client_id", "client_secret"]:
            try:
                setattr(_client, prop, response[prop])
            except KeyError:
                pass

class RegistrationResponseCU(BodyResponse):
    response = "RegistrationResponseCU"

    def __call__(self, environ, response):
        _client = environ["client"]
        for prop in ["client_id"]:
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
def discover(self, client, orig_response, content, issuer, location,
             features, _trace_):
    pcr = client.provider_config(issuer)
    _trace_.info("%s" % client.keystore._store)
    client.match_preferences(pcr)
    return "", DResponse(status=200, type="application/json"), pcr


class Discover(Operation):
    tests = {"post": [ProviderConfigurationInfo]}
    function = discover
    environ_param = "provider_info"
    request = None

    def __init__(self, **kwargs):
        Operation.__init__(self)
        self.request = "DiscoveryRequest"

    def post_op(self, result, environ, args):
        # Update the environ with the provider information
        # This overwrites what's there before. In some cases this might not
        # be preferable.

        environ[self.environ_param].update(result[2].to_dict())

# ===========================================================================

PHASES= {
    "login": (AuthorizationRequestCode, AuthzResponse),
    #"login-nonce": (AuthorizationRequest_with_nonce, AuthzResponse),
    "login-wqc": (AuthorizationRequestCode_WQC, AuthzResponse),
    "login-ruwqc": (AuthorizationRequestCode_RUWQC, AuthzResponse),
    "login-ruwqc-err": (AuthorizationRequestCode_RUWQC_Err, AuthzErrResponse),
    "login-redirect-fault": (AuthorizationRequest_Mismatching_Redirect_uri,
                             AuthorizationErrorResponse),
    "oic-login-no-nonce": (AuthorizationRequest_without_nonce,
                             AuthorizationErrorResponse),
#    "login-no-redirect-err": (AuthorizationRequest_No_Redirect_uri,
#                             AuthorizationErrorResponse),
    "verify": (ConnectionVerify, AuthzResponse),
    "oic-login": (OpenIDRequestCode, AuthzResponse),
    "oic-login-reqfile": (OpenIDRequestCodeRequestInFile, AuthzResponse),
    #"oic-login-nonce": (OpenIDRequestCodeWithNonce, AuthzResponse),
    "oic-login+profile": (OpenIDRequestCodeScopeProfile, AuthzResponse),
    "oic-login+email": (OpenIDRequestCodeScopeEMail, AuthzResponse),
    "oic-login+phone": (OpenIDRequestCodeScopePhone, AuthzResponse),
    "oic-login+address": (OpenIDRequestCodeScopeAddress, AuthzResponse),
    "oic-login+all": (OpenIDRequestCodeScopeAll, AuthzResponse),
    "oic-login+spec1": (OpenIDRequestCodeUIClaim1, AuthzResponse),
    "oic-login+spec2": (OpenIDRequestCodeUIClaim2, AuthzResponse),
    "oic-login+spec3": (OpenIDRequestCodeUIClaim3, AuthzResponse),
    "oic-login-combine_claims": (OpenIDRequestCodeUICombiningClaims,
                                 AuthzResponse),
    "oic-login+idtc1": (OpenIDRequestCodeIDTClaim1, AuthzResponse),
    "oic-login+idtc2": (OpenIDRequestCodeIDTClaim2, AuthzResponse),
    "oic-login+idtc3": (OpenIDRequestCodeIDTClaim3, AuthzResponse),
    "oic-login+idtc6": (OpenIDRequestCodeIDTClaim4, AuthzResponse),
    "oic-login+idtc4": (OpenIDRequestCodeIDTMaxAge1, AuthzResponse),
    "oic-login+idtc5": (OpenIDRequestCodeIDTMaxAge10, AuthzResponse),
    "oic-login+idtc7": (OpenIDRequestCodeIDTEmail, AuthzResponse),

    "oic-login+disp_page": (OpenIDRequestCodeDisplayPage, AuthzResponse),
    "oic-login+disp_popup": (OpenIDRequestCodeDisplayPopUp, AuthzResponse),

    "oic-login+prompt_none": (OpenIDRequestCodePromptNone, AuthzErrResponse),
    "oic-login+prompt_login": (OpenIDRequestCodePromptLogin, AuthzResponse),
    "oic-login+prompt_none+idtoken": (OpenIDRequestCodePromptNoneWithIdToken,
                                      AuthzErrResponse),
    "oic-login+prompt_none+request":(OpenIDRequestCodePromptNoneWithUserID,
                                     AuthzErrResponse),

    "oic-login-token": (OpenIDRequestToken, AuthzResponse),
    "oic-login-idtoken": (OpenIDRequestIDToken, AuthzResponse),
    "oic-login-code+token": (OpenIDRequestCodeToken, AuthzResponse),
    "oic-login-code+idtoken": (OpenIDRequestCodeIDToken, AuthzResponse),
    "oic-login-idtoken+token": (OpenIDRequestIDTokenToken, AuthzResponse),
    "oic-login-code+idtoken+token": (OpenIDRequestCodeIDTokenToken,
                                     AuthzResponse),

    "oic-login-no-redirect": (AuthorizationRequest_No_Redirect_uri,
                              AuthzResponse),
    "oic-login-no-redirect-err": (AuthorizationRequest_No_Redirect_uri,
                              AuthzErrResponse),
    #
    "access-token-request_csp":(AccessTokenRequestCSPost,
                                  AccessTokenResponse),
    "access-token-request":(AccessTokenRequest, AccessTokenResponse),
    "access-token-request_csj":(AccessTokenRequestCSJWT,
                                  AccessTokenResponse),
    "access-token-request_pkj":(AccessTokenRequestPKJWT,
                                AccessTokenResponse),
    "access-token-request_err" : (AccessTokenRequest_err, ErrorResponse),
    "user-info-request":(UserInfoRequestGetBearerHeader, UserinfoResponse),
    "user-info-request_pbh":(UserInfoRequestPostBearerHeader, UserinfoResponse),
    "user-info-request_pbb":(UserInfoRequestPostBearerBody, UserinfoResponse),
    "user-info-request_err":(UserInfoRequestGetBearerHeader_err,
                             ErrorResponse),
    "oic-registration": (RegistrationRequest, RegistrationResponseCARS),
    "oic-registration-multi-redirect": (RegistrationRequest_MULREDIR,
                                        RegistrationResponseCARS),
    "oic-registration-wqc": (RegistrationRequest_WQC, RegistrationResponseCARS),
    "oic-registration-wf": (RegistrationRequest_WF,
                            ClientRegistrationErrorResponse),
    "oic-registration-ke": (RegistrationRequest_KeyExp, RegistrationResponseCARS),
    "oic-registration-update": (RegistrationRequest_update,
                                RegistrationResponseCU),
    "oic-registration-rotate": (RegistrationRequest_rotate_secret,
                                RegistrationResponseCARS),
    "oic-registration-policy+logo": (RegistrationRequest_with_policy_and_logo,
                                     RegistrationResponseCARS),
    "oic-registration-public_id": (RegistrationRequest_with_public_userid,
                                   RegistrationResponseCARS),
    "oic-registration-pairwise_id": (RegistrationRequest_with_pairwise_userid,
                                     RegistrationResponseCARS),
    "oic-registration-sector_id": (RegistrationRequest_SectorID,
                                   RegistrationResponseCARS),
    "oic-registration-signed_userinfo": (RegistrationRequest_with_userinfo_signed,
                                   RegistrationResponseCARS),
    "oic-registration-sector_id-err": (RegistrationRequest_SectorID_Err,
                                       ClientRegistrationErrorResponse),
    "oic-change-user_id_type": (RegistrationRequest_update_user_id,
                                RegistrationResponseCU),
    "provider-discovery": (Discover, ProviderConfigurationResponse),
    "oic-missing_response_type": (MissingResponseType, AuthzErrResponse)
}

OWNER_OPS = []

FLOWS = {
    'oic-verify': {
        "name": 'Special flow used to find necessary user interactions',
        "descr": ('Request with response_type=code'),
        "sequence": ["verify"],
        "endpoints": ["authorization_endpoint"],
        "block": ["key_export"]
    },

    'oic-discovery': {
        "name": 'Provider configuration discovery',
        "descr": ('Exchange in which Client Discovers and Uses OP Information'),
        "sequence": [], # discovery will be auto-magically added
        "endpoints": [],
        "block": ["registration", "key_export"],
        "depends": ['oic-verify'],
        },

    # -------------------------------------------------------------------------
#    'oic-code+nonce-token': {
#        "name": 'Simple authorization grant flow',
#        "descr": ("1) Request with response_type=code",
#                  "scope = ['openid']",
#                  "2) AccessTokenRequest",
#                  "Authentication method used is 'client_secret_post'"),
#        "depends": ['mj-01'],
#        "sequence": ["oic-login-nonce", "access-token-request"],
#        "endpoints": ["authorization_endpoint", "token_endpoint"],
#        },
    'oic-code+token-token': {
        "name": "Flow with response_type='code token'",
        "descr": ("1) Request with response_type='code token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['mj-04'],
        "sequence": ["oic-login-code+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken-token': {
        "name": "Flow with response_type='code idtoken'",
        "descr": ("1) Request with response_type='code id_token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['mj-05'],
        "sequence": ["oic-login-code+idtoken", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken+token-token': {
        "name": "Flow with response_type='code token idtoken'",
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['mj-07'],
        "sequence": ["oic-login-code+idtoken+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # -------------------------------------------------------------------------

    'oic-token-userinfo': {
        "name": 'Implicit flow and Userinfo request',
        "descr": ("1) Request with response_type='token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['mj-02'],
        "sequence": ['oic-login-token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+token-userinfo': {
        "name": "Flow with response_type='code token' and Userinfo request",
        "descr": ("1) Request with response_type='code token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['mj-04'],
        "sequence": ['oic-login-code+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken-token-userinfo': {
        "name": "Flow with response_type='code idtoken' and Userinfo request",
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
        "name": "Flow with response_type='token idtoken' and Userinfo request",
        "descr": ("1) Request with response_type='id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['mj-06'],
        "sequence": ['oic-login-idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-userinfo': {
        "name": """Flow with response_type='code idtoken token' and Userinfo
    request""",
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends":["mj-07"],
        "sequence": ['oic-login-code+idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-token-userinfo': {
        "name": """Flow with response_type='code idtoken token'
    grab a second token using the code and then do a Userinfo
    request""",
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
    # beared body authentication
    'oic-code-token-userinfo_bb': {
        "name": """Authorization grant flow response_type='code token',
    UserInfo request using POST and bearer body authentication""",
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
        "name": """Implicit flow, UserInfo request using POST and bearer body
    authentication""",
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
        "endpoints": ["registration_endpoint"],
        "depends": ['oic-discovery'],
        },
    'mj-01': {
        "name": 'Request with response_type=code',
        "sequence": ["oic-login"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-00'],
    },
    'oic-code-token': {
        "name": 'Simple authorization grant flow',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['mj-01'],
        "sequence": ["oic-login", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },

    #    'mj-01n': {
#        "name": 'Request with response_type=code',
#        "sequence": ["oic-login-nonce"],
#        "endpoints": ["authorization_endpoint"]
#    },
    'mj-02': {
        "name": 'Request with response_type=token',
        "sequence": ["oic-login-token"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01']
        },
    'mj-03': {
        "name": 'Request with response_type=id_token',
        "sequence": ["oic-login-idtoken"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-04': {
        "name": 'Request with response_type=code token',
        "sequence": ["oic-login-code+token"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-05': {
        "name": 'Request with response_type=code id_token',
        "sequence": ['oic-login-code+idtoken'],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-06': {
        "name": 'Request with response_type=id_token token',
        "sequence": ['oic-login-idtoken+token'],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-07': {
        "name": 'Request with response_type=code id_token token',
        "sequence": ['oic-login-code+idtoken+token'],
        "endpoints": ["authorization_endpoint",],
        "depends": ['mj-01'],
        },
    # -------------------------------------------------------------------------
    'mj-11': {
        "name": 'UserInfo Endpoint Access with GET and bearer_header',
        "sequence": ["oic-login", "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-12': {
        "name": 'UserInfo Endpoint Access with POST and bearer_header',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_pbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-13': {
        "name": 'UserInfo Endpoint Access with POST and bearer_body',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    # -------------------------------------------------------------------------
    'mj-14': {
        "name": 'Scope Requesting profile Claims',
        "sequence": ["oic-login+profile", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-15': {
        "name": 'Scope Requesting email Claims',
        "sequence": ["oic-login+email", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-16': {
        "name": 'Scope Requesting address Claims',
        "sequence": ["oic-login+address", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-17': {
        "name": 'Scope Requesting phone Claims',
        "sequence": ["oic-login+phone", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-18': {
        "name": 'Scope Requesting all Claims',
        "sequence": ["oic-login+all", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-19': {
        "name": 'OpenID Request Object with Required name Claim',
        "sequence": ["oic-login+spec1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-20': {
        "name": 'OpenID Request Object with Optional email and picture Claim',
        "sequence": ["oic-login+spec2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-21': {
        "name": ('OpenID Request Object with Required name and Optional email and picture Claim'),
        "sequence": ["oic-login+spec3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-22': {
        "name": 'Requesting ID Token with auth_time Claim',
        "sequence": ["oic-login+idtc1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"claims":{"auth_time": None}})],
        "depends": ['mj-01'],
        },
    'mj-23': {
        "name": 'Requesting ID Token with Required specific acr Claim',
        "sequence": ["oic-login+idtc2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"claims":{"acr": {"values": ["2"]}}})],
        "depends": ['mj-01'],
        },
    'mj-24': {
        "name": 'Requesting ID Token with Optional acr Claim',
        "sequence": ["oic-login+idtc3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"claims":{"acr": "essential"}})],
        "depends": ['mj-01'],
        },
    'mj-25': {
        "name": 'Requesting ID Token with max_age=1 seconds Restriction',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request", "oic-login+idtc4",
                     "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("multiple-sign-on", {})],
        "depends": ['mj-01'],
        },
    # ---------------------------------------------------------------------
    'mj-26': {
        "name": 'Request with display=page',
        "sequence": ["oic-login+disp_page", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-27': {
        "name": 'Request with display=popup',
        "sequence": ["oic-login+disp_popup", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-28': {
        "name": 'Request with prompt=none',
        "sequence": ["oic-login+prompt_none"],
        "endpoints": ["authorization_endpoint"],
        "tests":[("verify-error", {"error":["login_required",
                                            "interaction_required",
                                            "session_selection_required",
                                            "consent_required"]})],
        "depends": ['mj-01'],
        },
    'mj-29': {
        "name": 'Request with prompt=login',
        "sequence": ["oic-login+prompt_login", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
        },
    # ---------------------------------------------------------------------
    'mj-30': {
        "name": 'Access token request with client_secret_basic authentication',
        "sequence": ["oic-login", "access-token-request_csp"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-31': {
        "name": 'Request with response_type=code and extra query component',
        "sequence": ["login-wqc"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-32': {
        "name": 'Request with redirect_uri with query component',
        "sequence": ["login-ruwqc"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01'],
        #"tests": [("verify-redirect_uri-query_component", {})]
                #{"redirect_uri":
                #     PHASES["login-ruwqc"][0].request_args["redirect_uri"]})]
    },
    'mj-33': {
        "name": 'Registration where a redirect_uri has a query component',
        "sequence": ["oic-registration-wqc"],
        "endpoints": ["registration_endpoint"],
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-3.1.2",
        "depends": ['mj-01'],
    },
    'mj-34': {
        "name": 'Registration where a redirect_uri has a fragment',
        "sequence": ["oic-registration-wf"],
        "endpoints": ["registration_endpoint"],
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-3.1.2",
        "depends": ['mj-01'],
    },
    'mj-35': {
        "name": "Authorization request missing the 'response_type' parameter",
        "sequence": ["oic-missing_response_type"],
        "endpoints": ["authorization_endpoint"],
        "tests":[("verify-error", {"error":["invalid_request"]})],
        "depends": ['mj-01'],
    },
    'mj-36': {
        "name": "The sent redirect_uri does not match the registered",
        "sequence": ["login-redirect-fault"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-37': {
        "name": 'Access token request with client_secret_jwt authentication',
        "sequence": ["oic-registration-ke", "oic-login",
                     "access-token-request_csj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-38': {
        "name": 'Access token request with public_key_jwt authentication',
        "sequence": ["oic-registration-ke", "oic-login",
                     "access-token-request_pkj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-39': {
        "name": 'Trying to use access code twice should result in an error',
        "sequence": ["oic-login", "access-token-request",
                     "access-token-request_err"],
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.1",
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "tests": [("verify-bad-request-response", {})],
        "depends":["oic-code-token"],
    },
    'mj-40': {
        "name": 'Trying to use access code twice should result in '
                'revoking previous issued tokens',
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.1",
        "sequence": ["oic-login", "access-token-request",
                     "access-token-request_err", "user-info-request_err"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-bad-request-response", {})],
        "depends":["mj-39"],
    },
    'mj-41': {
        "name": 'Registration and later registration update',
        "sequence": ["oic-registration", "oic-registration-update"],
        "endpoints": ["registration_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-42': {
        "name": 'Registration and later secret rotate',
        "sequence": ["oic-registration", "oic-registration-rotate"],
        "endpoints": ["registration_endpoint"],
        "tests": [("changed-client-secret", {})],
        "depends": ['mj-01'],
        },
    'mj-43': {
        "name": "No redirect_uri in request, one registered",
        "sequence": ["oic-registration", "oic-login-no-redirect"],
        "endpoints": ["registration_endpoint", "authorization_endpoint"],
        "depends": ["oic-code-token"]
    },
    'mj-44': {
        "name": "No redirect_uri in request, multi registered",
        "sequence": ["oic-registration-multi-redirect",
                     "oic-login-no-redirect-err"],
        "endpoints": ["registration_endpoint", "authorization_endpoint"],
        "depends": ["oic-code-token"],
        #"tests": [("verify-bad-request-response", {})],
    },
    'mj-45': {
        "name": 'Registration with policy_url and logo_url',
        "sequence": ["oic-registration-policy+logo", "oic-login"],
        "endpoints": ["registration_endpoint", "authorization_endpoint"],
        "tests": [("policy_url_on_page", {}),
                    ("logo_url_on_page", {})],
        "depends": ['mj-01'],
        },
    'mj-46': {
        "name": 'Registration of wish for public user_id',
        "sequence": ["oic-registration-public_id", "oic-login",
                     "access-token-request"],
        "endpoints": ["registration_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-47': {
        "name": 'Registration of sector-identifier-uri',
        "sequence": ["oic-registration-sector_id", "oic-login"],
        "endpoints": ["registration_endpoint"],
        "depends": ['mj-01'],
        },
    'mj-48': {
        "name": 'Incorrect registration of sector-identifier-uri',
        "sequence": ["oic-registration-sector_id-err"],
        "endpoints": ["registration_endpoint"],
        "depends": ['mj-47'],
        },
    'mj-49': {
        "name": 'Registration of wish for pairwise user_id',
        "sequence": ["oic-registration-pairwise_id", "oic-login",
                     "access-token-request", "user-info-request"],
        "endpoints": ["registration_endpoint", "authorization_endpoint",
                      "token_endpoint", "userinfo_endpoint"],
        "depends": ['mj-47'],
        },
    'mj-50': {
        "name": 'Verify change in user_id',
        "sequence": ["oic-registration-public_id", "oic-login",
                     "access-token-request", "user-info-request",
                     "oic-change-user_id_type", "oic-login+prompt_login",
                     "access-token-request", "user-info-request"],
        "endpoints": ["registration_endpoint"],
        "depends": ["mj-49"],
        "tests": [("different_user_id", {})]
        },
    'mj-51': {
        "name": 'Login no nonce',
        "sequence": ["oic-login-no-nonce"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-02']
    },
    'mj-52': {
        "name": 'Requesting ID Token with Email claims',
        "sequence": ["oic-login+idtc7", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "tests": [("verify-id-token", {})],
        "depends": ['mj-01'],
    },
#    "mj-53": {
#        "name": 'using prompt=none with user hint through IdToken',
#        "sequence": ["oic-login", "access-token-request",
#                     "oic-login+prompt_none+idtoken"],
#        "endpoints": ["registration_endpoint"],
#        "depends": ['mj-01'],
#        },
#    "mj-54": {
#        "name": 'using prompt=none with user hint through user_id in request',
#        "sequence": ["oic-login", "access-token-request",
#                     "oic-login+prompt_none+request"],
#        "endpoints": ["registration_endpoint"],
#        "depends": ['mj-01'],
#        },
    'mj-55': {
        "name": 'Rejects redirect_uri when Query Parameter Does Not Match',
        "sequence": ["oic-registration-wqc", "login-ruwqc-err"],
        "endpoints": ["registration_endpoint", "authorization_endpoint"],
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-3.1.2",
        "depends": ['mj-01'],
        },
    'mj-56': {
        "name": ('Supports Combining Claims Requested with scope and Request Object'),
        "sequence": ["oic-login-combine_claims", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-22'],
        "tests": [("verify-userinfo", {})]
        },
    'mj-57': {
        "name": 'Support Request File',
        "sequence": ["oic-login-reqfile"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-00'],
        },
    'mj-58': {
        "name": 'Requesting ID Token with Required acr Claim',
        "sequence": ["oic-login+idtc6", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        #"tests": [("verify-id-token", {"claims":{"acr": None}})],
        "depends": ['mj-01'],
        },
    'mj-59': {
        "name": 'Requesting ID Token with max_age=10 seconds Restriction',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request", "oic-login+idtc5",
                     "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("single-sign-on", {})],
        "depends": ['mj-25'],
        },
#    'mj-60': {
#        "name": "RP wants signed UserInfo returned",
#        "sequence": ["oic-registration-signed_userinfo", "oic-login",
#                     "access-token-request", "user-info-request"],
#        "endpoints": ["authorization_endpoint", "token_endpoint",
#                      "userinfo_endpoint"],
#        "tests": [("signed-userinfo", {})],
#        "depends": ['mj-01'],
#
#        }
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