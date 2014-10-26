#!/usr/bin/env python
import copy
from jwkest.jwk import SerializationNotPossible
from oic.exception import UnSupported
from oic.utils.keyio import KeyBundle
from oic.utils.keyio import dump_jwks
from oic.oauth2.message import SchemeError
from oic.utils.webfinger import OIC_ISSUER, WebFinger
from oic.utils.http_util import Response

import rrtest.request as req
from rrtest.request import BodyResponse
from rrtest.request import GetRequest
from rrtest.request import Request
from rrtest.request import UrlResponse
from rrtest.request import PostRequest
from rrtest.request import Process
from rrtest.check import VerifyBadRequestResponse
from rrtest.check import CheckErrorResponse

__author__ = 'rohe0002'

# ========================================================================

import time

from urllib import urlencode
from oic.oauth2 import JSON_ENCODED, PBase

# Used upstream not in this module so don't remove
from oictest.check import *
from rrtest.opfunc import *

# ========================================================================

LOCAL_PATH = "export/"


class MissingResponseClaim(Exception):
    pass


class NotSupported(Exception):
    pass


def _get_base(cconf=None):
    """
    Make sure a '/' terminated URL is returned
    """
    try:
        part = urlparse(cconf["_base_url"])
    except KeyError:
        part = urlparse(cconf["base_url"])
    #part = urlparse(cconf["redirect_uris"][0])

    if part.path:
        if not part.path.endswith("/"):
            _path = part.path[:] + "/"
        else:
            _path = part.path[:]
    else:
        _path = "/"

    return "%s://%s%s" % (part.scheme, part.netloc, _path, )

#noinspection PyUnusedLocal


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
        self.template = ""

    def __call__(self, lookup, environ, start_response, **kwargs):
        resp = Response(mako_template=self.template,
                        template_lookup=lookup,
                        headers=[])
        return resp(environ, start_response, **kwargs)


class ExpectError(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "expect_err.mako"


class RmCookie(Notice):
    def __init__(self):
        Notice.__init__(self)
        self.template = "rmcookie.mako"


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


class AuthorizationRequestToken(AuthorizationRequest):
    request = "AuthorizationRequest"
    _request_args = {"response_type": ["token"], "scope": ["openid"]}


class AuthorizationRequestIDToken(AuthorizationRequest):
    request = "AuthorizationRequest"
    _request_args = {"response_type": ["id_token"], "scope": ["openid"]}
    _tests = {"pre": [CheckResponseType, CheckScopeSupport, CheckEndpoint],
              "post": []}


class AuthorizationRequestCodeUri(AuthorizationRequestCode):
    pass
    # def __init__(self, conv=None):
    #     AuthorizationRequestCode.__init__(self, conv)
    #     self.tests["post"].extend([VerifyPolicyURLs, VerifyLogoURLs])


class AuthorizationRequestCode_WQC(AuthorizationRequestCode):
    def __init__(self, conv=None):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["query"] = "component"


class AuthorizationRequestCode_RUWQC(AuthorizationRequestCode):
    def __call__(self, location, response="", content="", features=None,
                 **kwargs):
        _client = self.conv.client
        base_url = _client.redirect_uris[0]
        self.request_args["redirect_uri"] = "%s?%s" % (
            base_url, urlencode({"fox": "bat"}))
        return Request.__call__(self, location, response, content, features,
                                **kwargs)


class AuthorizationRequestCode_RUWQC_Err(AuthorizationRequestCode_RUWQC):
    def __init__(self, conv):
        AuthorizationRequestCode_RUWQC.__init__(self, conv)
        self.tests["post"] = [CheckErrorResponse]


class AuthorizationRequest_Mismatching_Redirect_uri(AuthorizationRequestCode):
    def __init__(self, conv=None):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["redirect_uri"] = "https://foo.example.se/authz_cb"
        self.tests["post"] = [CheckErrorResponse]


class AuthorizationRequest_No_Redirect_uri(AuthorizationRequestCode):
    def __init__(self, conv=None):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["redirect_uri"] = None
        self.tests["post"] = [VerifyBadRequestResponse]


class AuthorizationRequestCodeWithNonce(AuthorizationRequestCode):
    def __init__(self, conv=None):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["nonce"] = "12nonce34"


class AuthorizationRequest_without_nonce(AuthorizationRequestToken):
    def __init__(self, conv=None):
        AuthorizationRequestToken.__init__(self, conv)
        self.request_args["nonce"] = None
        self.tests["post"] = [VerifyBadRequestResponse]


class AuthorizationRequestCodeRequestInFile(AuthorizationRequestCode):
    _kw_args = {"request_method": "file", "local_dir": "export"}

    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.kw_args["base_path"] = _get_base(conv.client_config) + "export/"


class ConnectionVerify(GetRequest):
    request = "AuthorizationRequest"
    _request_args = {"response_type": ["code"], "scope": ["openid"]}
    _tests = {"pre": [CheckResponseType, CheckEndpoint],
              "post": []}
    interaction_check = True


class AuthorizationRequestCodeDisplayPage(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["display"] = "page"


class AuthorizationRequestCodeDisplayPopUp(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["display"] = "popup"


class AuthorizationRequestCodePromptNone(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["prompt"] = "none"
        #self.tests["post"] = [VerifyErrorResponse]


class AuthorizationRequestCodePromptNoneWithIdToken(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["prompt"] = "none"
        # verify that the same sub is returned as present in the IdToken
        self.tests["post"] = [VerifyPromptNoneResponse]

    def __call__(self, location, response="", content="", features=None,
                 **kwargs):
        return AuthorizationRequestCode.__call__(self, location, response,
                                                 content, features, **kwargs)

    def call_setup(self):
        idt = response_claim(self.conv, message.AccessTokenResponse, "id_token")
        self.request_args["id_token"] = idt


class AuthorizationRequestCodePromptNoneWithUserID(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["prompt"] = "none"
        self.tests["post"] = [VerifyPromptNoneResponse]

    def call_setup(self):
        idt = response_claim(self.conv, message.AccessTokenResponse, "id_token")
        if not idt:
            raise MissingResponseClaim("id_token in access token response")

        jso = json.loads(unpack(idt)[1])
        user_id = jso["sub"]
        self.request_args["claims"] = {"id_token": {"sub": {"value": user_id}}}

    def __call__(self, location, response="", content="", features=None,
                 **kwargs):
        return AuthorizationRequestCode.__call__(self, location, response,
                                                 content, features, **kwargs)


class AuthorizationRequestCodeWithUserID(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)

    def call_setup(self):
        idt = response_claim(self.conv, message.AccessTokenResponse, "id_token")
        if not idt:
            raise MissingResponseClaim("id_token in access token response")

        jso = json.loads(unpack(idt)[1])
        user_id = jso["sub"]
        self.request_args["claims"] = {"id_token": {"sub": {"value": user_id}}}

    def __call__(self, location, response="", content="", features=None,
                 **kwargs):
        return AuthorizationRequestCode.__call__(self, location, response,
                                                 content, features, **kwargs)


class AuthorizationRequestCodePromptLogin(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["prompt"] = "login"


class AuthorizationRequestCodeScopeProfile(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["scope"].append("profile")
        self.tests["pre"].append(CheckScopeSupport)


class AuthorizationRequestCodeScopeEMail(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["scope"].append("email")
        self.tests["pre"].append(CheckScopeSupport)


class AuthorizationRequestCodeScopeAddress(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["scope"].append("address")
        self.tests["pre"].append(CheckScopeSupport)


class AuthorizationRequestCodeScopePhone(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["scope"].append("phone")
        self.tests["pre"].append(CheckScopeSupport)


class AuthorizationRequestCodeScopeOfflineAccess(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["scope"].append("offline_access")
        self.request_args["prompt"] = "consent"
        self.tests["pre"].append(CheckScopeSupport)


class AuthorizationRequestCodeScopeAll(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["scope"].extend(["phone", "address", "email",
                                           "profile"])
        self.tests["pre"].append(CheckScopeSupport)


class AuthorizationRequestCodeUIClaim1(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_param = "request"
        self.request_args["claims"] = {
            "userinfo": {"name": {"essential": True}}}
        self.tests["pre"].append(CheckRequestParameterSupported)

class AuthorizationRequestCodeUIClaim2(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        # Picture and email optional
        self.request_param = "request"
        self.request_args["claims"] = {
            "userinfo": {"picture": None, "email": None}}


class AuthorizationRequestCodeUIClaim3(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        # Must name, may picture and email
        self.request_param = "request"
        self.request_args["claims"] = {
            "userinfo": {"name": {"essential": True},
                         "picture": None,
                         "email": None}}


class AuthorizationRequestCodeUICombiningClaims(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        # Must name, may picture and email
        self.request_param = "request"
        self.request_args["claims"] = {
            "userinfo": {"name": {"essential": True},
                         "picture": None,
                         "email": None}}
        self.request_args["scope"].append("address")


class AuthorizationRequestCodeIDTClaim1(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        # Must auth_time
        self.request_param = "request"
        self.request_args["claims"] = {
            "id_token": {"auth_time": {"essential": True}}}


class AuthorizationRequestCodeIDTClaim2(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_param = "request"
        self.request_args["claims"] = {"id_token": {"acr": {"values": ["2"]}}}
        self.tests["pre"].append(CheckAcrSupport)


class AuthorizationRequestCodeIDTClaim3(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        # Must acr
        self.request_param = "request"
        self.request_args["claims"] = {"id_token": {"acr": {"essential": True}}}


class AuthorizationRequestCodeIDTClaim4(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        # Must acr
        self.request_param = "request"
        self.request_args["claims"] = {"id_token": {"acr": None}}


class AuthorizationRequestCodeIDTClaimX(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        # Must acr
        self.request_args["claims"] = {
            "id_token": {"auth_time": {"essential": True}}}


class AuthorizationRequestCodeIDTMaxAge1(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["max_age"] = 1


class AuthorizationRequestCodeIDTMaxAge10(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["max_age"] = 10


class AuthorizationRequestLocale(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["ui_locales"] = ["se"]


class AuthorizationRequestLoginHit(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["login-hint"] = conv.login_hint


class AuthorizationRequestCodeIDTEmail(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["claims"] = {
            "id_token": {"email": {"essential": True}}}


class AuthorizationRequestCodeMixedClaims(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["claims"] = {
            "id_token": {"email": {"essential": True}},
            "userinfo": {"name": {"essential": True}}}


class AuthorizationRequestCodeToken(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["response_type"].append("token")


class AuthorizationRequestCodeIDToken(AuthorizationRequestCode):
    def __init__(self, conv):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["response_type"].append("id_token")


class AuthorizationRequestIDTokenToken(AuthorizationRequestIDToken):
    def __init__(self, conv):
        AuthorizationRequestIDToken.__init__(self, conv)
        self.request_args["response_type"].append("token")


class AuthorizationRequestCodeIDTokenToken(AuthorizationRequestCodeIDToken):
    def __init__(self, conv):
        AuthorizationRequestCodeIDToken.__init__(self, conv)
        self.request_args["response_type"].append("token")


class AuthorizationRequestCodeResponseModeFormPost(AuthorizationRequestCode):
    def __init__(self, conv=None):
        AuthorizationRequestCode.__init__(self, conv)
        self.request_args["response_mode"] = "form_post"

# =============================================================================


class RegistrationRequest(PostRequest):
    request = "RegistrationRequest"
    content_type = JSON_ENCODED
    _request_args = {}

    def __init__(self, conv):
        PostRequest.__init__(self, conv)

        for arg in message.RegistrationRequest().parameters():
            try:
                val = conv.client_config["provider_info"][arg]
            except KeyError:
                try:
                    val = conv.client_config["preferences"][arg]
                except KeyError:
                    try:
                        val = conv.client_config["client_info"][arg]
                    except KeyError:
                        try:
                            val = conv.client_config["client_registration"][arg]
                        except KeyError:
                            continue
            self.request_args[arg] = copy.copy(val)
        try:
            del self.request_args["key_export_url"]
        except KeyError:
            pass

        # verify the registration info
        self.tests["post"].append(RegistrationInfo)


class RegistrationRequest_MULREDIR(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["redirect_uris"].append(
            "%scb" % _get_base(conv.client_config))


class RegistrationRequest_MULREDIR_mult_host(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["redirect_uris"].append("https://example.org/cb")


class RegistrationRequest_WQC(RegistrationRequest):
    """ With query component """

    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)

        ru = self.request_args["redirect_uris"][0]
        if "?" in ru:
            ru += "&foo=bar"
        else:
            ru += "?foo=bar"
        self.request_args["redirect_uris"][0] = ru


class RegistrationRequest_WF(RegistrationRequest):
    """ With fragment, which is not allowed """
    _tests = {"post": [CheckErrorResponse]}

    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)

        ru = self.request_args["redirect_uris"][0]
        ru += "#fragment"
        self.request_args["redirect_uris"][0] = ru


class RegistrationRequest_KeyExpCSJ(RegistrationRequest):
    """ Registration request with client key export """
    request = "RegistrationRequest"

    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["token_endpoint_auth_method"] = "client_secret_jwt"
        conv.client.behaviour["token_endpoint_auth_method"] = "client_secret_jwt"
        self.tests["pre"].append(CheckTokenEndpointAuthMethod)
        #self.export_server = "http://%s:8090/export" % socket.gethostname()

    def __call__(self, location, response="", content="", features=None,
                 **kwargs):
        _client = self.conv.client
        # Do the redirect_uris dynamically
        self.request_args["redirect_uris"] = _client.redirect_uris

        return PostRequest.__call__(self, location, response,
                                    content, features, **kwargs)


class RegistrationRequest_KeyExpCSP(RegistrationRequest):
    """ Registration request with client key export """
    request = "RegistrationRequest"

    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["token_endpoint_auth_method"] = "client_secret_post"
        conv.client.behaviour["token_endpoint_auth_method"] = "client_secret_post"
        self.tests["pre"].append(CheckTokenEndpointAuthMethod)
        #self.export_server = "http://%s:8090/export" % socket.gethostname()

    def __call__(self, location, response="", content="", features=None,
                 **kwargs):
        _client = self.conv.client
        # Do the redirect_uris dynamically
        self.request_args["redirect_uris"] = _client.redirect_uris

        return PostRequest.__call__(self, location, response,
                                    content, features, **kwargs)


class RegistrationRequest_KeyExpPKJ(RegistrationRequest):
    """ Registration request with client key export """
    request = "RegistrationRequest"

    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["token_endpoint_auth_method"] = "private_key_jwt"
        conv.client.behaviour["token_endpoint_auth_method"] = "private_key_jwt"
        self.tests["pre"].append(CheckTokenEndpointAuthMethod)
        #self.export_server = "http://%s:8090/export" % socket.gethostname()

    def __call__(self, location, response="", content="", features=None,
                 **kwargs):
        _client = self.conv.client
        # Do the redirect_uris dynamically
        self.request_args["redirect_uris"] = _client.redirect_uris

        return PostRequest.__call__(self, location, response,
                                    content, features, **kwargs)


class RegistrationRequest_with_policy_and_logo(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)

        ruri = self.request_args["redirect_uris"][0]
        p = urlparse(ruri)

        self.request_args["policy_uri"] = "%s://%s/%s" % (p.scheme, p.netloc,
                                                          "policy.html")
        self.request_args["logo_uri"] = "%s://%s/%s" % (p.scheme, p.netloc,
                                                        "logo.png")


class RegistrationRequest_with_public_userid(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["subject_type"] = "public"
        conv.client.behaviour["subject_type"] = "public"
        self.tests["pre"].append(CheckUserIdSupport)


class RegistrationRequest_with_userinfo_signed(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["userinfo_signed_response_alg"] = "RS256"
        conv.client.behaviour["userinfo_signed_response_alg"] = "RS256"
        self.tests["pre"].append(CheckSignedUserInfoSupport)


class RegistrationRequest_with_pairwise_userid(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["subject_type"] = "pairwise"
        conv.client.behaviour["subject_type"] = "pairwise"
        self.tests["pre"].append(CheckUserIdSupport)
        store_sector_redirect_uris(self.request_args, cconf=conv.client_config)


class RegistrationRequest_with_id_token_signed_response_alg(
        RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["id_token_signed_response_alg"] = "HS256"
        conv.client.behaviour["id_token_signed_response_alg"] = "HS256"
        self.tests["pre"].append(CheckSignedIdTokenSupport)


class RegistrationRequest_SectorID(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        store_sector_redirect_uris(self.request_args, cconf=conv.client_config)


class RegistrationRequest_SectorID_2(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        _base = _get_base(conv.client_config)
        self.request_args["redirect_uris"].append("%scb" % _base)
        store_sector_redirect_uris(self.request_args, cconf=conv.client_config)


class RegistrationRequest_SectorID_Err(RegistrationRequest):
    """Sector Identifier Not Containing Registered redirect_uri Values"""

    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        store_sector_redirect_uris(self.request_args, False, True,
                                   cconf=conv.client_config)
        #self.request_args["redirect_uris"].append("%scb" % _get_base(cconf))
        self.tests["post"] = [CheckErrorResponse]


class RegistrationRequestEncUserinfo(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["userinfo_encrypted_response_alg"] = "RSA1_5"
        self.request_args["userinfo_encrypted_response_enc"] = "A128CBC-HS256"
        self.tests["pre"].extend([CheckEncryptedUserInfoSupportALG,
                                  CheckEncryptedUserInfoSupportENC])


class RegistrationRequestSignEncUserinfo(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["userinfo_signed_response_alg"] = "RS256"
        self.request_args["userinfo_encrypted_response_alg"] = "RSA1_5"
        self.request_args["userinfo_encrypted_response_enc"] = "A128CBC-HS256"
        self.tests["pre"].extend([CheckEncryptedUserInfoSupportALG,
                                  CheckEncryptedUserInfoSupportENC])


class RegistrationRequestEncIDtoken(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["id_token_signed_response_alg"] = "none"
        self.request_args["id_token_encrypted_response_alg"] = "RSA1_5"
        self.request_args["id_token_encrypted_response_enc"] = "A128CBC-HS256"
        self.tests["pre"].extend([CheckEncryptedIDTokenSupportALG,
                                  CheckEncryptedIDTokenSupportENC])


class RegistrationRequestSignEncIDtoken(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        self.request_args["id_token_signed_response_alg"] = "RS256"
        self.request_args["id_token_encrypted_response_alg"] = "RSA1_5"
        self.request_args["id_token_encrypted_response_enc"] = "A128CBC-HS256"
        self.tests["pre"].extend([CheckEncryptedIDTokenSupportALG,
                                  CheckEncryptedIDTokenSupportENC])


class RegistrationRequestJWKS(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        _client = self.conv.client
        _client.jwks_uri = None
        self.request_args["jwks"] = {
            "keys": _client.keyjar.dump_issuer_keys("")}


class RegistrationRequestNoResponseTypes(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        del conv.client.behaviour["response_types"]
        #self.request_args["response_types"] = None


class RegistrationRequestResponseTypesToken(RegistrationRequest):
    def __init__(self, conv):
        RegistrationRequest.__init__(self, conv)
        conv.client.behaviour["response_types"] = ["token"]
        self.request_args["response_types"] = ["token"]


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


class AccessTokenRequestCSB(AccessTokenRequest):
    def __init__(self, conv):
        AccessTokenRequest.__init__(self, conv)
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


class AccessTokenRequest_err(AccessTokenRequest):
    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.tests["post"] = []


class AccessTokenRequestScope(AccessTokenRequest):
    def __init__(self, conv):
        AccessTokenRequest.__init__(self, conv)
        self.request_args["scope"] = "scim"
        self.tests["post"] = [CheckErrorResponse]


class AccessTokenRequestModRedirectURI1(AccessTokenRequest):
    def __init__(self, conv):
        AccessTokenRequest.__init__(self, conv)
        self.tests["post"] = [CheckErrorResponse]

    def call_setup(self):
        _client = self.conv.client
        _uri = _client.redirect_uris[0]
        # Mess with the redirect_uri dynamically
        _uri += "/xlevel"
        self.request_args["redirect_uri"] = _uri


class AccessTokenRequestModRedirectURI2(AccessTokenRequest):
    def __init__(self, conv):
        AccessTokenRequest.__init__(self, conv)
        self.tests["post"] = [CheckErrorResponse]

    def call_setup(self):
        _client = self.conv.client
        _uri = _client.redirect_uris[0]
        # Mess with the redirect_uri dynamically
        _uri += "?query=foo"
        self.request_args["redirect_uri"] = _uri


class AccessTokenRequestModRedirectURI3(AccessTokenRequest):
    def __init__(self, conv):
        AccessTokenRequest.__init__(self, conv)
        self.tests["post"] = [CheckErrorResponse]

    def call_setup(self):
        _client = self.conv.client
        _uri = _client.redirect_uris[0]
        # Mess with the redirect_uri dynamically
        part = urlparse(_uri)
        _uri = _uri.replace(part.path, "/")
        self.request_args["redirect_uri"] = _uri


class UserInfoRequestPostBearerHeader_err(PostRequest):
    request = "UserInfoRequest"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "bearer_header"}
        self.tests["post"] = [CheckErrorResponse]


class UserInfoRequestGetBearerHeader(GetRequest):
    request = "UserInfoRequest"

    def __init__(self, conv):
        GetRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "bearer_header"}


class UserInfoRequestPostBearerHeader(PostRequest):
    request = "UserInfoRequest"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "bearer_header"}


class UserInfoRequestPostBearerHeaderJOSE(PostRequest):
    request = "UserInfoRequest"
    accept = "application/jwt"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "bearer_header"}


class UserInfoRequestPostBearerBody(PostRequest):
    request = "UserInfoRequest"

    def __init__(self, conv):
        PostRequest.__init__(self, conv)
        self.kw_args = {"authn_method": "bearer_body"}


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


class UserinfoResponse(BodyResponse):
    response = "OpenIDSchema"

    def __init__(self):
        BodyResponse.__init__(self)
        self.tests = {"post": [VerifyClaims]}


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

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.request = "DiscoveryRequest"
        self.function = self.discover
        self.do_postop = True
        self.tests = self._tests.copy()

    def discover(self, client, orig_response="", content="", issuer="",
                 **kwargs):
        # Allow statically over-riding dynamic info
        over_ride = client.provider_info
        pcr = client.provider_config(issuer)
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


class Webfinger(Operation):
    #tests = {"post": [OidcIssuer]}
    request = None

    def __init__(self, conv, **kwargs):
        Operation.__init__(self, conv, **kwargs)
        self.request = "WebFinger"
        self.function = self.discover
        self.do_postop = False

    @staticmethod
    def discover(*arg, **kwargs):
        wf = WebFinger(OIC_ISSUER)
        wf.httpd = PBase()
        wf.discovery_query(kwargs["principal"])

# ===========================================================================

PHASES = {
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
    "oic-login": (AuthorizationRequestCode, AuthzResponse),
    "oic-login-uri": (AuthorizationRequestCodeUri, AuthzResponse),
    "oic-login-reqfile": (AuthorizationRequestCodeRequestInFile, AuthzResponse),
    "oic-login-nonce": (AuthorizationRequestCodeWithNonce, AuthzResponse),
    "oic-login+profile": (AuthorizationRequestCodeScopeProfile, AuthzResponse),
    "oic-login+email": (AuthorizationRequestCodeScopeEMail, AuthzResponse),
    "oic-login+phone": (AuthorizationRequestCodeScopePhone, AuthzResponse),
    "oic-login+address": (AuthorizationRequestCodeScopeAddress, AuthzResponse),
    "oic-login+offline": (AuthorizationRequestCodeScopeOfflineAccess,
                          AuthzResponse),
    "oic-login+all": (AuthorizationRequestCodeScopeAll, AuthzResponse),
    "oic-login+spec1": (AuthorizationRequestCodeUIClaim1, AuthzResponse),
    "oic-login+spec2": (AuthorizationRequestCodeUIClaim2, AuthzResponse),
    "oic-login+spec3": (AuthorizationRequestCodeUIClaim3, AuthzResponse),
    "oic-login-combine_claims": (AuthorizationRequestCodeUICombiningClaims,
                                 AuthzResponse),
    "oic-login-mixed_claims": (AuthorizationRequestCodeMixedClaims,
                               AuthzResponse),
    "oic-login+idtc1": (AuthorizationRequestCodeIDTClaim1, AuthzResponse),
    "oic-login+idtc2": (AuthorizationRequestCodeIDTClaim2, AuthzResponse),
    "oic-login+idtc3": (AuthorizationRequestCodeIDTClaim3, AuthzResponse),
    "oic-login+idtc6": (AuthorizationRequestCodeIDTClaim4, AuthzResponse),
    "oic-login+idtc4": (AuthorizationRequestCodeIDTMaxAge1, AuthzResponse),
    "oic-login+idtc5": (AuthorizationRequestCodeIDTMaxAge10, AuthzResponse),
    "oic-login+idtc7": (AuthorizationRequestCodeIDTEmail, AuthzResponse),
    "oic-login+idtcX": (AuthorizationRequestCodeIDTClaimX, AuthzResponse),

    "oic-login+disp_page": (AuthorizationRequestCodeDisplayPage, AuthzResponse),
    "oic-login+disp_popup": (AuthorizationRequestCodeDisplayPopUp,
                             AuthzResponse),
    "oic-login+prompt_none": (AuthorizationRequestCodePromptNone,
                              AuthzErrResponse),
    "oic-login+prompt_login": (AuthorizationRequestCodePromptLogin,
                               AuthzResponse),
    "oic-login+prompt_none+idtoken": (
        AuthorizationRequestCodePromptNoneWithIdToken, None),
    "oic-login+prompt_none+request": (
        AuthorizationRequestCodePromptNoneWithUserID, None),
    "oic-login+request": (AuthorizationRequestCodeWithUserID, AuthzResponse),
    "oic-login-token": (AuthorizationRequestToken, ImplicitAuthzResponse),
    "oic-login-idtoken": (AuthorizationRequestIDToken, ImplicitAuthzResponse),
    "oic-login-code+token": (AuthorizationRequestCodeToken,
                             ImplicitAuthzResponse),
    "oic-login-code+idtoken": (AuthorizationRequestCodeIDToken,
                               ImplicitAuthzResponse),
    "oic-login-idtoken+token": (AuthorizationRequestIDTokenToken,
                                ImplicitAuthzResponse),
    "oic-login-code+idtoken+token": (AuthorizationRequestCodeIDTokenToken,
                                     ImplicitAuthzResponse),
    "oic-login-no-redirect": (AuthorizationRequest_No_Redirect_uri,
                              AuthzResponse),
    "oic-login-no-redirect-err": (AuthorizationRequest_No_Redirect_uri,
                                  AuthzErrResponse),
    "oic-login-formpost": (AuthorizationRequestCodeResponseModeFormPost,
                           AuthzFormResponse),
    #
    "access-token-request_csb": (AccessTokenRequestCSB, AccessTokenResponse),
    "access-token-request_csp": (AccessTokenRequestCSPost, AccessTokenResponse),
    "access-token-request": (AccessTokenRequest, AccessTokenResponse),
    "access-token-request_csj": (AccessTokenRequestCSJWT, AccessTokenResponse),
    "access-token-request_pkj": (AccessTokenRequestPKJWT, AccessTokenResponse),
    "access-token-request_err": (AccessTokenRequest_err, req.ErrorResponse),
    "access-token-request-scope": (AccessTokenRequestScope, req.ErrorResponse),
    "access-token-refresh": (RefreshAccessToken, AccessTokenResponse),
    "access-token-refresh_pkj": (RefreshAccessTokenPKJWT, AccessTokenResponse),
    "user-info-request_gbh": (UserInfoRequestGetBearerHeader, UserinfoResponse),
    "user-info-request_pbh": (UserInfoRequestPostBearerHeader,
                              UserinfoResponse),
    "user-info-request_gbh_jose": (UserInfoRequestPostBearerHeaderJOSE,
                                   UserinfoResponse),
    "user-info-request_pbb": (UserInfoRequestPostBearerBody, UserinfoResponse),
    "user-info-request_err": (UserInfoRequestPostBearerHeader_err,
                              req.ErrorResponse),
    "oic-registration": (RegistrationRequest, RegistrationResponse),
    "oic-registration-multi-redirect": (RegistrationRequest_MULREDIR,
                                        RegistrationResponse),
    "oic-registration-wqc": (RegistrationRequest_WQC, RegistrationResponse),
    "oic-registration-wf": (RegistrationRequest_WF,
                            ClientRegistrationErrorResponse),
    "oic-registration-ke_csj": (RegistrationRequest_KeyExpCSJ,
                                RegistrationResponse),
    "oic-registration-ke_pkj": (RegistrationRequest_KeyExpPKJ,
                                RegistrationResponse),
    "oic-registration-policy+logo": (RegistrationRequest_with_policy_and_logo,
                                     RegistrationResponse),
    "oic-registration-public_id": (RegistrationRequest_with_public_userid,
                                   RegistrationResponse),
    "oic-registration-pairwise_id": (RegistrationRequest_with_pairwise_userid,
                                     RegistrationResponse),
    "oic-registration-sector_id": (RegistrationRequest_SectorID,
                                   RegistrationResponse),
    "oic-registration-signed_userinfo": (
        RegistrationRequest_with_userinfo_signed, RegistrationResponse),
    "oic-registration-sector_id-err": (RegistrationRequest_SectorID_Err,
                                       ClientRegistrationErrorResponse),
    "oic-registration-signed_idtoken": (
        RegistrationRequest_with_id_token_signed_response_alg,
        RegistrationResponse),
    "oic-registration-encrypted_userinfo": (
        RegistrationRequestEncUserinfo, RegistrationResponse),
    "oic-registration-signed+encrypted_userinfo": (
        RegistrationRequestSignEncUserinfo, RegistrationResponse),
    "oic-registration-encrypted_idtoken": (RegistrationRequestEncIDtoken,
                                           RegistrationResponse),
    "oic-registration-signed+encrypted_idtoken": (
        RegistrationRequestSignEncIDtoken, RegistrationResponse),
    "oic-registration-jwks": (RegistrationRequestJWKS, RegistrationResponse),
    "oic-registration-no_response_type": (RegistrationRequestNoResponseTypes,
                                          RegistrationResponse),
    "oic-registration-response_type-token": (
        RegistrationRequestResponseTypesToken, RegistrationResponse),
    "provider-discovery": (Discover, ProviderConfigurationResponse),
    "provider-info": (ProviderRequest, ProviderConfigurationResponse),
    "oic-missing_response_type": (MissingResponseType, AuthzErrResponse),
    "read-registration": (ReadRegistration, RegistrationResponse),
    "oic-registration-multi-redirect_hosts": (
        RegistrationRequest_MULREDIR_mult_host, RegistrationResponse),
    "access-token-request-other-redirect_uri-1": (
        AccessTokenRequestModRedirectURI1, req.ErrorResponse),
    "access-token-request-other-redirect_uri-2": (
        AccessTokenRequestModRedirectURI2, req.ErrorResponse),
    "access-token-request-other-redirect_uri-3": (
        AccessTokenRequestModRedirectURI3, req.ErrorResponse),
    "intermission": TimeDelay,
    "rotate_keys": RotateKeys,
    #"rotate_sign_keys": RotateSignKeys,
    #"rotate_enc_keys": RotateEncKeys,
    "notice": Notice,
    "rm_cookie": RmCookie,
    "expect_err": ExpectError
}

OWNER_OPS = []
USERINFO_REQUEST_AUTH_METHOD = "user-info-request_gbh"

FLOWS = {
    'oic-discovery': {
        "name": 'Support WebFinger discovery',
        "descr": 'Exchange in which Client Discovers and Uses OP Information',
        "sequence": [],
        "endpoints": [],
        "block": ["registration", "key_export"],
    },

    # -------------------------------------------------------------------------
    'oic-code+nonce-token': {
        "name": 'Simple authorization grant flow',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['mj-01'],
        "sequence": ["oic-login-nonce", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
    },
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

    # 'oic-token-userinfo': {
    #     "name": 'Implicit flow and Userinfo request',
    #     "descr": ("1) Request with response_type='token'",
    #               "2) UserinfoRequest",
    #               "  'bearer_body' authentication used"),
    #     "depends": ['mj-02'],
    #     "sequence": ['oic-login-token', USERINFO_REQUEST_AUTH_METHOD],
    #     "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
    # },
    'oic-code+token-userinfo': {
        "name": "Flow with response_type='code token' and Userinfo request",
        "descr": ("1) Request with response_type='code token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['mj-04'],
        "sequence": ['oic-login-code+token', USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
    },
    'oic-code+idtoken-token-userinfo': {
        "name": "Flow with response_type='code idtoken' and Userinfo request",
        "descr": ("1) Request with response_type='code id_token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code+idtoken-token'],
        "sequence": ['oic-login-code+idtoken', "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
    },
    'oic-idtoken+token-userinfo': {
        "name": "Flow with response_type='token idtoken' and Userinfo request",
        "descr": ("1) Request with response_type='id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['mj-06'],
        "sequence": ['oic-login-idtoken+token', USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
    },
    'oic-code+idtoken+token-userinfo': {
        "name": 'Flow with response_type="code idtoken token" and Userinfo '
                'request',
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ["mj-07"],
        "sequence": ['oic-login-code+idtoken+token', USERINFO_REQUEST_AUTH_METHOD],
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
                     'user-info-request_gbh'],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
    },
    'oic-idtoken': {
        "name": "Flow with response_type='idtoken'",
        "descr": ("1) Request with response_type='id_token'",),
        "depends": ["mj-03"],
        "sequence": ['oic-login-idtoken'],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
    },
    # -------------------------------------------------------------------------
    # beared body authentication
    'oic-code-token-userinfo_bb': {
        "name": """Authorization grant flow response_type='code',
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
    # 'oic-token-userinfo_bb': {
    #     "name": """Implicit flow, UserInfo request using POST and bearer body
    # authentication""",
    #     "descr": ("1) Request with response_type='token'",
    #               "2) UserinfoRequest",
    #               "  'bearer_body' authentication used"),
    #     "depends": ['mj-02'],
    #     "sequence": ['oic-login-token', "user-info-request_pbb"],
    #     "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
    # },
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
    # 'mj-02': {
    #     "name": 'Request with response_type=token',
    #     "sequence": ["oic-login-token"],
    #     "endpoints": ["authorization_endpoint"],
    #     "depends": ['mj-01']
    # },
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
        "tests": [('check-nonce', {})]
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
        "endpoints": ["authorization_endpoint", ],
        "depends": ['mj-01'],
    },
    'mj-08': {
        "name": 'Access token request with client_secret_basic authentication',
        # Should register token_endpoint_auth_method=client_secret_basic
        "sequence": ["oic-login", "access-token-request_csb"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-09': {
        "name": 'Access token request with client_secret_post authentication',
        # Should register token_endpoint_auth_method=client_secret_post
        "sequence": ["oic-login", "access-token-request_csp"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-10': {
        "name": 'Access token request with client_secret_jwt authentication',
        "sequence": ["oic-registration-ke_csj", "oic-login",
                     "access-token-request_csj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-11': {
        "name": 'Access token request with public_key_jwt authentication',
        "sequence": ["oic-registration-ke_pkj", "oic-login",
                     "access-token-request_pkj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
    },
    # -------------------------------------------------------------------------
    'mj-12a': {
        "name": 'UserInfo Endpoint Access with GET and bearer_header',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_gbh"],
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
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-12'],
    },
    'mj-15': {
        "name": 'Scope Requesting email Claims',
        "sequence": ["oic-login+email", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-12'],
    },
    'mj-16': {
        "name": 'Scope Requesting address Claims',
        "sequence": ["oic-login+address", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-12'],
    },
    'mj-17': {
        "name": 'Scope Requesting phone Claims',
        "sequence": ["oic-login+phone", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-12'],
    },
    'mj-18': {
        "name": 'Scope Requesting all Claims',
        "sequence": ["oic-login+all", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-12'],
    },
    'mj-19': {
        "name": 'Claims Request with Essential name Claim',
        "sequence": ["oic-login+spec1", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-12'],
    },
    'mj-20': {
        "name": 'Claims Request with Voluntary email and picture Claims',
        "sequence": ["oic-login+spec2", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-12'],
    },
    'mj-21': {
        "name": (
            'Claims Request with Essential name and Voluntary email and '
            'picture Claims'),
        "sequence": ["oic-login+spec3", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-12'],
    },
    'mj-22': {
        "name": 'Requesting ID Token with Voluntary auth_time Claim',
        "sequence": ["oic-login+idtc1", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"auth_time": None})],
        "depends": ['mj-01'],
    },
    'mj-23': {
        "name": 'Requesting ID Token with Essential specific acr Claim',
        "sequence": ["oic-login+idtc2", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"acr": {"values": ["2"]}})],
        "depends": ['mj-01'],
    },
    'mj-24': {
        "name": 'Requesting ID Token with Voluntary acr Claim',
        "sequence": ["oic-login+idtc3", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"acr": "essential"})],
        "depends": ['mj-01'],
    },
    'mj-25': {
        "name": 'Requesting ID Token with max_age=1 seconds Restriction',
        "sequence": ["oic-login", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD, "intermission", "oic-login+idtc4",
                     "access-token-request", USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("multiple-sign-on", {})],
        "depends": ['mj-01'],
    },
    # ---------------------------------------------------------------------
    'mj-26': {
        "name": 'Request with display=page',
        "sequence": ["oic-login+disp_page", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-27': {
        "name": 'Request with display=popup',
        "sequence": ["oic-login+disp_popup", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-28': {
        "name": 'Request with prompt=none',
        "sequence": ["rm_cookie", "oic-login+prompt_none"],
        "endpoints": ["authorization_endpoint"],
        "tests": [("verify-error", {"error": ["login_required",
                                              "interaction_required",
                                              "session_selection_required",
                                              "consent_required"]})],
        "depends": ['mj-01'],
    },
    'mj-29': {
        "name": 'Request with prompt=login means it SHOULD prompt the End-User '
                'for reauthentication',
        "sequence": ["oic-login+prompt_login",
                     "access-token-request", USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
    },
    # ---------------------------------------------------------------------
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
        "name": 'Authorization request missing the response_type parameter',
        "sequence": ["expect_err", "oic-missing_response_type"],
        "endpoints": ["authorization_endpoint"],
        "tests": [("verify-error", {"error": ["invalid_request",
                                              "unsupported_response_type"]})],
        "depends": ['mj-01'],
    },
    'mj-36': {
        "name": 'The sent redirect_uri does not match the registered',
        "sequence": ["expect_err", "login-redirect-fault"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-39': {
        "name": 'Trying to use access code twice should result in an error',
        "sequence": ["oic-login", "access-token-request",
                     "access-token-request_err"],
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-4.1",
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "tests": [("verify-bad-request-response", {})],
        "depends": ["oic-code-token"],
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
        "depends": ["mj-39"],
    },
    'mj-41': {
        "name": 'Registering and then read the client info',
        "sequence": ["oic-registration", "read-registration"],
        "depends": ["mj-00"],
    },
    'mj-43': {
        "name": 'No redirect_uri in request with one registered',
        "sequence": ["oic-registration", "expect_err",
                     "oic-login-no-redirect-err"],
        "endpoints": ["registration_endpoint", "authorization_endpoint"],
        "depends": ["oic-code-token"]
    },
    'mj-45': {
        "name": 'Registration with policy_uri and logo_uri',
        "sequence": ["oic-registration-policy+logo", "oic-login-uri"],
        "endpoints": ["registration_endpoint", "authorization_endpoint"],
        "tests": [("policy_uri_on_page", {}),
                  ("logo_uri_on_page", {})],
        "depends": ['mj-01'],
    },
    'mj-46': {
        "name": 'Registration of wish for public sub',
        "sequence": ["oic-registration-public_id", "oic-login",
                     "access-token-request"],
        "endpoints": ["registration_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-47': {
        "name": 'Registration of sector_identifier_uri',
        "sequence": ["oic-registration-sector_id", "oic-login"],
        "endpoints": ["registration_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-48': {
        "name": 'Incorrect registration of sector_identifier_uri',
        "sequence": ["oic-registration-sector_id-err"],
        "endpoints": ["registration_endpoint"],
        "depends": ['mj-47'],
    },
    'mj-49': {
        "name": 'Registration of wish for pairwise sub',
        "sequence": ["oic-registration-pairwise_id", "oic-login",
                     "access-token-request", USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["registration_endpoint", "authorization_endpoint",
                      "token_endpoint", "userinfo_endpoint"],
        "depends": ['mj-47'],
    },
    'mj-51': {
        "name": 'Login no nonce',
        "sequence": ["expect_err", "oic-login-no-nonce"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-01'],
        "tests": [("verify-error", {"error": ["invalid_request",
                                              "unsupported_response_type"]})],
    },
    'mj-52': {
        "name": 'Requesting ID Token with Email claims',
        "sequence": ["oic-login+idtc7", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "tests": [("verify-id-token", {})],
        "depends": ['mj-01'],
    },
    "mj-53": {
        "name": 'Using prompt=none with user hint through id_token_hint',
        "sequence": ["oic-login", "access-token-request", 'rm_cookie',
                     "oic-login+prompt_none+idtoken"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
    },
    "mj-54": {
        "name": 'Using prompt=none with user hint through sub in request',
        "sequence": ["oic-login", "access-token-request", 'rm_cookie',
                     "oic-login+prompt_none+request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-01'],
    },
    'non-matching-redirect_uri': {
        "name": 'Rejects redirect_uri when Query Parameter Does Not Match',
        "sequence": ["oic-registration-wqc", 'expect_err', "login-ruwqc-err"],
        "endpoints": ["registration_endpoint", "authorization_endpoint"],
        "reference": "http://tools.ietf.org/html/draft-ietf-oauth-v2-31#section-3.1.2",
        "depends": ['mj-01'],
    },
    'mj-56': {
        "name": 'Supports Combining Claims Requested with scope and claims '
                'Request Parameter',
        "sequence": ["oic-login-combine_claims", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-22'],
        "tests": [("verify-userinfo", {})]
    },
    'mj-57': {
        "name": 'Support request_uri Request Parameter',
        "sequence": ["oic-login-reqfile"],
        "endpoints": ["authorization_endpoint"],
        "depends": ['mj-00'],
    },
    'mj-58': {
        "name": 'Requesting ID Token with Essential acr Claim',
        "sequence": ["oic-login+idtc6", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        #"tests": [("verify-id-token", {"acr": None})],
        "depends": ['mj-01'],
    },
    'mj-59': {
        "name": 'Requesting ID Token with max_age=10 seconds Restriction',
        "sequence": ["oic-login", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD, "oic-login+idtc5",
                     "access-token-request", USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("single-sign-on", {}),
                  ("verify-id-token", {"auth_time": None})],
        "depends": ['mj-25'],
    },
    'mj-60': {
        "name": 'RP signals that it wants signed UserInfo returned by '
                'setting the HTTP accept header to "application/jwt"',
        "sequence": ["oic-registration-signed_userinfo", "oic-login",
                     "access-token-request", "user-info-request_gbh_jose"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("asym-signed-userinfo", {})],
        "depends": ['mj-01'],

    },
    'mj-61': {
        "name": 'RP wants symmetric IdToken signature',
        "sequence": ["oic-registration-signed_idtoken", "oic-login",
                     "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "tests": [("sym-signed-idtoken", {})],
        "depends": ['mj-01'],
    },
    #    'mj-62': {
    #        "name": 'Requesting ID Token with auth_time Claim',
    #        "sequence": ["oic-login+spec2", "access-token-request"],
    #        "endpoints": ["authorization_endpoint", "token_endpoint",
    #                      "userinfo_endpoint"],
    #        "depends": ['mj-01'],
    #        },
    'mj-63': {
        "name": 'Supports Returning Different Claims in ID Token and UserInfo '
                'Endpoint',
        "sequence": ["oic-login-mixed_claims", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {}), ("verify-userinfo", {})],
        "depends": ['mj-19'],
    },
    'mj-64': {
        "name": 'Can Provide Encrypted UserInfo Response',
        "sequence": ["oic-registration-encrypted_userinfo", "oic-login",
                     "access-token-request", USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-12'],
        "tests": [("encrypted-userinfo", {})],
    },
    'mj-65': {
        "name": 'Can Provide Signed and Encrypted UserInfo Response',
        "sequence": ["oic-registration-signed+encrypted_userinfo", "oic-login",
                     "access-token-request", USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-60'],
        "tests": [("encrypted-userinfo", {})],
    },
    # 'mj-66': {
    #     "name": 'Can Provide Encrypted ID Token Response',
    #     "sequence": ["oic-registration-encrypted_idtoken", "oic-login",
    #                  "access-token-request", USERINFO_REQUEST_AUTH_METHOD],
    #     "endpoints": ["authorization_endpoint", "token_endpoint",
    #                   "userinfo_endpoint"],
    #     "depends": ['mj-60'],
    #     "tests": [("encrypted-idtoken", {})],
    # },
    'mj-67': {
        "name": 'Can Provide Signed and Encrypted ID Token Response',
        "sequence": ["oic-registration-signed+encrypted_idtoken", "oic-login",
                     "access-token-request", USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-60'],
        "tests": [("signed-encrypted-idtoken", {})],
    },
    "mj-68": {
        "name": 'User hint through sub in request',
        "sequence": ["oic-login", "access-token-request",
                     "oic-login+request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
    },
    'mj-69': {
        "name": 'Access token refresh',
        "sequence": ["oic-login", "access-token-request",
                     "access-token-refresh"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-13'],
        "tests": [("verify-aud", {})],
    },
    'mj-70': {
        "name": 'Offline_access scope',
        "sequence": ["oic-login+offline", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "depends": ['mj-69'],
    },
    'mj-71': {
        "name": 'Checking redirect_uri matching between '
                'AuthorizationRequestEndpoint and TokenRequestEndpoint 1',
        "sequence": ["oic-login",
                     "access-token-request-other-redirect_uri-1"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-69'],
    },
    'mj-72': {
        "name": 'Checking redirect_uri matching between '
                'AuthorizationRequestEndpoint and TokenRequestEndpoint 2',
        "sequence": ["oic-login",
                     "access-token-request-other-redirect_uri-2"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-69'],
    },
    'mj-73': {
        "name": 'Checking redirect_uri matching between '
                'AuthorizationRequestEndpoint and TokenRequestEndpoint 3',
        "sequence": ["oic-login",
                     "access-token-request-other-redirect_uri-3"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-69'],
    },
    'mj-74': {
        "name": 'Registration of static keys',
        "sequence": ["oic-registration-jwks", "oic-login",
                     "access-token-request_csj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-10'],
        #"tests": [("encrypted-idtoken", {})],
    },
    'mj-75': {
        "name": 'Specifying the authn response to be in the form of a '
                'form post',
        "sequence": ["oic-login-formpost",
                     "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
        #"tests": [("encrypted-idtoken", {})],
    },
    'mj-76': {
        "name": 'Request access token, change RSA key and request another '
                'access token',
        "sequence": ["oic-registration-ke_csj", "oic-login",
                     "access-token-request_pkj", "rotate_keys",
                     "access-token-refresh_pkj"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        "depends": ['mj-01'],
        #"tests": [("encrypted-idtoken", {})],
    },
    'mj-77': {
        "name": 'Requesting ID Token with Essential auth_time Claim',
        "sequence": ["oic-login+idtcX", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("verify-id-token", {"auth_time": "essential"})],
        "depends": ['mj-01'],
    },
    'mj-78': {
        "name": 'RP registers userinfo_signed_response_alg to signal that it '
                'wants signed UserInfo returned',
        "sequence": ["oic-registration-signed_userinfo", "oic-login",
                     "access-token-request", USERINFO_REQUEST_AUTH_METHOD],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        "tests": [("asym-signed-userinfo", {})],
        "depends": ['mj-01'],

    }
}

#Providing Aggregated Claims
#Providing Distributed Claims
#Logout Initiated by OP
#Logout Received by OP
#State Change Other than Logout Communicated

NEW = {
    'x-30': {
        "name": 'Scope Requesting profile Claims with aggregated Claims',
        "sequence": ["oic-login+profile", "access-token-request",
                     USERINFO_REQUEST_AUTH_METHOD],
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
