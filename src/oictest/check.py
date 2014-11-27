import json

from jwkest import b64d
from jwkest import unpack
from jwkest.jwe import JWE_RSA
from jwkest.jwk import RSAKey, ECKey
from jwkest.jwk import base64url_to_long
from oic.oauth2.message import ErrorResponse
from oic.oic import AuthorizationResponse
from oic.oic import message
from oictest.regalg import MTI
from oictest.regalg import REGISTERED_JWS_ALGORITHMS
from oictest.regalg import REGISTERED_JWE_alg_ALGORITHMS
from oictest.regalg import REGISTERED_JWE_enc_ALGORITHMS
from rrtest import check
from rrtest import Unknown

from rrtest.check import Check
from rrtest.check import Information
from rrtest.check import WARNING
from rrtest.check import CONT_JSON
from rrtest.check import CONT_JWT
from rrtest.check import CriticalError
from rrtest.check import Other
from rrtest.check import Error
from rrtest.check import ResponseInfo
from rrtest.check import CRITICAL
from rrtest.check import ERROR
from rrtest.check import INTERACTION
from rrtest.check import INFORMATION

__author__ = 'rohe0002'

import inspect
import sys
import urlparse

from oic.oic.message import SCOPE2CLAIMS
from oic.oic.message import IdToken
from oic.oic.message import OpenIDSchema
from oic.utils import time_util


def get_provider_info(conv):
    _pi = conv.client.provider_info
    if not _pi:
        _pi = conv.provider_info
    return _pi


def get_protocol_response(conv, cls):
    res = []
    for instance, msg in conv.protocol_response:
        if isinstance(instance, cls):
            res.append((instance, msg))
    return res


class CmpIdtoken(Other):
    """
    Compares the JSON received as a CheckID response with my own
    interpretation of the IdToken.
    """
    cid = "compare-idoken-received-with-check_id-response"

    def _func(self, conv):
        res = {}
        instance, msg = get_protocol_response(conv, AuthorizationResponse)[0]

        kj = conv.client.keyjar
        keys = {}
        for issuer in kj.keys():
            keys.update(kj.get("ver", issuer=issuer))

        idt = IdToken().deserialize(instance["id_token"], "jwt", key=keys)
        if idt.to_dict() == conv.protocol_response[-1][0].to_dict():
            pass
        else:
            self._status = self.status
            res["message"] = " ".join([
                "My deserialization of the IDToken differs from what the",
                "checkID response"])
        return res


class VerifyPromptNoneResponse(Check):
    """
    The OP may respond in more than one way and still be within
    what the spec says.
    none
    The Authorization Server MUST NOT display any authentication or
    consent user interface pages.
    """
    cid = "verify-prompt-none-response"
    msg = "OP error"

    def _func(self, conv):
        _response = conv.last_response
        _content = conv.last_content
        _client = conv.client
        res = {}
        if _response.status_code == 400:
            err = ErrorResponse().deserialize(_content, "json")
            err.verify()
            if err["error"] in ["consent_required", "interaction_required"]:
                # This is OK
                res["content"] = err.to_json()
                conv.protocol_response.append((err, _content))
            else:
                self._message = "Not an error I expected"
                self._status = CRITICAL
        elif _response.status_code in [301, 302]:
            _loc = _response.headers["location"]
            callback = False
            for url in _client.redirect_uris:
                if _loc.startswith(url):
                    callback = True
                    break

            if not callback:
                self._message = "Not valid to not redirect back to RP"
                self._status = ERROR
                return res

            if "?" in _loc:
                _query = _loc.split("?")[1]
            elif "#" in _loc:
                _query = _loc.split("#")[1]
            else:  # ???
                self._message = "Expected info in the redirect"
                self._status = CRITICAL
                return res
            try:
                err = ErrorResponse().deserialize(_query, "urlencoded")
                err.verify()
                if err["error"] in ["consent_required", "interaction_required",
                                    "login_required"]:
                    # This is OK
                    res["content"] = err.to_json()
                    conv.protocol_response.append((err, _query))
                else:
                    self._message = "Not an error I expected '%s'" % err[
                        "error"]
                    self._status = CRITICAL
            except:
                resp = AuthorizationResponse().deserialize(_query, "urlencoded")
                resp.verify()
                res["content"] = resp.to_json()
                conv.protocol_response.append((resp, _query))
        else:  # should not get anything else
            self._message = "Not an response I expected"
            self._status = CRITICAL

        return res


class CheckSupported(CriticalError):
    """
    Checks that something asked for are supported
    """
    cid = "check-support"
    msg = "X not supported"
    element = "X_supported"
    parameter = "X"
    default = None
    required = False

    def _requested(self, request_args):
        return request_args[self.parameter]

    def _func(self, conv):
        res = {}
        try:
            _sup = self._supported(conv.req.request_args,
                                   get_provider_info(conv))
            if not _sup:
                self._status = self.status
                self._message = self.msg
        except KeyError:
            pass

        return res

    def _supported(self, request_args, provider_info):
        try:
            supported = provider_info[self.element]
        except KeyError:
            if self.default is None:
                if self.required:
                    return False
                else:
                    return True
            else:
                supported = self.default

        try:
            required = self._requested(request_args)
            if isinstance(required, basestring):
                if required not in supported:
                    return False
            else:
                for value in required:
                    if value not in supported:
                        return False
            return True
        except KeyError:
            pass

        return True


class CheckOPSupported(CheckSupported):
    pass


class CheckResponseType(CheckOPSupported):
    """
    Checks that the asked for response type are among the supported
    """
    cid = "check-response-type"
    msg = "Response type not supported"

    def _supported(self, request_args, provider_info):
        try:
            supported = [set(s.split(" ")) for s in
                         provider_info["response_types_supported"]]
        except KeyError:
            supported = [{"code"}]

        try:
            val = request_args["response_type"]
            if isinstance(val, basestring):
                rt = {val}
            else:
                rt = set(val)
            for sup in supported:
                if sup == rt:
                    return True
            return False
        except KeyError:
            pass

        return True


class CheckAcrSupport(CheckOPSupported):
    """
    Checks that the asked for acr are among the supported
    """
    cid = "check-acr-support"
    msg = "ACR level not supported"

    def _supported(self, request_args, provider_info):
        try:
            supported = provider_info["acrs_supported"]
        except KeyError:
            return True

        try:
            # {"claims": {"acr": {"values": ["2"]}}}
            val = request_args["idtoken_claims"]
            acrs = val["claims"]["acr"]["values"]

            for acr in acrs:
                if acr in supported:
                    return True
            return False
        except KeyError:
            pass

        return True


class CheckScopeSupport(CheckOPSupported):
    """
    Checks that the asked for scope are among the supported
    """
    cid = "check-scope-support"
    msg = "Scope not supported"
    element = "scopes_supported"
    parameter = "scope"


class CheckUserIdSupport(CheckOPSupported):
    """
    Checks that the asked for acr are among the supported
    """
    cid = "check-userid-support"
    msg = "Subject type not supported"
    element = "subject_types_supported"
    parameter = "subject_type"


class CheckSignedUserInfoSupport(CheckSupported):
    """
    Checks that the asked for signature algorithms are among the supported
    """
    cid = "check-signed-userinfo-support"
    msg = "Signed UserInfo not supported"
    element = "userinfo_signing_alg_values_supported"
    parameter = "userinfo_signed_response_alg"


class CheckSignedIdTokenSupport(CheckSupported):
    """
    Checks that the asked for signature algorithms are among the supported
    """
    cid = "check-signed-idtoken-support"
    msg = "Signed Id Token algorithm not supported"
    element = "id_token_signing_alg_values_supported"
    parameter = "id_token_signed_response_alg"


class CheckSignedRequestObjectSupport(CheckSupported):
    """
    Checks that the asked for signature algorithms are among the supported
    """
    cid = "check-signed-request_object-support"
    msg = "Signed request object algorithm not supported"
    element = "request_object_signing_alg_values_supported"
    parameter = "request_object_signed_alg"


class CheckEncryptedUserInfoSupportALG(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-signed-userinfo-alg-support"
    msg = "Userinfo encryption alg algorithm not supported"
    element = "userinfo_encryption_alg_values_supported"
    parameter = "userinfo_encrypted_response_alg"


class CheckEncryptedUserInfoSupportENC(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-encrypt-userinfo-enc-support"
    msg = "UserInfo encryption enc algorithm not supported"
    element = "userinfo_encryption_enc_values_supported"
    parameter = "userinfo_encrypted_response_enc"


class CheckEncryptedIDTokenSupportALG(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-encrypt-idtoken-alg-support"
    msg = "Id Token encryption alg algorithm not supported"
    element = "id_token_encryption_alg_values_supported"
    parameter = "id_token_encrypted_response_alg"


class CheckEncryptedIDTokenSupportENC(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-encrypt-idtoken-enc-support"
    msg = "Id Token encryption enc method not supported"
    element = "id_token_encryption_enc_values_supported"
    parameter = "id_token_encrypted_response_enc"


class CheckEncryptedRequestObjectSupportALG(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-encrypt-request_object-alg-support"
    msg = "Request_object encryption alg algorithm not supported"
    element = "request_object_encryption_alg_values_supported"
    parameter = "request_object_encryption_alg"


class CheckEncryptedRequestObjectSupportENC(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-encrypt-idtoken-enc-support"
    msg = "Request_object encryption enc algorithm not supported"
    element = "request_object_encryption_enc_values_supported"
    parameter = "request_object_encryption_enc"


class CheckClaimsSupport(CheckOPSupported):
    """
    Checks that the asked for scope are among the supported
    """
    cid = "check-scope-support"
    msg = "Claims not supported"
    element = "claims_supported"
    parameter = "claims"

    def _requested(self, request_args):
        _req = request_args[self.parameter]
        return _req["userinfo"].keys()


class CheckRequestClaimsSupport(CheckOPSupported):
    """
    Checks that the asked for scope are among the supported
    """
    cid = "check-scope-support"
    msg = "Claims not supported"
    element = "claims_supported"
    parameter = "claims"

    def _requested(self, request_args):
        _req = CheckOPSupported._requested(self, request_args)
        return _req["userinfo"].keys()


class CheckSupportedTrue(CriticalError):
    """
    Checks that the request parameter is supported
    """
    cid = "check-X-support"
    msg = "X not supported"
    element = "X"

    def _func(self, conv):
        res = {}

        try:
            assert get_provider_info(conv)[self.element] == "true"
        except (AssertionError, KeyError):
            self._status = self.status
            self._message = self.msg

        return res


class CheckRequestParameterSupported(CheckSupportedTrue):
    """
    Checks that the request parameter is supported
    """
    cid = "check-request-parameter-supported-support"
    msg = "Request parameter not supported"
    element = "request_parameter_supported"


class CheckRequestURIParameterSupported(CriticalError):
    """
    Checks that the request parameter is supported
    """
    cid = "check-request-parameter-supported-support"
    msg = "Request parameter not supported"
    element = "request_uri_parameter_supported"


class CheckIdTokenSignedResponseAlgSupport(CheckSupported):
    """
    Checks that the asked for id_token_signed_response_alg are among the
    supported
    """
    cid = "check-id_token_signed_response_alg-support"
    msg = "Id_token_signed_response_alg not supported"
    element = "id_token_signed_response_alg_supported"
    parameter = "id_token_signed_response_alg"


class CheckTokenEndpointAuthMethod(CriticalError):
    """
    Checks that the token endpoint supports the used Auth type
    """
    cid = "check-token-endpoint-auth-method"
    msg = "Auth type not supported"

    def _func(self, conv):
        try:
            _req = conv.request_spec
            if _req.request == "RegistrationRequest":
                _met = conv.request_args["token_endpoint_auth_method"]
            else:
                _met = conv.args["authn_method"]

            try:
                _pi = get_provider_info(conv)
                _sup = _pi["token_endpoint_auth_methods_supported"]
            except KeyError:
                _sup = None

            if not _sup:
                # MTI
                _sup = ["client_secret_basic"]

            if _met not in _sup:
                self._message = self.msg
                self._status = self.status
        except KeyError:
            pass

        return {}


class CheckContentTypeHeader(Error):
    """
    Verify that the content-type header is what it should be.
    """
    cid = "check_content_type_header"

    def _func(self, conv=None):
        res = {}
        _response = conv.last_response
        try:
            ctype = _response.headers["content-type"]
            if conv.response_spec.ctype == "json":
                if CONT_JSON in ctype or CONT_JWT in ctype:
                    pass
                else:
                    self._status = self.status
                    self._message = "Wrong content type: %s" % ctype
            else:  # has to be uuencoded
                if not "application/x-www-form-urlencoded" in ctype:
                    self._status = self.status
                    self._message = "Wrong content type: %s" % ctype
        except KeyError:
            pass

        return res


class CheckEndpoint(CriticalError):
    """ Checks that the necessary endpoint exists at a server """
    cid = "check-endpoint"
    msg = "Endpoint missing"

    def _func(self, conv=None):
        cls = conv.req.request
        try:
            endpoint = conv.client.request2endpoint[cls]
        except KeyError:
            pass
        else:
            try:
                assert endpoint in get_provider_info(conv)
            except AssertionError:
                self._status = self.status
                self._message = "No '%s' registered" % endpoint

        return {}


class CheckHasJwksURI(Error):
    """
    Check that the jwks_uri claim is in the provider_info
    """
    cid = "providerinfo-has-jwks_uri"
    msg = "jwks_uri claims missing"

    def _func(self, conv):
        try:
            jwks_uri = get_provider_info(conv)["jwks_uri"]
        except KeyError:
            self._status = self.status
            self._message = "No 'jwks_uri' registered"

        return {}


class CheckHasClaimsSupported(Error):
    """
    Check that the claims_supported claim is in the provider_info
    """
    cid = "providerinfo-has-claims_supported"
    msg = "claims_supported claims missing"

    def _func(self, conv):
        try:
            jwks_uri = get_provider_info(conv)["claims_supported"]
        except KeyError:
            self._status = self.status
            self._message = "No 'claims_supported' registered"

        return {}


class CheckProviderInfo(Error):
    """
    Check that the Provider Info is sound
    """
    cid = "check-provider-info"
    msg = "Provider information error"

    def _func(self, conv=None):
        #self._status = self.status
        return {}


class CheckRegistrationResponse(Error):
    """
    Verifies an Registration response. This is additional constrains besides
    what is optional or required.
    """
    cid = "check-registration-response"
    msg = "Registration response error"

    def _func(self, conv=None):
        #self._status = self.status
        return {}


class CheckAuthorizationResponse(Error):
    """
    Verifies an Authorization response. This is additional constrains besides
    what is optional or required.
    """
    cid = "check-authorization-response"

    def _func(self, conv=None):
        #self._status = self.status
        return {}


class LoginRequired(Error):
    """
    Verifies an Authorization error response. The error should be
    login_required.
    """
    cid = "login-required"

    def _func(self, conv=None):
        #self._status = self.status
        resp = conv.last_content
        try:
            assert resp.type() == "AuthorizationErrorResponse"
        except AssertionError:
            self._status = self.status
            self._message = "Expected authorization error response got %s" % (
                resp.type())

            try:
                assert resp.type() == "ErrorResponse"
            except AssertionError:
                self.status = CRITICAL
                self._message = "Expected an Error Response got %s" % (
                    resp.type())
                return {}

        try:
            assert resp.error == "login_required"
        except AssertionError:
            self._status = self.status
            self._message = "Wrong error code"

        return {}


class InteractionNeeded(CriticalError):
    """
    A Webpage was displayed for which no known interaction is defined.
    """
    cid = "interaction-needed"
    msg = "Unexpected page"

    def _func(self, conv=None):
        self._status = self.status
        self._message = None
        return {"url": conv.position}


class InteractionCheck(CriticalError):
    """
    A Webpage was displayed for which no known interaction is defined.
    """
    cid = "interaction-check"

    def _func(self, conv=None):
        self._status = INTERACTION
        self._message = conv.last_content
        parts = urlparse.urlsplit(conv.position)
        return {"url": "%s://%s%s" % parts[:3]}


def get_authz_request(conv):
    for req in ["AuthorizationRequest", "OpenIDRequest"]:
        try:
            return getattr(conv, req)
        except AttributeError:
            pass
    return None


class VerifyClaims(Error):
    """
    Verifies that the user information returned is consistent with
    what was asked for
    """
    cid = "verify-claims"
    errmsg = "attributes received not matching claims"

    def _func(self, conv=None):
        userinfo_claims = {}

        req = get_authz_request(conv)
        try:
            _scopes = req["scope"]
        except KeyError:
            return {}

        for scope in _scopes:
            try:
                claims = dict([(name, None) for name in SCOPE2CLAIMS[scope]])
                userinfo_claims.update(claims)
            except KeyError:
                pass

        if "request" in req:
            jso = json.loads(unpack(req["request"])[1])
            _uic = jso["userinfo"]
            for key, val in _uic["claims"].items():
                userinfo_claims[key] = val

        try:
            _userinfo_claims = req["claims"]["userinfo"]
        except KeyError:
            pass
        else:
            for key, val in _userinfo_claims.items():
                userinfo_claims[key] = val

        # Get the UserInfoResponse, should only be one
        inst, txt = get_protocol_response(conv, OpenIDSchema)[0]
        if userinfo_claims:
            for key, restr in userinfo_claims.items():
                if key in inst:
                    pass
                else:
                    if restr == {"essential": True}:
                        self._status = self.status
                        self._message = "required attribute '%s' missing" % key
                        return {"returned claims": inst.keys()}

        for key in inst.keys():
            if key not in userinfo_claims:
                self._status = WARNING
                self._message = "Unexpected %s claim in response" % key
                return {"returned claims": inst.keys()}

        return {}


REQUIRED = {"essential": True}
OPTIONAL = None


class verifyIDToken(CriticalError):
    """
    Verifies that the IDToken contains what it should
    """
    cid = "verify-id-token"
    msg = "IDToken error"

    def _func(self, conv):
        done = False

        idtoken_claims = {}
        req = get_authz_request(conv)
        try:
            id_claims = req["claims"]["id_token"]
        except KeyError:
            pass
        else:
            idtoken_claims = id_claims.copy()

        for item, msg in conv.protocol_response:
            if self._status == self.status or done:
                break

            try:
                _idt = item["id_token"]
                if _idt is None:
                    continue
            except KeyError:
                continue

            idtoken = _idt
            for key, val in idtoken_claims.items():
                if key == "max_age":
                    if idtoken["exp"] > (time_util.utc_time_sans_frac() + val):
                        self._status = self.status
                        diff = idtoken["exp"] - time_util.utc_time_sans_frac()
                        self._message = "exp to far in the future [%d]" % diff
                        break
                    else:
                        continue

                if val == OPTIONAL:
                    if key not in idtoken:
                        self._status = self.status
                        self._message = "'%s' was supposed to be there" % key
                        break
                elif val == REQUIRED:
                    try:
                        assert key in idtoken
                    except AssertionError:
                        self._status = self.status
                        self._message = "'%s' was expected to be there" % key
                        break
                elif "values" in val:
                    if key not in idtoken:
                        self._status = self.status
                        self._message = "Missing value on '%s'" % key
                        break
                    else:
                        _val = idtoken[key]
                        if isinstance(_val, basestring):
                            if _val not in val["values"]:
                                self._status = self.status
                                self._message = "Wrong value on '%s'" % key
                                break
                        elif isinstance(_val, int):
                            if _val not in val["values"]:
                                self._status = self.status
                                self._message = "Wrong value on '%s'" % key
                                break
                        else:
                            for sval in _val:
                                if sval in val["values"]:
                                    continue
                            self._status = self.status
                            self._message = "Wrong value on '%s'" % key
                            break

                done = True

        return {}


class RegistrationInfo(ResponseInfo):
    """Registration Response"""


class ProviderConfigurationInfo(ResponseInfo):
    """Provider Configuration Response"""


class UnpackAggregatedClaims(Error):
    cid = "unpack-aggregated-claims"

    def _func(self, conv=None):
        resp = conv.response_message
        _client = conv.client

        try:
            _client.unpack_aggregated_claims(resp)
        except Exception, err:
            self._message = "Unable to unpack aggregated Claims: %s" % err
            self._status = self.status

        return {}


class ChangedSecret(Error):
    cid = "changed-client-secret"

    def _func(self, conv=None):
        resp = conv.response_message
        _client = conv.client
        old_sec = _client.client_secret

        if old_sec == resp["client_secret"]:
            self._message = "Client secret was not changed"
            self._status = self.status

        return {}


class VerifyAccessTokenResponse(Error):
    """
    Checks the Access Token response
    """
    cid = "verify-access-token-response"
    section = "http://openid.bitbucket.org/" + \
              "openid-connect-messages-1_0.html#access_token_response"

    def _func(self, conv=None):
        resp, text = get_protocol_response(conv, message.AccessTokenResponse)[0]

        #This specification further constrains that only Bearer Tokens [OAuth
        # .Bearer] are issued at the Token Endpoint. The OAuth 2.0 response
        # parameter "token_type" MUST be set to "Bearer".
        if "token_type" in resp and resp["token_type"].lower() != "bearer":
            self._message = "token_type has to be 'Bearer'"
            self._status = self.status

        #In addition to the OAuth 2.0 response parameters, the following
        # parameters MUST be included in the response if the grant_type is
        # authorization_code and the Authorization Request scope parameter
        # contained openid: id_token
        cis = conv.cis[-1]
        if cis["grant_type"] == "authorization_code":
            req = get_authz_request(conv)
            if "openid" in req["scope"]:
                if "id_token" not in resp:
                    self._message = "IdToken has to be present"
                    self._status = self.status

        return {}


class SingleSignOn(Error):
    """ Verifies that Single-Sign-On actually works """
    cid = "single-sign-on"

    def _func(self, conv):
        logins = 0

        for line in conv.trace:
            if ">> login <<" in line:
                logins += 1

        if logins > 1:
            self._message = " ".join(["Multiple authentications when only one",
                                      "was expected"])
            self._status = self.status

        return {}


class MultipleSignOn(Error):
    """ Verifies that multiple authentication was used in the flow """
    cid = "multiple-sign-on"

    def _func(self, conv):
        logins = 0

        for line in conv.trace:
            if ">> login <<" in line:
                logins += 1

        if logins == 1:
            self._message = " ".join(["Only one authentication when more than",
                                      "one was expected"])
            self._status = self.status

        return {}


class VerifyRedirect_uriQueryComponent(Error):
    """
    Checks that a query component in the redirect_uri value that was
    specified in the Authorization request are present in the
    URL used by the OP for the response.
    """
    cid = "verify-redirect_uri-query_component"

    def _func(self, conv):
        ruri = self._kwargs["redirect_uri"]
        part = urlparse.urlparse(ruri)
        qdict = urlparse.parse_qs(part.query)
        item, msg = conv.protocol_response[-1]
        try:
            for key, vals in qdict.items():
                if len(vals) == 1:
                    assert item[key] == vals[0]
        except AssertionError:
            self._message = "Query component that was part of the " \
                            "redirect_uri is missing"
            self._status = self.status

        return {}


class CheckKeys(CriticalError):
    """ Checks that the necessary keys are defined """
    cid = "check-keys"
    msg = "Missing keys"

    def _func(self, conv=None):
        #cls = conv.request_spec"].request
        client = conv.client
        # key type
        keys = client.keyjar.get_signing_key("rsa")
        try:
            assert keys
        except AssertionError:
            self._status = self.status
            self._message = "No rsa key for signing registered"

        return {}


class VerifyPolicyURLs(Error):
    cid = "policy_uri_on_page"
    msg = "policy_uri not on page"

    def _func(self, conv=None):
        login_page = conv.login_page
        regreq = conv.RegistrationRequest

        try:
            assert regreq["policy_uri"] in login_page
        except AssertionError:
            self._status = self.status

        return {}


class VerifyLogoURLs(Error):
    cid = "logo_uri_on_page"
    msg = "logo_uri not on page"

    def _func(self, conv=None):
        login_page = conv.login_page
        regreq = conv.RegistrationRequest

        try:
            assert regreq["logo_uri"] in login_page
        except AssertionError:
            self._status = self.status

        return {}


class CheckUserID(Error):
    """
    Verifies that the sub value differs between public and pairwise
    subject types.
    """
    cid = "different_sub"
    msg = "sub not changed between public and pairwise"

    def _func(self, conv=None):
        sub = []
        for instance, msg in get_protocol_response(conv, OpenIDSchema):
            sub.append(instance["sub"])

        try:
            assert len(sub) == 2
            assert sub[0] != sub[1]
        except AssertionError:
            self._status = self.status

        return {}


class VerifyUserInfo(Error):
    """
    Checks that all required information are in the UserInfo.
    Note that it's not an error on the OPs behalf if not all information
    is there.
    """
    cid = "verify-userinfo"
    msg = "Essential User info missing"

    def _func(self, conv):
        req = get_authz_request(conv)
        try:
            claims = req["userinfo_claims"]["claims"]
        except KeyError:
            claims = {}
        for scope in req["scope"]:
            for param in SCOPE2CLAIMS[scope]:
                claims[param] = REQUIRED

        response, msg = conv.protocol_response[-1]
        try:
            for key, val in claims.items():
                if val == OPTIONAL:
                    continue
                elif val == REQUIRED:
                    assert key in response
                else:
                    value = val["value"]
                    assert response[key] == value
        except AssertionError:
            self._status = self.status

        return {}


class CheckAsymSignedUserInfo(Error):
    """
    Verifies that the UserInfo was signed with a RSA key
    """
    cid = "asym-signed-userinfo"
    msg = "User info was not signed"

    def _func(self, conv):
        instance, msg = get_protocol_response(conv, OpenIDSchema)[0]
        header = json.loads(b64d(str(msg.split(".")[0])))
        try:
            assert header["alg"].startswith("RS")
        except AssertionError:
            self._status = self.status

        return {}


class CheckSymSignedIdToken(Error):
    """
    Verifies that the IDToken was signed with a symmetric key
    """
    cid = "sym-signed-idtoken"
    msg = "Incorrect signature type"

    def _func(self, conv):
        instance, msg = get_protocol_response(conv,
                                              message.AccessTokenResponse)[0]
        _dict = json.loads(msg)
        jwt = _dict["id_token"]
        header = json.loads(b64d(str(jwt.split(".")[0])))
        try:
            assert header["alg"].startswith("HS")
        except AssertionError:
            self._status = self.status

        return {}


class CheckESSignedIdToken(Error):
    """
    Verifies that the IdToken was signed with a EC key
    """
    cid = "es-signed-idtoken"
    msg = "Incorrect signature type"

    def _func(self, conv):
        instance, msg = get_protocol_response(conv,
                                              message.AccessTokenResponse)[0]
        _dict = json.loads(msg)
        jwt = _dict["id_token"]
        header = json.loads(b64d(str(jwt.split(".")[0])))
        try:
            assert header["alg"].startswith("ES")
        except AssertionError:
            self._status = self.status

        return {}


class CheckEncryptedUserInfo(Error):
    """
    Verifies that the UserInfo returned was encrypted
    """
    cid = "encrypted-userinfo"
    msg = "User info was not encrypted"

    def _func(self, conv):
        instance, msg = get_protocol_response(conv, OpenIDSchema)[0]
        header = json.loads(b64d(str(msg.split(".")[0])))
        try:
            assert header["alg"].startswith("RSA")
        except AssertionError:
            self._status = self.status

        return {}


class CheckEncryptedIDToken(Error):
    """
    Verifies that a IDToken was encrypted
    """
    cid = "encrypted-idtoken"
    msg = "ID Token was not encrypted"

    def _func(self, conv):
        instance, msg = get_protocol_response(conv,
                                              message.AccessTokenResponse)[0]
        _dic = json.loads(msg)
        header = json.loads(b64d(str(_dic["id_token"].split(".")[0])))
        try:
            assert header["alg"].startswith("RSA")
        except AssertionError:
            self._status = self.status

        return {}


class CheckSignedEncryptedIDToken(Error):
    """
    Verifies that a IDToken was signed and then encrypted
    """
    cid = "signed-encrypted-idtoken"
    msg = "ID Token was not signed and encrypted"

    def _func(self, conv):
        client = conv.client
        instance, msg = get_protocol_response(conv,
                                              message.AccessTokenResponse)[0]
        _dic = json.loads(msg)
        header = json.loads(b64d(str(_dic["id_token"].split(".")[0])))
        try:
            assert header["alg"].startswith("RSA")
        except AssertionError:
            self._status = self.status

        dkeys = client.keyjar.get_decrypt_key(owner="")
        jwt = JWE_RSA().decrypt(_dic["id_token"], dkeys[0].key)
        _header = unpack(jwt)[0]
        try:
            assert _header["alg"] in ["RS256", "HS256"]
        except AssertionError:
            self._status = self.status

        return {}


class VerifyAud(Error):
    cid = "verify-aud"
    msg = "Not the same aud in the newly issued token"

    def _func(self, conv):
        # Should be two AccessTokenResponses
        atr = []
        for instance, msg in get_protocol_response(
                conv, message.AccessTokenResponse):
            atr.append(instance)

        try:
            assert atr[0]["id_token"]["aud"] == atr[1]["id_token"]["aud"]
        except AssertionError:
            self._status = self.status

        return {}


class VerifyImplicitResponse(Error):
    cid = "verify-implicit-reponse"
    msg = "Expected response in fragment"

    def _func(self, conv):
        _part = urlparse.urlparse(conv.info)
        # first verify there is a fragment
        try:
            assert _part.fragment
            # The is where the response is
            _resp = AuthorizationResponse().from_urlencoded(_part.fragment)
            assert _resp
            # Can't do this check since in the response_message the id_token is
            # unpacked
            #assert _resp == conv.response_message
        except AssertionError:
            self._status = self.status

        return {}


class CheckNonce(Error):
    """
    Verify that I in the IDToken gets back the nonce I included in the
    Authorization Request.
    """
    cid = "check-nonce"
    msg = "Expected same nonce back as sent"

    def _func(self, conv):
        try:
            _nonce = conv.AuthorizationRequest["nonce"]
        except KeyError:
            pass
        else:
            instance, msg = get_protocol_response(conv,
                                                  AuthorizationResponse)[0]

            try:
                assert _nonce == instance["id_token"]["nonce"]
            except (AssertionError, KeyError):
                self._status = self.status

        return {}


class CheckResponseMode(CheckOPSupported):
    """
    Checks that the asked for response mode are among the supported
    """
    cid = "check-response-mode"
    msg = "Response mode not supported"

    def _supported(self, request_args, provider_info):
        try:
            supported = provider_info["response_modes_supported"]
        except KeyError:  # default set
            supported = ['query', 'fragment']

        try:
            val = request_args["response_mode"]
            if val in supported:
                return True
            else:
                return False
        except KeyError:
            pass

        return True


class VerifyISS(Error):
    """
    verify that the iss value given in the discovery response is the
    same as the issuer in an IDToken.
    """
    cid = "verify-iss"
    msg = "Not the same iss/issuer in the id_token as in the Provider Info"

    def _func(self, conv):
        # Should be two AccessTokenResponses
        atr = []
        instance = conv.protocol_response[-1][0]
        iss = instance["id_token"]["iss"]
        issuer = get_provider_info(conv)["issuer"]

        try:
            assert iss == issuer
        except AssertionError:
            self._status = self.status

        return {}


class VerfyMTIEncSigAlgorithms(Information):
    """
    Verify that the MTI algorithms appear.
    """
    cid = "verify-mti-enc-sig-algorithms"
    msg = "MTI encryption/signature algorithm missing"
    status = INFORMATION

    def _func(self, conv):
        _pi = get_provider_info(conv)

        missing = []
        for key, algs in MTI.items():
            for alg in algs:
                try:
                    assert alg in _pi[key]
                except (AssertionError, KeyError):
                    _alg = "%s:%s" % (key, alg)
                    if _alg not in missing:
                        missing.append(_alg)

        if missing:
            self._message = "The following MTI algorithms was missing :%s" % (
                missing,)
            self._status = self.status

        return {}


class CheckEncSigAlgorithms(Information):
    """
    Verify that the ENC/SIG algorithms listed are officially registered.
    """
    cid = "check-enc-sig-algorithms"
    msg = "Unofficial algorithm"

    def _func(self, conv):
        _pi = get_provider_info(conv)

        unknown_jws = []
        for typ in ["id_token", "userinfo", "request_object",
                    "token_endpoint_auth"]:
            _claim = "%s_signing_alg_values_supported" % typ
            try:
                algs = _pi[_claim]
            except KeyError:
                pass
            else:
                for alg in algs:
                    try:
                        assert alg in REGISTERED_JWS_ALGORITHMS
                    except AssertionError:
                        if alg not in unknown_jws:
                            unknown_jws.append(alg)

        unknown_jwe_alg = []
        for typ in ["id_token", "userinfo", "request_object"]:
            _claim = "%s_encryption_alg_values_supported" % typ
            try:
                algs = _pi[_claim]
            except KeyError:
                pass
            else:
                for alg in algs:
                    try:
                        assert alg in REGISTERED_JWE_alg_ALGORITHMS
                    except AssertionError:
                        if alg not in unknown_jwe_alg:
                            unknown_jwe_alg.append(alg)

        unknown_jwe_enc = []
        for typ in ["id_token", "userinfo", "request_object"]:
            _claim = "%s_encryption_enc_values_supported" % typ
            try:
                algs = _pi[_claim]
            except KeyError:
                pass
            else:
                for alg in algs:
                    try:
                        assert alg in REGISTERED_JWE_enc_ALGORITHMS
                    except AssertionError:
                        if alg not in unknown_jwe_enc:
                            unknown_jwe_enc.append(alg)

        if unknown_jws or unknown_jwe_alg or unknown_jwe_enc:
            _txt = "Used algorithms that are not registered: "
            flag = False
            if unknown_jws:
                _txt += "JWS algorithms:%s" % (unknown_jws,)
                flag = True
            if unknown_jwe_alg:
                if flag:
                    _txt += ", "
                _txt += "JWE alg algorithms:%s" % (unknown_jwe_alg,)
                flag = True
            if unknown_jwe_enc:
                if flag:
                    _txt += ", "
                _txt += "JWE enc algorithms:%s" % (unknown_jwe_enc,)

            self._message = _txt
            self._status = self.status

        return {}


class VerifyOPEndpointsUseHTTPS(Information):
    """
    Verify that all OP endpoints uses https
    """
    cid = "verify-op-endpoints-use-https"
    msg = "Some OP endpoints are not using HTTPS"

    def _func(self, conv):
        _pi = get_provider_info(conv)
        for param, val in _pi.items():
            if param.endswith("_endpoint"):
                try:
                    assert val.startswith("https://")
                except AssertionError:
                    self._status = self.status
                    break

        return {}


class VerifyOPHasRegistrationEndpoint(Information):
    """
    Verify that the OP has a registration endpoint
    """
    cid = "verify-op-has-registration-endpoint"
    msg = "No registration endpoint"

    def _func(self, conv):
        _pi = get_provider_info(conv)
        try:
            assert "registration_endpoint" in _pi
        except AssertionError:
            self._status = self.status

        return {}


class VerifyIDTokenUserInfoSubSame(Information):
    """
    Verify that the sub claim in the IdToken is the same as is provider in
    the userinfo
    """
    cid = "verify-id_token-userinfo-same-sub"
    msg = "Sub identifier differs between the IdToken and the UserInfo"

    def _func(self, conv):
        ui_sub = idt_sub = ""

        # The userinfo sub
        for instance, msg in conv.protocol_response:
            if isinstance(instance, message.OpenIDSchema):
                ui_sub = instance["sub"]
        # The IdToken sub
        for instance, msg in conv.protocol_response:
            if isinstance(instance, message.AccessTokenResponse):
                if "id_token" in instance:
                    idt_sub = instance["id_token"]["sub"]
                    break
            elif isinstance(instance, message.AuthorizationResponse):
                if "id_token" in instance:
                    idt_sub = instance["id_token"]["sub"]
                    break

        try:
            assert ui_sub == idt_sub
        except AssertionError:
            self._status = self.status

        return {}


class VerifyState(Information):
    """
    Verifies that the State variable is the same returned as was sent
    """
    cid = "verify-state"
    msg = "The State variable in not the same as sent"

    def _func(self, conv):
        _send_state = _recv_state = ""

        # The send state
        _send_state = conv.AuthorizationRequest["state"]
        # the received state
        inst, txt = get_protocol_response(conv, AuthorizationResponse)[-1]
        _recv_state = inst["state"]

        try:
            assert _send_state == _recv_state
        except AssertionError:
            self.status = self._status

        return {}


class VerifySignedIdTokenHasKID(Error):
    """
    Verifies that the header of a signed IDToken includes a kid claim.
    """
    cid = "verify-signed-idtoken-has-kid"
    msg = "Signed IdToken has no kid"

    def _func(self, conv):
        instance, msg = get_protocol_response(conv,
                                              message.AccessTokenResponse)[0]
        _dict = json.loads(msg)
        jwt = _dict["id_token"]
        header = json.loads(b64d(str(jwt.split(".")[0])))
        # doesn't verify signing kid if JWT is signed and then encrypted
        if "enc" not in header:
            if header["alg"].startswith("RS"):
                try:
                    assert "kid" in header
                except AssertionError:
                    self._status = self.status

        return {}


class VerifySignedIdToken(Error):
    """
    Verifies that an IdToken is signed
    """
    cid = "verify-idtoken-is-signed"
    msg = "Unsigned IdToken"

    def _func(self, conv):
        instance, msg = get_protocol_response(conv,
                                              message.AccessTokenResponse)[0]
        _dict = json.loads(msg)
        jwt = _dict["id_token"]
        header = json.loads(b64d(str(jwt.split(".")[0])))
        try:
            assert header["alg"] != "none"
        except AssertionError:
            self._status = self.status

        return {}


class VerifyNonce(Error):
    """
    Verifies that the nonce recceived in the IDToken is the same as was
    given in the Authorization Request
    """
    cid = "verify-nonce"
    msg = "Not the same nonce in the id_token as in the authorization request"

    def _func(self, conv):
        try:
            ar_nonce = conv.AuthorizationRequest["nonce"]
        except KeyError:
            ar_nonce = ""

        instance, msg = get_protocol_response(conv,
                                              message.AccessTokenResponse)[0]
        try:
            idt_nonce = instance["id_token"]["nonce"]
        except KeyError:
            idt_nonce = ""

        try:
            assert ar_nonce == idt_nonce
        except AssertionError:
            self._status = self.status

        return {}


class VerifyUnSignedIdToken(Error):
    """
    Verifies that an IDToken is in fact unsigned, that is signed with the
    'none' algorithm.
    """
    cid = "unsigned-idtoken"
    msg = "Unsigned IdToken"

    def _func(self, conv):
        instance, msg = get_protocol_response(conv,
                                              message.AccessTokenResponse)[0]
        _dict = json.loads(msg)
        jwt = _dict["id_token"]
        header = json.loads(b64d(str(jwt.split(".")[0])))
        try:
            assert header["alg"] == "none"
        except AssertionError:
            self._status = self.status

        return {}


class CheckSubConfig(Error):
    cid = "sub-claim-configured"
    msg = "Sub claim not configured"

    def _func(self, conv):
        try:
            _ = conv.client_config["sub"]
        except KeyError:
            self._status = self.status

        return {}


class VerifySubValue(Error):
    """
    Verifies that the sub claim returned in the id_token matched the
    asked for.
    """
    cid = "verify-sub-value"
    msg = "Unexpected sub value"

    def _func(self, conv):
        _pattern = conv.client_config["sub"]
        instance, msg = get_protocol_response(conv,
                                              message.AccessTokenResponse)[0]
        atr_sub = instance["id_token"]["sub"]
        for key, val in _pattern.items():
            if key == "essential":  # doesn't really make any sense
                pass
            elif key == "value":
                try:
                    assert atr_sub == val
                except AssertionError:
                    self._status = self.status
                    break
            elif key == "values":
                try:
                    assert atr_sub in val
                except AssertionError:
                    self._status = self.status
                    break

        return {}


class VerifyBase64URL(Check):
    """
    Verifies that the base64 encoded parts of a JWK is in fact base64url
    encoded and not just base64 encoded
    """
    cid = "verify-jwks"
    msg = "JWKS not accoding to spec"

    def _func(self, conv):
        # There should be two entrie in the KeyJar, one is myself and the
        # other the OP
        for issuer, kbs in conv.client.keyjar.issuer_keys.items():
            if issuer == "":  # myself
                continue
            else:
                for kb in kbs:
                    if kb.imp_jwks is not None:
                        for key in kb.imp_jwks["keys"]:
                            if key["kty"] == "RSA":
                                _longs = RSAKey.longs
                            elif key["kty"] == "EC":
                                _longs = ECKey.longs
                            else:
                                _longs = []
                            for p in _longs:
                                try:
                                    _val = key[p]
                                except KeyError:
                                    pass
                                else:
                                    if _val:
                                        try:
                                            _ = base64url_to_long(_val)
                                        except ValueError:
                                            self._status = WARNING
                                            break

        return {}

CLASS_CACHE = {}


def factory(cid, classes=CLASS_CACHE):
    if len(classes) == 0:
        check.factory(cid, classes)
        for name, obj in inspect.getmembers(sys.modules[__name__]):
            if inspect.isclass(obj):
                try:
                    classes[obj.cid] = obj
                except AttributeError:
                    pass

    if cid in classes:
        return classes[cid]
    else:
        raise Unknown("Couldn't find the check: '%s'" % cid)


if __name__ == "__main__":
    chk = factory("check-http-response")
    print chk
