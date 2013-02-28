import json

from jwkest import b64d
from jwkest import unpack
from jwkest.jwe import decrypt
from oic.oauth2.message import ErrorResponse
from oic.oic import AuthorizationResponse
from oic.oic import message
from rrtest import check, Unknown

from rrtest.check import Check, CONT_JSON, CONT_JWT
from rrtest.check import CriticalError
from rrtest.check import Other
from rrtest.check import Error
from rrtest.check import ResponseInfo
from rrtest.check import CRITICAL
from rrtest.check import ERROR
from rrtest.check import INTERACTION

__author__ = 'rohe0002'

import inspect
import sys
import urlparse

from oic.oic.message import SCOPE2CLAIMS
from oic.oic.message import IdToken
from oic.oic.message import OpenIDSchema
from oic.utils import time_util


class CmpIdtoken(Other):
    """
    Compares the JSON received as a CheckID response with my own
    interpretation of the IdToken.
    """
    cid = "compare-idoken-received-with-check_id-response"

    def _func(self, conv):
        res = {}
        instance = None
        for instance, msg in conv.protocol_response:
            if instance.type() == "AuthorizationResponse":
                break

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
                if err["error"] in ["consent_required", "interaction_required"]:
                    # This is OK
                    res["content"] = err.to_json()
                    conv.protocol_response.append((err, _query))
                else:
                    self._message = "Not an error I expected"
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

    def _func(self, conv):
        res = {}
        try:
            _sup = self._supported(conv.request_args,
                                   conv.provider_info)
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
                return False
            else:
                supported = self.default

        try:
            required = request_args[self.parameter]
            if isinstance(required, basestring):
                if required in supported:
                    return True
            else:
                for value in required:
                    if value in supported:
                        return True
            return False
        except KeyError:
            pass

        return True


class CheckResponseType(CheckSupported):
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
            supported = [set(["code"])]

        try:
            val = request_args["response_type"]
            if isinstance(val, basestring):
                rt = set([val])
            else:
                rt = set(val)
            for sup in supported:
                if sup == rt:
                    return True
            return False
        except KeyError:
            pass

        return True


class CheckAcrSupport(CheckSupported):
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


class CheckScopeSupport(CheckSupported):
    """
    Checks that the asked for acr are among the supported
    """
    cid = "check-acr-support"
    msg = "ACR level not supported"
    element = "scopes_supported"
    parameter = "scope"


class CheckUserIdSupport(CheckSupported):
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


class CheckEncryptedUserInfoSupportALG(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-signed-userinfo-alg-support"
    msg = "Userinfo alg algorithm not supported"
    element = "userinfo_encryption_alg_values_supported"
    parameter = "userinfo_encrypted_response_alg"


class CheckEncryptedUserInfoSupportENC(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-signed-userinfo-enc-support"
    msg = "UserInfo enc algorithm not supported"
    element = "userinfo_encryption_enc_values_supported"
    parameter = "userinfo_encrypted_response_enc"


class CheckEncryptedIDTokenSupportALG(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-signed-idtoken-alg-support"
    msg = "Id Token alg algorithm not supported"
    element = "id_token_encryption_alg_values_supported"
    parameter = "id_token_encrypted_response_alg"


class CheckEncryptedIDTokenSupportENC(CheckSupported):
    """
    Checks that the asked for encryption algorithm are among the supported
    """
    cid = "check-signed-idtoken-enc-support"
    msg = "Id Token enc method not supported"
    element = "id_token_encryption_enc_values_supported"
    parameter = "id_token_encrypted_response_enc"


class CheckTokenEndpointAuthType(CriticalError):
    """
    Checks that the token endpoint supports the used Auth type
    """
    cid = "check-token-endpoint-auth-type"
    msg = "Auth type not supported"

    def _func(self, conv):
        try:
            _req = conv.request_spec
            if _req.request == "RegistrationRequest":
                _met = conv.request_args["token_endpoint_auth_type"]
            else:
                _met = conv.args["authn_method"]
            _pi = conv.provider_info

            try:
                _sup = _pi["token_endpoint_auth_types_supported"]
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
        cls = conv.request_spec.request
        endpoint = conv.client.request2endpoint[cls]
        try:
            assert endpoint in conv.provider_info
        except AssertionError:
            self._status = self.status
            self._message = "No '%s' registered" % endpoint

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

        # last item should be the UserInfoResponse
        resp = conv.response_message
        if userinfo_claims:
            for key, restr in userinfo_claims.items():
                if key in resp:
                    pass
                else:
                    if restr == {"essential": True}:
                        self._status = self.status
                        self._message = "required attribute '%s' missing" % key
                        return {"returned claims": resp.keys()}

        for key in resp.keys():
            if key not in userinfo_claims:
                self._status = ERROR
                self._message = "Unexpected %s claim in response" % key
                return {"returned claims": resp.keys()}

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
        if "idtoken_claims" in req:
            for key, val in req["idtoken_claims"]["claims"].items():
                idtoken_claims[key] = val
                #self._kwargs["claims"].items()

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
                    assert key in idtoken
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
    cid = "verify-access-token-response"
    section = "http://openid.bitbucket.org/" + \
              "openid-connect-messages-1_0.html#access_token_response"

    def _func(self, conv=None):
        resp = conv.response_message

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
    cid = "policy_url_on_page"
    msg = "policy_url not on page"

    def _func(self, conv=None):
        login_page = conv.login_page
        regreq = conv.RegistrationRequest

        try:
            assert regreq["policy_url"] in login_page
        except AssertionError:
            self._status = self.status

        return {}


class VerifyLogoURLs(Error):
    cid = "logo_url_on_page"
    msg = "logo_url not on page"

    def _func(self, conv=None):
        login_page = conv.login_page
        regreq = conv.RegistrationRequest

        try:
            assert regreq["logo_url"] in login_page
        except AssertionError:
            self._status = self.status

        return {}


class CheckUserID(Error):
    cid = "different_sub"
    msg = "sub not changed between public and pairwise"

    def _func(self, conv=None):
        sub = []
        for instance, msg in conv.protocol_response:
            if isinstance(instance, OpenIDSchema):
                _dict = json.loads(msg)
                sub.append(_dict["sub"])

        try:
            assert len(sub) == 2
            assert sub[0] != sub[1]
        except AssertionError:
            self._status = self.status

        return {}


class VerifyUserInfo(Error):
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
    cid = "asym-signed-userinfo"
    msg = "User info was not signed"

    def _func(self, conv):
        for instance, msg in conv.protocol_response:
            if isinstance(instance, message.OpenIDSchema):
                header = json.loads(b64d(str(msg.split(".")[0])))
                try:
                    assert header["alg"].startswith("RS")
                except AssertionError:
                    self._status = self.status
                break

        return {}


class CheckSymSignedIdToken(Error):
    cid = "sym-signed-idtoken"
    msg = "Incorrect signature type"

    def _func(self, conv):
        for instance, msg in conv.protocol_response:
            if isinstance(instance, message.AccessTokenResponse):
                _dict = json.loads(msg)
                jwt = _dict["id_token"]
                header = json.loads(b64d(str(jwt.split(".")[0])))
                try:
                    assert header["alg"].startswith("HS")
                except AssertionError:
                    self._status = self.status
                break

        return {}


class CheckEncryptedUserInfo(Error):
    cid = "encrypted-userinfo"
    msg = "User info was not encrypted"

    def _func(self, conv):
        for instance, msg in conv.protocol_response:
            if isinstance(instance, message.OpenIDSchema):
                header = json.loads(b64d(str(msg.split(".")[0])))
                try:
                    assert header["alg"].startswith("RSA")
                except AssertionError:
                    self._status = self.status
                break

        return {}


class CheckEncryptedIDToken(Error):
    cid = "encrypted-idtoken"
    msg = "ID Token was not encrypted"

    def _func(self, conv):
        for instance, msg in conv.protocol_response:
            if isinstance(instance, message.AccessTokenResponse):
                _dic = json.loads(msg)
                header = json.loads(b64d(str(_dic["id_token"].split(".")[0])))
                try:
                    assert header["alg"].startswith("RSA")
                except AssertionError:
                    self._status = self.status
                break

        return {}


class CheckSignedEncryptedIDToken(Error):
    cid = "signed-encrypted-idtoken"
    msg = "ID Token was not signed and encrypted"

    def _func(self, conv):
        client = conv.client
        for instance, msg in conv.protocol_response:
            if isinstance(instance, message.AccessTokenResponse):
                _dic = json.loads(msg)
                header = json.loads(b64d(str(_dic["id_token"].split(".")[0])))
                try:
                    assert header["alg"].startswith("RSA")
                except AssertionError:
                    self._status = self.status
                    break

                dkeys = client.keyjar.get_decrypt_key(owner="")
                txt = decrypt(_dic["id_token"], dkeys, "private")
                _tmp = unpack(txt)[0]
                try:
                    assert _tmp["alg"] == "RS256"
                except AssertionError:
                    self._status = self.status
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
