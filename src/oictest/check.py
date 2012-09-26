import json
from oic.jwt import b64d
from oic.oauth2.message import ErrorResponse
from oic.oic import message

__author__ = 'rohe0002'

import inspect
import sys
import traceback
import urlparse

from oic.oic.message import SCOPE2CLAIMS, IdToken, OpenIDSchema
#from oic.oic.message import
from oic.utils import time_util

INFORMATION = 0
OK = 1
WARNING = 2
ERROR = 3
CRITICAL = 4
INTERACTION = 5

STATUSCODE = ["INFORMATION", "OK", "WARNING", "ERROR", "CRITICAL",
              "INTERACTION"]


class Check():
    """ General test
    """
    id = "check"
    msg = "OK"

    def __init__(self, **kwargs):
        self._status = OK
        self._message = ""
        self.content = None
        self.url = ""
        self._kwargs = kwargs

    def _func(self, environ):
        return {}

    def __call__(self, environ=None, output=None):
        _stat =  self.response(**self._func(environ))
        output.append(_stat)
        return _stat

    def response(self, **kwargs):
        try:
            name = " ".join([s.strip() for s in self.__doc__.strip().split("\n")])
        except AttributeError:
            name = ""

        res = {
            "id": self.id,
            "status": self._status,
            "name": name
        }

        if self._message:
            res["message"] = self._message

        if kwargs:
            res.update(kwargs)

        return res

class ExpectedError(Check):
    pass

class CriticalError(Check):
    status = CRITICAL

class Error(Check):
    status = ERROR

class Other(CriticalError):
    """ Other error """
    msg  = "Other error"
    
class CmpIdtoken(Other):
    """
    Compares the JSON received as a CheckID response with my own
    interpretation of the IdToken.
    """
    id = "compare-idoken-received-with-check_id-response"

    def _func(self, environ):
        res = {}
        msg = None
        for msg in environ["item"]:
            if msg.type() == "AuthorizationResponse":
                break

        keys = environ["client"].keystore.get_keys("ver", owner=None)
        idt = IdToken().deserialize(msg["id_token"], "jwt", key=keys)
        if idt.to_dict() == environ["item"][-1].to_dict():
            pass
        else:
            self._status = self.status
            res["message"] = " ".join([
                    "My deserialization of the IDToken differs from what the",
                    "checkID response"])
        return res

class CheckHTTPResponse(CriticalError):
    """
    Checks that the HTTP response status is within the 200 or 300 range
    """
    id = "check-http-response"
    msg = "OP error"

    def _func(self, environ):
        _response = environ["response"]
        _content = environ["content"]

        res = {}
        if _response.status_code >= 400 :
            self._status = self.status
            self._message = self.msg
            if "application/json" in _response.headers["content-type"]:
                try:
                    err = ErrorResponse().deserialize(_content, "json")
                    self._message = err.to_json()
                except Exception:
                    res["content"] = _content
            else:
                res["content"] = _content
            res["url"] = environ["url"]
            res["http_status"] = _response.status_code
        else:
            # might still be an error message
            try:
                err = ErrorResponse().deserialize(_content, "json")
                err.verify()
                self._message = err.to_json()
                self._status = self.status
            except Exception:
                pass

            res["url"] = environ["url"]

        return res

class CheckErrorResponse(ExpectedError):
    """
    Checks that the HTTP response status is outside the 200 or 300 range
    or that an JSON encoded error message has been received
    """
    id = "check-error-response"
    msg = "OP error"

    def _func(self, environ):
        _response = environ["response"]
        _content = environ["content"]

        res = {}
        if _response.status_code >= 400 :
            content_type = _response.headers["content-type"]
            if content_type == None:
                res["content"] = _content
            elif "application/json" in content_type:
                try:
                    err = ErrorResponse().deserialize(_content, "json")
                    err.verify()
                    res["content"] = err.to_json()
                    res["temp"] = err
                except Exception:
                    res["content"] = _content
            else:
                res["content"] = _content
        else:
            # might still be an error message
            try:
                err = ErrorResponse().deserialize(_content, "json")
                err.verify()
                res["content"] = err.to_json()
            except Exception:
                self._message = "Expected error message"
                self._status = CRITICAL

            res["url"] = environ["url"]

        return res

class CheckRedirectErrorResponse(ExpectedError):
    """
    Checks that the HTTP response status is outside the 200 or 300 range
    or that an JSON encoded error message has been received
    """
    id = "check-redirect-error-response"
    msg = "OP error"

    def _func(self, environ):
        _response = environ["response"]

        res = {}
        try:
            query = _response.headers["location"].split("?")[1]
        except (KeyError, AttributeError):
            self._message = "Expected redirect"
            self._status = CRITICAL
            return res

        if _response.status_code == 302 :
            err = ErrorResponse().deserialize(query, "urlencoded")
            err.verify()
            res["content"] = err.to_json()
            environ["item"].append(err)
        else:
            self._message = "Expected error message"
            self._status = CRITICAL

        return res

class VerifyBadRequestResponse(ExpectedError):
    """
    Verifies that the OP returned a 400 Bad Request response containing a
    Error message.
    """
    id = "verify-bad-request-response"
    msg = "OP error"

    def _func(self, environ):
        _response = environ["response"]
        _content = environ["content"]
        res = {}
        if _response.status_code == 400 :
            err = ErrorResponse().deserialize(_content, "json")
            err.verify()
            res["content"] = err.to_json()
            environ["item"].append(err)
        else:
            self._message = "Expected a 400 error message"
            self._status = CRITICAL

        return res

class CheckSupported(CriticalError):
    """
    Checks that something asked for are supported
    """
    id = "check-support"
    msg = "X not supported"
    element = "X_supported"
    parameter = "X"

    def _func(self, environ):
        res = {}
        try:
            _sup = self._supported(environ["request_args"],
                                   environ["provider_info"])
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
            return True

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
    id = "check-response-type"
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
    id = "check-acr-support"
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
    id = "check-acr-support"
    msg = "ACR level not supported"
    element = "scopes_supported"
    parameter = "scope"

class CheckUserIdSupport(CheckSupported):
    """
    Checks that the asked for acr are among the supported
    """
    id = "check-userid-support"
    msg = "User_id type not supported"
    element = "user_id_types_supported"
    parameter = "user_id_type"

class CheckSignedUserInfoSupport(CheckSupported):
    """
    Checks that the asked for signature algorithms are among the supported
    """
    id = "check-signed-userinfo-support"
    msg = "Signed UserInfo not supported"
    element = "userinfo_algs_supported"
    parameter = "userinfo_signed_response_alg"

class CheckSignedIdTokenSupport(CheckSupported):
    """
    Checks that the asked for signature algorithms are among the supported
    """
    id = "check-signed-idtoken-support"
    msg = "Signed Id Token algorithm not supported"
    element = "id_token_algs_supported"
    parameter = "id_token_signed_response_alg"

class CheckTokenEndpointAuthType(CriticalError):
    """
    Checks that the token endpoint supports the used Auth type
    """
    id = "check-token-endpoint-auth-type"
    msg = "Auth type not supported"

    def _func(self, environ):
        try:
            _met = environ["args"]["authn_method"]
            _pi = environ["provider_info"]
            try:
                _sup = _pi["token_endpoint_auth_types_supported"]
            except KeyError:
                _sup = None

            if not _sup:
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
    id = "check_content_type_header"

    def _func(self, environ=None):
        res = {}
        _response = environ["response"]
        try:
            ctype = _response.headers["content-type"]
            if environ["response_spec"].type == "json":
                if not "application/json" in ctype:
                    self._status = self.status
                    self._message = "Wrong content type: %s" % ctype
            else: # has to be uuencoded
                if not "application/x-www-form-urlencoded" in ctype:
                    self._status = self.status
                    self._message = "Wrong content type: %s" % ctype
        except KeyError:
            pass

        return res

class CheckEndpoint(CriticalError):
    """ Checks that the necessary endpoint exists at a server """
    id = "check-endpoint"
    msg = "Endpoint missing"

    def _func(self, environ=None):
        cls = environ["request_spec"].request
        endpoint = environ["client"].request2endpoint[cls]
        try:
            assert endpoint in environ["provider_info"]
        except AssertionError:
            self._status = self.status
            self._message = "No '%s' registered" % endpoint

        return {}

class CheckProviderInfo(Error):
    """
    Check that the Provider Info is sound
    """
    id = "check-provider-info"
    msg = "Provider information error"

    def _func(self, environ=None):
        #self._status = self.status
        return {}

class CheckRegistrationResponse(Error):
    """
    Verifies an Registration response. This is additional constrains besides
    what is optional or required.
    """
    id = "check-registration-response"
    msg = "Registration response error"

    def _func(self, environ=None):
        #self._status = self.status
        return {}

class CheckAuthorizationResponse(Error):
    """
    Verifies an Authorization response. This is additional constrains besides
    what is optional or required.
    """
    id = "check-authorization-response"

    def _func(self, environ=None):
        #self._status = self.status
        return {}

class LoginRequired(Error):
    """
    Verifies an Authorization error response. The error should be
    login_required.
    """
    id = "login-required"

    def _func(self, environ=None):
        #self._status = self.status
        resp = environ["content"]
        try:
            assert resp.type() == "AuthorizationErrorResponse"
        except AssertionError:
            self._status = self.status
            self._message = "Expected authorization error response got %s" %(
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

class WrapException(CriticalError):
    """
    A runtime exception
    """
    id = "exception"
    msg = "Test tool exception"

    def _func(self, environ=None):
        self._status = self.status
        self._message = traceback.format_exception(*sys.exc_info())
        return {}

class InteractionNeeded(CriticalError):
    """
    A Webpage was displayed for which no known interaction is defined.
    """
    id = "interaction-needed"
    msg = "Unexpected page"

    def _func(self, environ=None):
        self._status = self.status
        self._message = None
        return {"url": environ["url"]}

class InteractionCheck(CriticalError):
    """
    A Webpage was displayed for which no known interaction is defined.
    """
    id = "interaction-check"

    def _func(self, environ=None):
        self._status = INTERACTION
        self._message = environ["content"]
        parts = urlparse.urlsplit(environ["url"])
        return {"url": "%s://%s%s" % parts[:3]}

class MissingRedirect(CriticalError):
    """ At this point in the flow a redirect back to the client was expected.
    """
    id = "missing-redirect"
    msg = "Expected redirect to the RP, got something else"

    def _func(self, environ=None):
        self._status = self.status
        return {"url": environ["url"]}

class Parse(CriticalError):
    """ Parsing the response """
    id = "response-parse"
    errmsg = "Parse error"
    
    def _func(self, environ=None):
        if "exception" in environ:
            self._status = self.status
            err = environ["exception"]
            self._message = "%s: %s" % (err.__class__.__name__, err)
        else:
            cname = environ["response_message"].type()
            if environ["response_type"] != cname:
                self._status = self.status
                self._message = ("Didn't get a response of the type I expected:",
                                " '%s' instead of '%s'" % (cname,
                                                environ["response_type"]))
        return {
            "response_type": environ["response_type"],
            "url": environ["url"]
        }

def get_authz_request(environ):
    for req, resp in environ["sequence"]:
        try:
            if req.request in ["OpenIDRequest", "AuthorizationRequest"]:
                return req
        except AttributeError:
            pass
    return None

class ScopeWithClaims(Error):
    """
    Verifies that the user information returned is consistent with
    what was asked for
    """
    id = "scope-claims"
    errmsg= "attributes received not matching claims"

    def _func(self, environ=None):
        userinfo_claims = {}

        req_args = get_authz_request(environ)._request_args
        try:
            _scopes = req_args["scope"]
        except KeyError:
            return {}

        for scope in _scopes:
            try:
                claims = dict([(name, None) for name in SCOPE2CLAIMS[scope]])
                userinfo_claims.update(claims)
            except KeyError:
                pass

        if "userinfo_claims" in req_args:
            _uic = req_args["userinfo_claims"]
            for key, val in _uic["claims"].items():
                userinfo_claims[key] = val

        # last item should be the UserInfoResponse
        resp = environ["response_message"]
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

class VerifyErrResponse(ExpectedError):
    """
    Verifies that the response received was an Error response
    """
    id = "verify-err-response"
    msg = "OP error"

    def _func(self, environ):
        res = {}

        response = environ["response"]
        if response.status_code == 302:
            _query = response.headers["location"].split("?")[1]
            try:
                err = ErrorResponse().deserialize(_query, "urlencoded")
                err.verify()
                res["temp"] = err
                res["message"] = err.to_dict()
            except Exception:
                self._message = "Faulty error message"
                self._status = ERROR
        else:
            self._message = "Expected a redirect with an error message"
            self._status = ERROR

        return res

REQUIRED = {"essential": True}
OPTIONAL = None

class verifyIDToken(CriticalError):
    """
    Verifies that the IDToken contains what it should
    """
    id = "verify-id-token"
    msg = "IDToken error"

    def _func(self, environ):
        done = False
        _vkeys = environ["client"].keystore.get_keys("ver", owner=None)

        idtoken_claims = {}
        req_args = get_authz_request(environ)._request_args
        if "idtoken_claims" in req_args:
            for key, val in req_args["idtoken_claims"]["claims"].items():
                idtoken_claims[key] = val
        #self._kwargs["claims"].items()

        for item in environ["item"]:
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

class Information(Check):
    status = INFORMATION

class ResponseInfo(Information):
    """Response information"""

    def _func(self, environ=None):
        self._status = self.status
        _msg = environ["content"]

        if isinstance(_msg, basestring):
            self._message = _msg
        else:
            self._message = _msg.to_dict()

        return {}

class RegistrationInfo(ResponseInfo):
    """Registration Response"""

class ProviderConfigurationInfo(ResponseInfo):
    """Provider Configuration Response"""

class UnpackAggregatedClaims(Error):
    id = "unpack-aggregated-claims"

    def _func(self, environ=None):
        resp = environ["response_message"]
        _client = environ["client"]

        try:
            _client.unpack_aggregated_claims(resp)
        except Exception, err:
            self._message = "Unable to unpack aggregated Claims: %s" % err
            self._status = self.status

        return {}

class ChangedSecret(Error):
    id = "changed-client-secret"

    def _func(self, environ=None):
        resp = environ["response_message"]
        old_sec = environ["request_args"]["client_secret"]
        _client = environ["client"]

        if old_sec == resp["client_secret"]:
            self._message = "Client secret was not changed"
            self._status = self.status

        return {}

class VerifyAccessTokenResponse(Error):
    id = "verify-access-token-response"
    section = "http://openid.bitbucket.org/openid-connect-messages-1_0.html#access_token_response"

    def _func(self, environ=None):
        resp = environ["response_message"]

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
        cis = environ["cis"][-1]
        if cis["grant_type"] == "authorization_code":
            req = get_authz_request(environ)
            if "openid" in req._request_args["scope"]:
                if "id_token" not in resp:
                    self._message = "IdToken has to be present"
                    self._status = self.status

        return {}

class SingleSignOn(Error):
    """ Verifies that Single-Sign-On actually works """
    id = "single-sign-on"

    def _func(self, environ):
        logins = 0

        for line in environ["trace"]:
            if ">> login <<" in line:
                logins += 1

        if logins > 1:
            self._message = " ".join(["Multiple authentications when only one",
                                      "was expected"])
            self._status = self.status

        return {}

class MultipleSignOn(Error):
    """ Verifies that multiple authentication was used in the flow """
    id = "multiple-sign-on"

    def _func(self, environ):
        logins = 0

        for line in environ["trace"]:
            if ">> login <<" in line:
                logins += 1

        if logins == 1:
            self._message = " ".join(["Only one authentication when more than",
                                      "one was expected"])
            self._status = self.status

        return {}

class VerifyRedirect_uriQueryComponent(Error):
    id = "verify-redirect_uri-query_component"

    def _func(self, environ):
        ruri = self._kwargs["redirect_uri"]
        part = urlparse.urlparse(ruri)
        qdict = urlparse.parse_qs(part.query)
        msg = environ["item"][-1]
        try:
            for key, vals in qdict.items():
                if len(vals) == 1:
                    assert msg[key] == vals[0]
        except AssertionError:
            self._message = "Query component that was part of the " \
                            "redirect_uri is missing"
            self._status = self.status

        return {}

class VerifyError(Error):
    id = "verify-error"

    def _func(self, environ):
        msg = environ["item"][-1]
        try:
            assert msg.type().endswith("ErrorResponse")
        except AssertionError:
            self._message = "Expected an error response"
            self._status = self.status
            return {}

        try:
            assert msg["error"] in self._kwargs["error"]
        except AssertionError:
            self._message = "Wrong type of error, got %s" % msg["error"]
            self._status = self.status

        return {}

class CheckKeys(CriticalError):
    """ Checks that the necessary keys are defined """
    id = "check-keys"
    msg = "Missing keys"

    def _func(self, environ=None):
        cls = environ["request_spec"].request
        client = environ["client"]
        # key type
        keys = client.keystore.get_sign_key("rsa")
        try:
            assert keys
        except AssertionError:
            self._status = self.status
            self._message = "No rsa key for signing registered"

        return {}

class VerifyPolicyURLs(Error):
    id = "policy_url_on_page"
    msg = "policy_url not on page"

    def _func(self, environ=None):
        login_page = environ["login"]
        regreq = environ["RegistrationRequest"]

        try:
            assert regreq["policy_url"] in login_page
        except AssertionError:
            self._status = self.status

        return {}

class VerifyLogoURLs(Error):
    id = "logo_url_on_page"
    msg = "logo_url not on page"

    def _func(self, environ=None):
        login_page = environ["login"]
        regreq = environ["RegistrationRequest"]

        try:
            assert regreq["logo_url"] in login_page
        except AssertionError:
            self._status = self.status

        return {}

class CheckUserID(Error):
    id = "different_user_id"
    msg = "user_id not changed between public and pairwise"

    def _func(self, environ=None):
        user_id = []
        for cls, msg in environ["responses"]:
            if cls == OpenIDSchema:
                _dict = json.loads(msg)
                user_id.append(_dict["user_id"])

        try:
            assert len(user_id) == 2
            assert user_id[0] != user_id[1]
        except AssertionError:
            self._status = self.status

        return {}

class VerifyUserInfo(Error):
    id = "verify-userinfo"
    msg = "Essential User info missing"

    def _func(self, environ):
        req_args = get_authz_request(environ)._request_args
        try:
            claims = req_args["userinfo_claims"]["claims"]
        except KeyError:
            claims = {}
        for scope in req_args["scope"]:
            for param in SCOPE2CLAIMS[scope]:
                claims[param] = REQUIRED

        response = environ["item"][-1]
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
    id = "asym-signed-userinfo"
    msg = "User info was not signed"

    def _func(self, environ):
        for cls, msg in environ["responses"]:
            if cls == message.OpenIDSchema:
                header = json.loads(b64d(str(msg.split(".")[0])))
                try:
                    assert header["alg"].startswith("RS")
                except AssertionError:
                    self._status = self.status
                break

class CheckSymSignedIdToken(Error):
    id = "sym-signed-idtoken"
    msg = "Incorrect signature type"

    def _func(self, environ):
        for cls, msg in environ["responses"]:
            if cls == message.AccessTokenResponse:
                _dict = json.loads(msg)
                jwt = _dict["id_token"]
                header = json.loads(b64d(str(jwt.split(".")[0])))
                try:
                    assert header["alg"].startswith("HS")
                except AssertionError:
                    self._status = self.status
                break

        return {}

def factory(id):
    for name, obj in inspect.getmembers(sys.modules[__name__]):
        if inspect.isclass(obj):
            try:
                if obj.id == id:
                    return obj
            except AttributeError:
                pass

    return None


if __name__ == "__main__":
    chk = factory("check-http-response")
    print chk