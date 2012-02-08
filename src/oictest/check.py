
__author__ = 'rohe0002'

import inspect
import sys
import traceback

from oic.oauth2.message import ErrorResponse
from oic.oic.message import IdToken
from oic.oic.message import SCOPE2CLAIMS
from oic.oic.message import AuthorizationErrorResponse
from oic.utils import time_util

#STATUS_CODES = {
#    101: "Cannot open connection",
#    102: "Connection refused",
#    200: "OK",
#    301: "Expiration time strange",
#    400: "Other",
#    401: "Required attribute missing in response",
#    402: "Wrong content-type",
#    500: "Process error",
#    501: "Timeout, communication problem encountered",
#    502: "OP error",
#    503: "Information about endpoint missing",
#    504: "Authentication method not supported",
#    505: "Response type not supported",
#    506: "Could not verify signature",
#    507: "User interaction needed",
#    508: "Missing redirect",
#    509: "Parse error"
#}

class Check():
    """ General test
    """
    id = "check"
    msg = "OK"
    
    def __init__(self, **kwargs):
        self._status = 200
        self._message = ""
        self.content = None
        self.url = ""
        self._kwargs = kwargs

    def _func(self, environ=None):
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

class Other(Check):
    """ Other error """
    errcode = 400
    msg  = "Other error"
    
class CmpIdtoken(Other):
    """
    Compares the JSON received as a CheckID response with my own
    interpretation of the IdToken.
    """
    id = "compare-idoken-received-with-check_id-response"

    def _func(self, environ):
        res = {}
        idt = IdToken.from_jwt(environ["item"][0].id_token,
                               key=environ["client"].verify_key)
        if idt.dictionary() == environ["item"][-1].dictionary():
            pass
        else:
            self._status = self.errcode
            res["message"] = (
                "My deserialization of the IDToken differs from what the ",
                "checkID response")
        return res

class CheckHTTPResponse(Check):
    """
    Checks that the HTTP response status is within the 200 or 300 range
    """
    id = "check-http-response"
    errcode = 502
    msg = "OP error"

    def _func(self, environ):
        _response = environ["response"]
        _content = environ["content"]

        res = {}
        if _response.status >= 400 :
            self._status = self.errcode
            self._message = self.msg
            if "application/json" in _response["content-type"]:
                try:
                    err = ErrorResponse.set_json(_content, extended=True)
                    self._message = err.get_json(extended=True)
                except Exception:
                    res["content"] = _content
            else:
                res["content"] = _content
            res["url"] = environ["url"]
            res["http_status"] = _response.status
        else:
            # might still be an error message
            try:
                err = ErrorResponse.set_json(_content, extended=True)
                err.verify()
                self._message = err.get_json(extended=True)
                self._status = self.errcode
            except Exception:
                pass

            res["url"] = environ["url"]

        return res

class CheckResponseType(Check):
    """
    Checks that the asked for response type are among the supported
    """
    id = "check-response-type"
    errcode = 504
    msg = "Response type not supported"

    def _func(self, environ):
        res = {}
        try:
            _sup = self.response_types_supported(environ["request_args"],
                                                 environ["provider_info"])
            if not _sup:
                self._status = self.errcode
                self._message = self.msg
        except KeyError:
            pass

        return res

    def response_types_supported(self, request_args, provider_info):
        try:
            rts = [set(s.split(" ")) for s in
                   provider_info["response_types_supported"]]
        except KeyError:
            rts = [{"code",}]

        try:
            val = request_args["response_type"]
            if isinstance(val, basestring):
                rt = {val,}
            else:
                rt = set(val)
            for sup in rts:
                if sup == rt:
                    return True
            return False
        except KeyError:
            pass

        return True

class CheckTokenEndpointAuthType(Check):
    """
    Checks that the token endpoint supports the used Auth type
    """
    id = "check-token-endpoint-auth-type"
    errcode = 504
    msg = "Auth type not supported"

    def _func(self, environ):
        try:
            _met = environ["args"]["authn_method"]
            _pi = environ["provider_info"]
            if _met not in _pi["token_endpoint_auth_types_supported"]:
                self._message = self.msg
                self._status = self.errcode
        except KeyError:
            pass

        return {}

class CheckContentTypeHeader(Check):
    """
    Verify that the content-type header is what it should be.
    """
    id = "check_content_type_header"
    errcode = 402

    def _func(self, environ=None):
        res = {}
        _response = environ["response"]
        try:
            ctype = _response["content-type"]
            if environ["response_spec"]["type"] == "json":
                if not "application/json" in ctype:
                    self._status = self.errcode
                    self._message = "Wrong content type: %s" % ctype
            else: # has to be uuencoded
                if not "application/x-www-form-urlencoded" in ctype:
                    self._status = self.errcode
                    self._message = "Wrong content type: %s" % ctype
        except KeyError:
            pass

        return res

class CheckEndpoint(Check):
    """ Checks that the necessary endpoint exists at a server """
    id = "check-endpoint"
    errcode = 504
    msg = "Endpoint missing"

    def _func(self, environ=None):
        cls = environ["request_spec"]["request"]
        endpoint = environ["client"].request2endpoint[cls]
        try:
            assert endpoint in environ["provider_info"]
        except AssertionError:
            self._status = self.errcode
            self._message = "No '%s' registered" % endpoint

        return {}

class CheckProviderInfo(Check):
    """
    Check that the Provider Info is sound
    """
    id = "check-provider-info"
    errcode = 512
    msg = "Provider information error"

    def _func(self, environ=None):
        #self._status = self.errcode
        return {}

class CheckRegistrationResponse(Check):
    """
    Verifies an Registration response. This is additional constrains besides
    what is optional or required.
    """
    id = "check-registration-response"
    errcode = 511
    msg = "Registration response error"

    def _func(self, environ=None):
        #self._status = self.errcode
        return {}

class CheckAuthorizationResponse(Check):
    """
    Verifies an Authorization response. This is additional constrains besides
    what is optional or required.
    """
    id = "check-authorization-response"
    errcode = 510

    def _func(self, environ=None):
        #self._status = self.errcode
        return {}

class LoginRequired(Check):
    """
    Verifies an Authorization error response. The error should be
    login_required.
    """
    id = "login-required"
    errcode = 510

    def _func(self, environ=None):
        #self._status = self.errcode
        resp = environ["response"]
        try:
            assert isinstance(resp, AuthorizationErrorResponse)
        except AssertionError:
            self._status = self.errcode
            self._message = "Expected authorization error response got %s" %(
                                                        resp.__class__.__name__)

        try:
            assert resp.error == "login_required"
        except AssertionError:
            self._status = self.errcode
            self._message = "Wrong error code"

        return {}

class WrapException(Check):
    """
    A runtime exception
    """
    id = "exception"
    errcode = 500
    msg = "Test tool exception"

    def _func(self, environ=None):
        self._status = 500
        self._message = traceback.format_exception(*sys.exc_info())
        return {}

class InteractionNeeded(Check):
    """
    A Webpage was displayed for which no known interaction is defined.
    """
    id = "interaction-needed"
    errcode = 507
    msg = "Unknown error"

    def _func(self, environ=None):
        self._status = self.errcode
        self._message = None
        return {"url": environ["url"]}

class MissingRedirect(Check):
    """ At this point in the flow a redirect back to the client was expected.
    """
    id = "missing-redirect"
    errcode = 508
    msg = "Expected redirect to the RP, got something else"

    def _func(self, environ=None):
        self._status = self.errcode
        return {"url": environ["url"]}

class Parse(Check):
    """ Parsing the response """
    id = "response-parse"
    errcode = 509
    errmsg = "Parse error"
    
    def _func(self, environ=None):
        if "exception" in environ:
            self._status = self.errcode
            err = environ["exception"]
            self._message = "%s: %s" % (err.__class__.__name__, err)
        else:
            cname = environ["response"].__class__.__name__
            if environ["response_type"] != cname:
                self._status = self.errcode
                self._message = ("Didn't get a response of the type I expected:",
                                " '%s' instead of '%s'" % (cname,
                                                environ["response_type"]))
        return {
            "response_type": environ["response_type"],
            "url": environ["url"]
        }

class ScopeWithClaims(Check):
    """
    Verifies that the user infomation returned is consistent with
    what was asked for
    """
    id = "scope-claims"
    errcode=520
    errmsg= "attributes received not matching claims"

    def _func(self, environ=None):
        userinfo_claims = {}
        for scope in environ["request_args"]["scope"]:
            try:
                claims = dict([(name, {"optional":True}) for name in
                                                         SCOPE2CLAIMS[scope]])
                userinfo_claims.update(claims)
            except KeyError:
                pass

        if "userinfo_claims" in environ["request_args"]:
            _uic = environ["request_args"]["userinfo_claims"]
            for key, val in _uic["claims"].items():
                userinfo_claims[key] = val

        # last item should be the UserInfoResponse
        resp = environ["response"]
        if userinfo_claims:
            for key, restr in userinfo_claims.items():
                if key in resp:
                    pass
                else:
                    if restr == {"optional": True}:
                        pass
                    else:
                        self._status = self.errcode
                        self._message = self.errmsg
                        return {"claims": resp.keys()}

        return {}

class verifyErrResponse(Check):
    """
    Checks that the HTTP response status is within the 200 or 300 range
    """
    id = "verify-err-response"
    errcode = 502
    msg = "OP error"

    def _func(self, environ):
        _content = environ["content"]

        res = {}
        try:
            err = ErrorResponse.set_json(_content, extended=True)
            err.verify()
        except Exception:
            self._message = self.msg
            self._status = self.errcode

        res["url"] = environ["url"]

        return res

class verifyIDToken(Check):
    """
    Verifies that the IDToken contains what it should
    """
    id = "verify-id-token"
    errcode = 503
    msg = "IDToken error"

    def _func(self, environ):
        done = False
        _vkeys = environ["client"].recv_keys["verify"]
        for item in environ["item"]:
            if self._status == self.errcode or done:
                break

            try:
                _jwt = item.id_token
            except KeyError:
                continue

            idtoken = IdToken.set_jwt(_jwt, _vkeys)
            for key, val in self._kwargs["claims"].items():
                if key == "max_age":
                    if idtoken.exp > (time_util.time_sans_frac() + val):
                        self._status = self.errcode
                        self._message = "exp to far in the future"
                        break
                    else:
                        continue

                if val is None:
                    _val = getattr(idtoken, key)
                    if _val is None:
                        self._status = self.errcode
                        self._message = "'%s' was supposed to be there" % key
                        break
                elif val == {"optional":True}:
                    pass
                elif "values" in val:
                    _val = getattr(idtoken, key)
                    if isinstance(_val, basestring):
                        if _val not in val["values"]:
                            self._status = self.errcode
                            self._message = "Wrong value on '%s'" % key
                            break
                    elif isinstance(_val, int):
                        if _val not in val["values"]:
                            self._status = self.errcode
                            self._message = "Wrong value on '%s'" % key
                            break
                    else:
                        for sval in _val:
                            if sval in val["values"]:
                                continue
                        self._status = self.errcode
                        self._message = "Wrong value on '%s'" % key
                        break

            done = True

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