__author__ = 'rohe0002'

import inspect
import sys
import traceback

from oic.oauth2.message import ErrorResponse
from oic.oic.message import IdToken

STATUS_CODES = {
    101: "Cannot open connection",
    102: "Connection refused",
    200: "OK",
    301: "Expiration time strange",
    400: "Other",
    401: "Required attribute missing in response",
    402: "Wrong content-type",
    500: "Process error",
    501: "Timeout, communication problem encountered",
    502: "OP error",
    503: "Information about endpoint missing",
    504: "Authentication method not supported",
    505: "Response type not supported",
    506: "Could not verify signature",
    507: "User interaction needed",
    508: "Missing redirect",
    509: "Parse error"
}

class Check():
    """ General test
    """
    id = "check"
    msg = "OK"
    
    def __init__(self):
        self._status = 200
        self._message = None
        self.content = None
        self.url = ""

    def _func(self, environ=None):
        return {}

    def __call__(self, environ=None, output=None):
        _stat =  self.response(**self._func(environ))
        output.append(_stat)
        return _stat

    def response(self, **kwargs):
        try:
            name = " ".join(self.__doc__.strip().split("\n"))
        except AttributeError:
            name = ""

        res = {
            "id": self.id,
            "status": self._status,
            "status_message": self.msg,
            "name": name
        }


        if self._message:
            res["message"] = self._message

        if kwargs:
            res.update(kwargs)

        return res

class Other(Check):
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
                               key=environ["client"].client_secret)
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
            if _response["content-type"] == "application/json":
                try:
                    err = ErrorResponse.set_json(_content, extended=True)
                    res["content"] = err.get_json(extended=True)
                except Exception:
                    res["content"] = _content
            else:
                res["content"] = _content
            res["url"] = environ["url"]
            res["http_status"] = _response.status
        else:
            res["url"] = environ["url"]

        return res

class CheckResponseType(Check):
    """
    Checks that the asked for response type are among the supported
    """
    id = "check-response-type"
    errcode = 505
    msg = "Response type not supported"

    def _func(self, environ):
        res = {}
        try:
            _sup = self.response_types_supported(environ["request_args"],
                                                 environ["provider_info"])
            if not _sup:
                self._status = self.errcode
        except KeyError:
            pass

        return res

    def response_types_supported(self, request_args, provider_info):
        try:
            rts = [set(s.split(" ")) for s in
                   provider_info["response_types_supported"]]
        except KeyError:
            rts = [{"code"}]

        try:
            val = request_args["response_type"]
            if isinstance(val, basestring):
                rt = {val}
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

    def _func(self, environ):
        try:
            _met = environ["args"]["authn_method"]
            _pi = environ["provider_info"]
            if _met not in _pi["token_endpoint_auth_types_supported"]:
                self._message = "Auth type not supported"
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
                if "application/json" in ctype:
                    return
                else:
                    self._status = self.errcode
                    self._message = "Wrong content type: %s" % ctype
            else: # has to be uuencoded
                if "application/x-www-form-urlencoded" in ctype:
                    return
                else:
                    self._status = self.errcode
                    self._message = "Wrong content type: %s" % ctype
        except KeyError:
            pass

        return res

class CheckProviderInfo(Check):
    """
    Check that the Provider Info is sound
    """
    id = "check-provider-info"
    errcode = 512
    msg = "Provider information error"

    def _func(self, environ=None):
        self._status = self.errcode
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
        self._status = self.errcode
        return {}

class CheckAuthorizationResponse(Check):
    """
    Verifies an Authorization response. This is additional constrains besides
    what is optional or required.
    """
    id = "check-authorization-response"
    errcode = 510

    def _func(self, environ=None):
        self._status = self.errcode
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

    def _func(self, environ=None):
        self._status = self.errcode
        return {"url": environ["url"]}

class MissingRedirect(Check):
    id = "missing-redirect"
    errcode = 508
    msg = "Expected redirect to the RP, got something else"

    def _func(self, environ=None):
        self._status = self.errcode
        return {"url": environ["url"]}

class ParseError(Check):
    id = "response-parse-error"
    errcode = 509
    errmsg = "Parse error"
    
    def _func(self, environ=None):
        self._status = self.errcode
        return {"url": environ["url"]}

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