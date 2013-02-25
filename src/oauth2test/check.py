import json

from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import MissingRequiredAttribute

from rrtest.check import Check, CONT_JSON
from rrtest.check import CriticalError
from rrtest.check import Error
from rrtest.check import ExpectedError
from rrtest.check import OK
from rrtest.check import CRITICAL
from rrtest.check import ERROR
from rrtest.check import INFORMATION

__author__ = 'rohe0002'

import inspect
import sys


class CheckErrorResponse(ExpectedError):
    """
    Checks that the HTTP response status is outside the 200 or 300 range
    or that an JSON encoded error message has been received
    """
    cid = "check-error-response"
    msg = "OP error"

    def _func(self, conv):
        _response = conv.last_response
        _content = conv.last_content

        res = {}
        if _response.status_code >= 400:
            content_type = _response.headers["content-type"]
            if content_type is None:
                res["content"] = _content
            elif CONT_JSON in content_type:
                try:
                    err = ErrorResponse().deserialize(_content, "json")
                    err.verify()
                    res["content"] = err.to_json()
                    #res["temp"] = err
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

            res["url"] = conv.position

        return res


class CheckRedirectErrorResponse(ExpectedError):
    """
    Checks that the HTTP response status is outside the 200 or 300 range
    or that an JSON encoded error message has been received
    """
    cid = "check-redirect-error-response"
    msg = "OP error"

    def _func(self, conv):
        _response = conv.last_response

        res = {}
        try:
            _loc = _response.headers["location"]
            if "?" in _loc:
                query = _loc.split("?")[1]
            elif "#" in _loc:
                query = _loc.split("#")[1]
            else:  # ???
                self._message = "Expected redirect"
                self._status = CRITICAL
                return res
        except (KeyError, AttributeError):
            self._message = "Expected redirect"
            self._status = CRITICAL
            return res

        if _response.status_code == 302:
            err = ErrorResponse().deserialize(query, "urlencoded")
            try:
                err.verify()
                res["content"] = err.to_json()
                conv.protocol_response.append((err, query))
            except MissingRequiredAttribute:
                self._message = "Expected error message"
                self._status = CRITICAL
        else:
            self._message = "Expected error message"
            self._status = CRITICAL

        return res


class VerifyBadRequestResponse(ExpectedError):
    """
    Verifies that the OP returned a 400 Bad Request response containing a
    Error message.
    """
    cid = "verify-bad-request-response"
    msg = "OP error"

    def _func(self, conv):
        _response = conv.last_response
        _content = conv.last_content
        res = {}
        if _response.status_code == 400:
            err = ErrorResponse().deserialize(_content, "json")
            err.verify()
            res["content"] = err.to_json()
            conv.protocol_response.append((err, _content))
        else:
            self._message = "Expected a 400 error message"
            self._status = CRITICAL

        return res


class MissingRedirect(CriticalError):
    """ At this point in the flow a redirect back to the client was expected.
    """
    cid = "missing-redirect"
    msg = "Expected redirect to the RP, got something else"

    def _func(self, conv=None):
        self._status = self.status
        return {"url": conv.position}


class Parse(CriticalError):
    """ Parsing the response """
    cid = "response-parse"
    errmsg = "Parse error"

    def _func(self, conv=None):
        if conv.exception:
            self._status = self.status
            err = conv.exception
            self._message = "%s: %s" % (err.__class__.__name__, err)
        else:
            _rmsg = conv.response_message
            cname = _rmsg.type()
            if conv.response_type != cname:
                self._status = self.status
                self._message = (
                    "Didn't get a response of the type I expected:",
                    " '%s' instead of '%s', content:'%s'" % (
                        cname, conv.response_type, _rmsg))
        return {
            "response_type": conv.response_type,
            "url": conv.position
        }


class VerifyErrorResponse(ExpectedError):
    """
    Verifies that the response received was an Error response
    """
    cid = "verify-err-response"
    msg = "OP error"

    def _func(self, conv):
        res = {}

        response = conv.last_response
        if response.status_code == 302:
            _loc = response.headers["location"]
            if "?" in _loc:
                _query = _loc.split("?")[1]
            elif "#" in _loc:
                _query = _loc.split("#")[1]
            else:
                self._message = "Faulty error message"
                self._status = ERROR
                return

            try:
                err = ErrorResponse().deserialize(_query, "urlencoded")
                err.verify()
                #res["temp"] = err
                res["message"] = err.to_dict()
            except Exception:
                self._message = "Faulty error message"
                self._status = ERROR
        else:
            self._message = "Expected a redirect with an error message"
            self._status = ERROR

        return res


class Information(Check):
    status = INFORMATION


class ResponseInfo(Information):
    """Response information"""

    def _func(self, conv=None):
        self._status = self.status
        _msg = conv.last_content

        if isinstance(_msg, basestring):
            self._message = _msg
        else:
            self._message = _msg.to_dict()

        return {}


class VerifyError(Error):
    cid = "verify-error"

    def _func(self, conv):
        response = conv.last_response
        if response.status_code == 400:
            try:
                resp = json.loads(response.text)
                if "error" in resp:
                    return {}
            except Exception:
                pass

        item, msg = conv.protocol_response[-1]
        try:
            assert item.type().endswith("ErrorResponse")
        except AssertionError:
            self._message = "Expected an error response"
            self._status = self.status
            return {}

        try:
            assert item["error"] in self._kwargs["error"]
        except AssertionError:
            self._message = "Wrong type of error, got %s" % item["error"]
            self._status = self.status

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


class VerifyAccessTokenResponse(Error):
    cid = "verify-access-token-response"

    def _func(self, conv=None):
        resp = conv.response_message

        #This specification further constrains that only Bearer Tokens [OAuth
        # .Bearer] are issued at the Token Endpoint. The OAuth 2.0 response
        # parameter "token_type" MUST be set to "Bearer".
        if "token_type" in resp and resp["token_type"].lower() != "bearer":
            self._message = "token_type has to be 'Bearer'"
            self._status = self.status

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
                if CONT_JSON in ctype:
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


class_cache = {}
def factory(cid, classes=class_cache):
    if len(classes) == 0:
        for name, obj in inspect.getmembers(sys.modules[__name__]):
            if inspect.isclass(obj):
                try:
                    class_cache[obj.cid] = obj
                except AttributeError:
                    pass
    if cid in classes:
        return classes[cid]
    else:
        return None


if __name__ == "__main__":
    chk = factory("check-http-response")
    print chk
