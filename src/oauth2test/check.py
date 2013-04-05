import json
from oic.oauth2 import ErrorResponse
from oic.oauth2 import MissingRequiredAttribute
from rrtest import check
from rrtest.check import CONT_JSON, CriticalError
from rrtest.check import ExpectedError
from rrtest.check import ERROR
from rrtest.check import CRITICAL
from rrtest.check import OK
from rrtest.check import Error

__author__ = 'rohe0002'

import inspect
import sys


class CheckAuthorizationResponse(Error):
    """
    Verifies an Authorization response. This is additional constrains besides
    what is optional or required.
    """
    cid = "check-authorization-response"

    def _func(self, conv):
        #self._status = self.status
        return {}


class VerifyAccessTokenResponse(Error):
    """
    Verifies Accesstoken response.
    """
    cid = "verify-access-token-response"

    def _func(self, conv):
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

    def _func(self, conv):
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


class CheckSecondCodeUsageErrorResponse(CheckErrorResponse):
    cid = "check_second_code_usage_error_response"

    def _func(self, conv):
        res = super(CheckSecondCodeUsageErrorResponse, self)._func(conv)

        expected_value = "invalid_grant"

        if OK == self._status:
            if expected_value != self.err['error']:
                self._status = CRITICAL
                self._message = ('The error parameter should be "%s"' %
                                 expected_value)

        return res


class CheckPresenceOfStateParameter(Error):
    """ Makes sure that the state-parameter is present and correct
    """
    cid = "check_presence_of_state_parameter"

    def _func(self, conv):
        response, content = conv.protocol_response[-1]
        if not "state" in response:
            self._status = self.status
            self._message = "State was missing from the authorization response"
        elif response["state"] != "afdsliLKJ253oiuffaslkj":
            self._status = self.status
            self._message = "State parameter was changed"
        return {}


class CheckErrorResponseForInvalidType(CheckErrorResponse):
    status = check.ERROR

    def _func(self, conv):
        res = super(CheckErrorResponseForInvalidType, self)._func(conv)

        expected_value = "unsupported_grant_type"

        if OK == self._status:
            if self.err["error"] != expected_value:
                self._status = self.status
                self._message = 'The error parameter should be "%s"' % expected_value

        return res



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
        return None


if __name__ == "__main__":
    chk = factory("check-http-response")
    print chk
