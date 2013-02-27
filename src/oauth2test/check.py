import json

from oic.oauth2.message import ErrorResponse
from oic.oauth2.message import MissingRequiredAttribute

from rrtest.check import Check, CONT_JSON
from rrtest.check import CriticalError
from rrtest.check import CheckErrorResponse
from rrtest.check import CheckRedirectErrorResponse
from rrtest.check import Error
from rrtest.check import ExpectedError
from rrtest.check import MissingRedirect
from rrtest.check import Parse
from rrtest.check import ResponseInfo
from rrtest.check import VerifyErrorResponse
from rrtest.check import VerifyError
from rrtest.check import WrapException
from rrtest.check import OK
from rrtest.check import CRITICAL
from rrtest.check import ERROR
from rrtest.check import INFORMATION

__author__ = 'rohe0002'

import inspect
import sys


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
    """
    Verifies Accesstoken response.
    """
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
