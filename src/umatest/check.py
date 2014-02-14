import json
from uma.message import RPTResponse
from oauth2test import check

__author__ = 'rohe0002'

import inspect
import sys
from rrtest.check import ResponseInfo, Error
from oic.oauth2.dynreg import ClientInfoResponse

CLASS_CACHE = {}


class RegistrationInfo(ResponseInfo):
    """
    Verifies an Registration response. This is additional constrains besides
    what is optional or required.
    """
    cid = "check-registration-response"
    msg = "Registration response error"

    def _func(self, conv=None):
        self._status = self.status
        _msg = conv.last_content

        if isinstance(_msg, basestring):
            self._message = _msg
        else:
            self._message = _msg.to_dict()

        return {}


class ProviderConfigurationInfo(ResponseInfo):
    """
    Verifies an provider info. This is additional constrains besides
    what is optional or required.
    """
    cid = "check-registration-response"
    msg = "Registration response error"

    def _func(self, conv=None):
        self._status = self.status
        _msg = conv.last_content

        if isinstance(_msg, basestring):
            self._message = _msg
        else:
            self._message = _msg.to_dict()

        return {}


class VerifyRPTResponse(Error):
    cid = "verify-rpt-response"
    msg = "Faulty RPT Response"

    def _func(self, conv):
        _instance = None
        for instance, msg in conv.protocol_response:
            if isinstance(instance, RPTResponse):
                _instance = instance
                break

        if not _instance:
            self._message = "Not a RPTResponse"
            self._status = self.status
        else:
            try:
                _instance.verify()
            except Exception:
                self._status = self.status

        return {}


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
