import inspect
import sys
from uma import message
from rrtest.check import Error, get_protocol_response
from rrtest import Unknown
from oictest import check

__author__ = 'roland'

CLASS_CACHE = {}


class MatchResourceSet(Error):
    """
    Verify that the returned resource set is as expected
    """
    cid = "match-resource-set"
    msg = ""

    def _func(self, conv):
        res = get_protocol_response(conv, message.ResourceSetDescription)
        inst, txt = res[-1]
        rset = self._kwargs["rset"]

        # All but _id and _rev should be equal
        for key in message.ResourceSetDescription.c_param.keys():
            if key in ["_id", "_rev"]:
                continue
            try:
                assert rset[key] == inst[key]
            except AssertionError:
                self._message = "Not the resource set I expected"
                self._status = self.status
                break
            except KeyError:
                try:
                    assert key not in rset and key not in inst
                except AssertionError:
                    self._message = "Not the resource set I expected"
                    self._status = self.status
                    break

        return {}


def factory(cid, classes=CLASS_CACHE):
    if len(classes) == 0:
        for name, obj in inspect.getmembers(sys.modules[__name__]):
            if inspect.isclass(obj):
                try:
                    classes[obj.cid] = obj
                except AttributeError:
                    pass

    if cid in classes:
        return classes[cid]
    else:
        classes = {}
        return check.factory(cid, classes)
