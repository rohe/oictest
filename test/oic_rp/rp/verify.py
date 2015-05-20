import traceback
from rrtest import Break, FatalError
from rrtest.check import STATUSCODE, ExpectedError
import sys

__author__ = 'roland'


class Verify(object):
    def __init__(self, check_factory, msg_factory, conv):
        self.check_factory = check_factory
        self.msg_factory = msg_factory
        self.trace = conv.trace
        self.test_output = []
        self.ignore_check = []
        self.exception = None
        self.conv = conv

    def check_severity(self, stat):
        if stat["status"] >= 4:
            self.trace.error("WHERE: %s" % stat["id"])
            self.trace.error("STATUS:%s" % STATUSCODE[stat["status"]])
            try:
                self.trace.error("HTTP STATUS: %s" % stat["http_status"])
            except KeyError:
                pass
            try:
                self.trace.error("INFO: %s" % (stat["message"],))
            except KeyError:
                pass

            if not stat["mti"]:
                raise Break(stat["message"])
            else:
                raise FatalError(stat["message"])

    def do_check(self, test, **kwargs):
        if isinstance(test, basestring):
            chk = self.check_factory(test)(**kwargs)
        else:
            chk = test(**kwargs)

        if chk.__class__.__name__ not in self.ignore_check:
            stat = chk(self.conv, self.test_output)
            self.check_severity(stat)

    def err_check(self, test, err=None, bryt=True):
        if err:
            self.exception = err
        chk = self.check_factory(test)()
        chk(self, self.test_output)
        if bryt:
            e = FatalError("%s" % err)
            e.trace = "".join(traceback.format_exception(*sys.exc_info()))
            raise e

    def test_sequence(self, sequence):
        if isinstance(sequence, dict):
            for test, kwargs in sequence.items():
                self.do_check(test, **kwargs)
        else:
            for test in sequence:
                if isinstance(test, tuple):
                    test, kwargs = test
                else:
                    kwargs = {}
                self.do_check(test, **kwargs)
                if test == ExpectedError:
                    return False
        return True
