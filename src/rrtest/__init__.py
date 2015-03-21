import json
import time
import traceback
from oic.oauth2 import HTTP_ERROR
import requests
from subprocess import Popen, PIPE
import sys

__author__ = 'rolandh'


class RRTestError(Exception):
    pass


class FatalError(RRTestError):
    pass


class Break(RRTestError):
    pass


class HttpError(RRTestError):
    pass


class Unknown(RRTestError):
    pass


def jwt_to_dict(resp):
    _d = {"claims": resp.to_dict()}
    if resp.jws_header:
        _d["jws header parameters"] = resp.jws_header
    if resp.jwe_header:
        _d["jwe header parameters"] = resp.jwe_header
    return _d


class Trace(object):
    def __init__(self):
        self.trace = []
        self.start = time.time()

    def request(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f --> %s" % (delta, msg))

    def reply(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f <-- %s" % (delta, msg))

    def response(self, resp):
        delta = time.time() - self.start
        try:
            cl_name = resp.__class__.__name__
        except AttributeError:
            cl_name = ""

        if cl_name == "IdToken":
            txt = json.dumps({"id_token": jwt_to_dict(resp)},
                             sort_keys=True, indent=2, separators=(',', ': '))
            self.trace.append("%f %s: %s" % (delta, cl_name, txt))
        else:
            try:
                dat = resp.to_dict()
            except AttributeError:
                txt = resp
                self.trace.append("%f %s" % (delta, txt))
            else:
                if cl_name == "OpenIDSchema":
                    cl_name = "UserInfo"
                    if resp.jws_header or resp.jwe_header:
                        dat = jwt_to_dict(resp)
                elif "id_token" in dat:
                    dat["id_token"] = jwt_to_dict(resp["id_token"])

                txt = json.dumps(dat, sort_keys=True, indent=2,
                                 separators=(',', ': '))

                self.trace.append("%f %s: %s" % (delta, cl_name, txt))

    def info(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f %s" % (delta, msg))

    def error(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f [ERROR] %s" % (delta, msg))

    def warning(self, msg):
        delta = time.time() - self.start
        self.trace.append("%f [WARNING] %s" % (delta, msg))

    def __str__(self):
        return "\n". join([t.encode("utf-8", 'replace') for t in self.trace])

    def clear(self):
        self.trace = []

    def __getitem__(self, item):
        return self.trace[item]

    def next(self):
        for line in self.trace:
            yield line

    def lastline(self):
        return self.trace[-1]


def start_script(path, wdir="", *args):
    if not path.startswith("/"):
        popen_args = ["./" + path]
    else:
        popen_args = [path]

    popen_args.extend(args)
    if wdir:
        return Popen(popen_args, stdout=PIPE, stderr=PIPE, cwd=wdir)
    else:
        return Popen(popen_args, stdout=PIPE, stderr=PIPE)


def stop_script_by_name(name):
    import subprocess
    import signal
    import os

    p = subprocess.Popen(['ps', '-A'], stdout=subprocess.PIPE)
    out, err = p.communicate()

    for line in out.splitlines():
        if name in line:
            pid = int(line.split(None, 1)[0])
            os.kill(pid, signal.SIGKILL)


def stop_script_by_pid(pid):
    import signal
    import os

    os.kill(pid, signal.SIGKILL)


def get_page(url):
    resp = requests.get(url)
    if resp.status_code == 200:
        return resp.text
    else:
        raise HTTP_ERROR(resp.status)


def exception_trace(tag, exc, log=None):
    message = traceback.format_exception(*sys.exc_info())
    if log:
        log.error("[%s] ExcList: %s" % (tag, "".join(message),))
        log.error("[%s] Exception: %s" % (tag, exc))
    else:
        print >> sys.stderr, "[%s] ExcList: %s" % (tag, "".join(message),)
        try:
            print >> sys.stderr, "[%s] Exception: %s" % (tag, exc)
        except UnicodeEncodeError:
            print >> sys.stderr, "[%s] Exception: %s" % (
                tag, exc.message.encode("utf-8", "replace"))
