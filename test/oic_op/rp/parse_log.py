#!/usr/bin/env python
import json
import os
import re
import sys
from jwkest.jwk import jwks_load
from oic.oauth2 import Message
from oic.oic.message import factory as oic_factory
from oic.oauth2.message import factory as oauth2_factory
from oic.oic.message import OpenIDSchema
from rrtest import Trace

__author__ = 'roland'

DIV = "============================================================"
SENT = re.compile("^\d+\.\d+ --> ([A-Z]+): (.*)")
RECV = re.compile("^\d+\.\d+ <-- ([A-Z]+): (.*)")
QUER = re.compile("^\d+\.\d+ <-- (.*)")
DATA = re.compile("^\d+\.\d+ ([a-zA-Z]+): {")
TAG = re.compile("^\d+\.\d+ (.*)")
END = re.compile("^\d+\.\d+ ==== END ====")
HEAD = re.compile("^\d+\.\d+ [-]+ ([a-zA-Z]+) [-]+")

PATTERN = {
    "sent": SENT,
    "recv": RECV,
    "data": DATA,
    "tag": TAG,
    "end": END,
    "head": HEAD,
    "quer": QUER
}

ORDER = ["head", "end", "sent", "recv", "quer", "data", "tag"]


def header(lines, index, end):
    res = {}
    while index < end:
        line = lines[index]

        if line == DIV:
            break

        try:
            (key, val) = line.split(": ", 1)
        except ValueError:
            pass
        else:
            res[key] = val

        index += 1

    return index, res


def trace_output(lines, index, end):
    cont = False
    seq = []
    _cls = None
    _data = []
    _sent = {}
    _recv = {}
    phase = ""
    while index < end:
        line = lines[index]

        if cont:
            if line == "}":
                _data.append(line)
                cont = False
                _args = json.loads("".join(_data))
                if _cls == "JWKS":
                    try:
                        _inst = jwks_load("".join(_data))
                    except TypeError:
                        pass
                elif _cls == "UserInfo":
                    _int = Message(**_args)
                    try:
                        _inst = OpenIDSchema(**_int["claims"])
                    except KeyError:
                        _inst = OpenIDSchema(**_args)
                    else:
                        try:
                            _inst.jwe_header = _int["jwe header parameters"]
                        except KeyError:
                            pass
                        try:
                            _inst.jws_header = _int["jws header parameters"]
                        except KeyError:
                            pass
                else:
                    try:
                        _inst = oic_factory(_cls)(**_args)
                    except KeyError:
                        _inst = oauth2_factory(_cls)(**args)
                seq.append((_cls, _inst))
            else:
                _data.append(line)
            index += 1
            continue

        if line == DIV:
            break
        elif line == "Trace output" or line == "":
            pass
        else:
            for phase in ORDER:
                m = PATTERN[phase].match(line)
                if m:
                    if phase == "head":
                        seq.append(m.groups()[0])
                    elif phase == "sent":
                        key, val = m.groups()
                        _sent[key] = val
                    elif phase == "recv":
                        key, val = m.groups()
                        _recv[key] = val
                    elif phase == "quer":
                        _recv["QUERY"] = m.groups()[0]
                        phase = "recv"
                    elif phase == "data":
                        m = DATA.match(line)
                        cont = True
                        _cls = m.groups()[0]
                        _data = ['{']
                    elif phase == "tag":
                        seq.append(("info", m.groups()[0]))

                    if phase in ["head", "data", "end"]:
                        if _sent:
                            seq.append(("sent", _sent))
                            _sent = {}
                        if _recv:
                            seq.append(("recv", _recv))
                            _recv = {}

                    break

        if phase == "end":
            break
        index += 1

    return index, seq

# __RegistrationRequest:post__
REQ = re.compile("^__([A-Za-z ]+):([A-Za-z]*|)__")
#  [check]
CHK = re.compile("^\[([a-z-]+)\]$")
#  	status: INFORMATION
INF = re.compile("^\\t([a-z]+): (.*)$")

TEST_PATTERN = {
    "req": REQ,
    "chk": CHK,
    "inf": INF,
}

TEST_ORDER = ["req", "chk", "inf"]


def test_output(lines, index, end):
    seq = []
    _chk = {}
    while index < end:
        line = lines[index]

        if line == DIV:
            break
        elif line == "Test output" or line == "":
            pass
        else:
            for phase in TEST_ORDER:
                m = TEST_PATTERN[phase].match(line)
                if m:
                    if phase == "req":
                        if _chk:
                            seq.append(_chk)
                            _chk = {}
                        seq.append(m.groups()[0])
                    elif phase == "chk":
                        if _chk:
                            seq.append(_chk)
                            _chk = {}
                        seq.append(m.groups()[0])
                    elif phase == "inf":
                        key, val = m.groups()
                        _chk[key] = val

                    break
        index += 1
    return index, seq


def result(lines, index, end):
    res = []
    while index < end:
        line = lines[index]

        if line.startswith("RESULT"):
            res.append(line.split(":")[1])

        index += 1

    return res


def div(lines, index, end):
    while index < end:
        line = lines[index]

        if line == DIV:
            break
        elif line == "Test output" or line == "":
            pass
        else:
            index -= 1
            break

        index += 1

    return index


def do_file(filename):
    lines = open(filename).read().split("\n")
    end = len(lines)

    index, headers = header(lines, 0, end)
    index, trace = trace_output(lines, index+1, end)
    index = div(lines, index+1, end)
    index, test = test_output(lines, index+1, end)
    _result = result(lines, index+1, end)

    return headers, trace, test, _result


def do_dir(dirname):
    res = {}
    for item in os.listdir(dirname):
        if item.startswith("."):
            continue

        fn = os.path.join(dirname, item)

        if os.path.isfile(fn):
            if item.startswith("OP-"):
                try:
                    headers, trace, test, test_result = do_file(fn)
                except IOError:
                    continue
                try:
                    _ = headers["Timestamp"]
                except KeyError:
                    pass
                else:
                    try:
                        res[item] = test_result[0]
                    except IndexError:
                        pass
        elif os.path.isdir(fn):
            v = do_dir(fn)
            if v:
                res[item] = v

    return res


def normalize(a):
    pa = a.split(".")
    if pa[3]:
        v = pa[3].split("+")
        v.sort()
        pa[3] = "+".join(v)
    return ".".join(pa)


def lcmp(a, b, inv=True):
    if inv:
        x = -1
        y = 1
    else:
        x = 1
        y = -1

    pa = a.split("+")
    pb = b.split("+")
    na = len(pa)
    nb = len(pb)

    if na == 0:
        return x
    elif nb == 0:
        return y

    for i in range(0, 2):
        if na == i:
            return x
        elif nb == i:
            return y

        if pa[i] == pb[i]:
            continue
        else:
            return cmp(pa[i], pb[i])
    return 0


PRIMO = ["", "no-config", "static"]


def prof_sort(a, b):
    if a == b:
        return 0

    pa = a.split(".")
    pb = b.split(".")

    if pa[0] != pb[0]:
        return lcmp(pa[0], pb[0])

    for i in [1, 2]:
        if pa[i] == pb[i]:
            continue
        else:
            if pa[i] == PRIMO[i]:
                return -1
            else:
                return 1

    return lcmp(pa[3], pb[3])


def profiles(res):
    profs = []
    for info in res.values():
        for prof in info.keys():
            if prof.endswith(".extras"):
                prof = prof[:-7]
            p = normalize(prof)
            if p not in profs:
                profs.append(p)
    profs.sort(prof_sort)
    return profs


def tests(res):
    all = []
    for iss, info in res.items():
        for prof, tests in info.items():
            for testname, val in tests.items():
                if testname not in all:
                    all.append(testname)
    all.sort()
    return all


if __name__ == "__main__":
    import argparse
    import importlib
    from oictest.base import Conversation
    from oictest.check import factory as check_factory
    from oictest.oidcrp import Client
    from oic.oic.message import factory as message_factory

    parser = argparse.ArgumentParser()
    parser.add_argument('-l', dest='log')
    parser.add_argument('-d', dest='dir')
    parser.add_argument('-c', dest="config")
    parser.add_argument('-D', dest="rec", action='store_true')
    args = parser.parse_args()

    if args.config:
        sys.path.insert(0, ".")
        CONF = importlib.import_module(args.config)
        conv = Conversation(Client, CONF.CLIENT, Trace(), None,
                            message_factory, check_factory=check_factory)

    if args.log:
        headers, trace, test, test_result = do_file(args.log)
        print headers["Timestamp"], test_result[0]

    if args.dir:
        print do_dir(args.dir)

    if args.rec:
        mat = {}
        res = do_dir(".")
        print json.dumps(res)

        # prof = profiles(res)
        # testid = tests(res)
        #
        # for t in testid:
        #     mat[t] = [[0, 0, 0] for i in range(0, len(prof))]
        #
        # for iss, info in res.items():
        #     for i in range(0, len(prof)):
        #         try:
        #             d = info[prof[i]]
        #         except KeyError:
        #             pass
        #         else:
        #             for j in range(0, len(testid)):
        #                 tid = testid[j]
        #                 try:
        #                     r = d[tid]
        #                 except KeyError:
        #                     pass
        #                 else:
        #                     if r == " PASSED":
        #                         mat[tid][i][0] += 1
        #                     elif r == " WARNING":
        #                         mat[tid][i][1] += 1
        #                     elif r == " FAILED":
        #                         mat[tid][i][2] += 1
        #
        # print json.dumps(mat)