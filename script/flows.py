#!/usr/bin/env python
__author__ = 'rohe0002'

import sys
import json
from subprocess import Popen
from subprocess import PIPE
from oictest.oic_operations import FLOWS

#    ("openid-code", None),
#    ("openid-code-token", None),
#    (
#        "openid-code-token",
#        "{'OpenIDRequest':{'request':{'response_type':['code','id_token']}}}"
#    ),
#    ("openid-code-userdata", None),
#    (
#        "openid-code-userdata",
#        "{'UserInfoRequest':{'kw':{'authn_method':'bearer_header'}}}"
#        ),
#    ("openid-code-check_id", None),
#    (
#        "openid-code-check_id",
#        "{'UserInfoRequest':{'kw':{'authn_method':'bearer_header'}}}"
#    ),
#    ("openid-token", None),
#    (
#        "openid-token",
#        "{'OpenIDRequest':{'request':{'response_type':['code','token']}}}"),
#    (
#        "openid-token",
#        "{'OpenIDRequest':{'request':{'response_type':['code','id_token','token']}}}"
#    ),
#    (
#        "openid-token",
#        "{'OpenIDRequest':{'request':{'response_type':['id_token']}}}"
#    ),
#    (
#        "openid-token",
#        "{'OpenIDRequest':{'request':{'response_type':['id_token','token']}}}"
#    ),
#    ("openid-token-idtoken-check_id", None),
#    ("openid-token-idtoken-userdata", None),
#    (
#        "openid-token-idtoken-userdata",
#        "{'OpenIDRequest':{'request':{'scope':['openid','profile']}}}"
#    ),
#    (
#        "openid-token-idtoken-userdata",
#        "{'OpenIDRequest':{'request':{'scope':['openid','email']}}}"
#    ),
#    (
#        "openid-token-idtoken-userdata",
#        "{'OpenIDRequest':{'request':{'scope':['openid','address']}}}"
#    ),

who = sys.argv[1]

def sorted_flows(flows):
    result = []
    remains = flows.keys()
    while remains:
        for flow in remains:
            spec = flows[flow]
            if "depends" in spec:
                flag = False
                for dep in spec["depends"]:
                    if dep in result:
                        flag = True
                    else:
                        flag = False
                        break

                if flag:
                    result.append(flow)
                    remains.remove(flow)
            else:
                result.append(flow)
                remains.remove(flow)

    return result

OICC = "/Users/rohe0002/code/oictest/test/oic/oicc.py"

for flow in sorted_flows(FLOWS):
    p1 = Popen(["./%s.py" % who], stdout=PIPE)
    cmd2 = [OICC, "-J", "-", flow]

    p2 = Popen(cmd2, stdin=p1.stdout, stdout=PIPE, stderr=PIPE)
    p_out = p2.stdout.read()
    print p_out
    output = json.loads(p_out)
    if output["status"] == "0":
        print "%s - OK" % flow
    else:
        print p_out
        p_err = p2.stderr.read()
        print p_err
