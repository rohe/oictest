#!/usr/bin/env python
import sys
from subprocess import Popen
from subprocess import PIPE

__author__ = 'rohe0002'

LIST = [
    ("openid-code", None),
    ("openid-token", None),
    (
        "openid-token",
        "{'OpenIDRequest':{'request':{'response_type':['code','token']}}}"),
    (
        "openid-token",
        "{'OpenIDRequest':{'request':{'response_type':['code','id_token','token']}}}"
    ),
    (
        "openid-token",
        "{'OpenIDRequest':{'request':{'response_type':['id_token'])"
    ),
    (
        "openid-token",
        "{'OpenIDRequest':{'request':{'response_type':['id_token','token']}}}"
    ),
    ("openid-token-idtoken-check_id", None),
    ("openid-token-idtoken-userdata", None),
    (
        "openid-token-idtoken-userdata",
        "{'OpenIDRequest':{'request':{'scope':['openid','profile']}}}"
    ),
    (
        "openid-token-idtoken-userdata",
        "{'OpenIDRequest':{'request':{'scope':['openid','email']}}}"
    ),
    (
        "openid-token-idtoken-userdata",
        "{'OpenIDRequest':{'request':{'scope':['openid','address']}}}"
    ),
    ("openid-code-userdata", None),
    (
        "openid-code-userdata",
        "{'UserInfoRequest':{'kw':{'authn_method':'bearer_header'}}}"
    ),
    (
        "openid-token-idtoken-userdata",
        "{'OpenIDRequest':{'kw':{'userinfo_claims':{'name':null,'nickname':{'optional':true},'email':null,'verified':null,'picture':{'optional': true}}}}}"
    )
]

NO_PROBLEM = ("", "")
who = sys.argv[1]

output = NO_PROBLEM
iaction = flow = ""
for (flow, iaction) in LIST:
    p1 = Popen(["./%s.py" % who], stdout=PIPE)
    cmd2 = ["oicc.py", "-J", "-"]
    if iaction:
        cmd2.extend(['-I', iaction])
    cmd2.append(flow)

    p2 = Popen(cmd2, stdin=p1.stdout, stdout=PIPE, stderr=PIPE)
    output = p2.communicate()
    if output != NO_PROBLEM:
        break
    print "OK"

if output != NO_PROBLEM:
    print flow
    print iaction
    if output[0]:
        print output[0]
    if output[1]:
        print output[1]
