#!/usr/bin/env python
import json
import sys

__author__ = 'roland'

tests = []
pros = [""]


RES = {
    " PASSED": 0,
    " WARNING": 1,
    " PARTIAL RESULT": 2,
    " FAILED": 3
}

PROF = {
    "code.config.static": "C.T.F",
    "code.config.dynamic": "C.T.T",
    "code.no-config.static": "C.F.F",
    "id_token.config.static": "I.T.F",
    "id_token.config.dynamic": "I.T.T",
    "id_token+token.config.static": "IT.T.F",
    "id_token+token.config.dynamic": "IT.T.T",
    "code+id_token.config.static": "CI.T.F",
    "code+id_token.config.dynamic": "CI.T.T",
    "code+id_token+token.config.static": "CIT.T.F",
    "code+id_token+token.config.dynamic": "CIT.T.T",
    "code+token.config.static": "CT.T.F",
    "code+token.config.dynamic": "CT.T.T"
}

ISSUERS = {
    u'https%3A%2F%2Fwww.paypal.com': "paypal",
    u'https%3A%2F%2Fstsadweb.one.microsoft.com%2Fadfs': "ADFS",
    u'https%3A%2F%2Fsts.windows.net%2Fb4ea3de6-839e-4ad1-ae78-c78e5c0cdc06%2F': "Azure",
    u'https%3A%2F%2Fseed.gluu.org': "gluu",
    u'https%3A%2F%2Foidcp.openrock.org%3A8043%2Fopenam%2Foauth2': "openrock",
    u'https%3A%2F%2Foidc-conformance-dev-ed.my.salesforce.com': "salesforce-dev",
    u'https%3A%2F%2Fmitreid.org%2F': "mitre",
    u'https%3A%2F%2Fgold.pinglabs.net': "Ping",
    u'https%3A%2F%2Fconnect.openid4.us': "NRI",
    u'https%3A%2F%2Fconnect.broch.io': "Luke",
    u'accounts.google.com': "google",
    u'https%3A%2F%2Fconnect.openid4.us%3A5443%2FphpOp': "NRI-phpop",
    u'https%3A%2F%2Faccounts.login00.idm.ver.sul.t-online.de': "DT-sul",
    u'https%3A%2F%2Faccounts.logint2.idm.toon.sul.t-online.de': "DT-tool",
    u'https%3A%2F%2Flogin.salesforce.com': "salesforce",
    "https%3A%2F%2Foictest.umdc.umu.se%3A8060%2F": "umu"
}

EXTRAS = [
    "OP-ClientAuth-PrivateJWT",
    "OP-ClientAuth-SecretJWT",
    "OP-Discovery-WebFinger",
    "OP-Discovery-WebFinger-Email",
    "OP-IDToken-ES256",
    "OP-IDToken-HS256",
    "OP-IDToken-SigEnc",
    "OP-Registration-Read",
    "OP-Registration-Sub-Differ",
    "OP-Registration-Sub-Pairwise",
    "OP-Registration-Sub-Public",
    "OP-Response-form_post",
    "OP-Rotation-RP-Enc",
    "OP-UserInfo-Enc",
    "OP-UserInfo-SigEnc",
    "OP-claims-Combined",
    "OP-claims-IDToken",
    "OP-claims-Split",
    "OP-claims-acr-essential",
    "OP-claims-acr-voluntary",
    "OP-claims-acr=1",
    "OP-claims-auth_time-essential",
    "OP-claims-essential+voluntary",
    "OP-claims-sub",
    "OP-claims-voluntary",
    "OP-redirect_uri-MissingOK",
    "OP-request-Sig",
    "OP-request-Support",
    "OP-request_uri-Enc",
    "OP-request_uri-SigEnc"
]


def do_profile(prof, tests, issuers, inp):
    tests.sort()
    mat = [[t] for t in tests]
    _item = [""]
    for _iss in issuers:
        col = []
        i = 0
        for test in tests:
            try:
                col.append(inp[_iss][prof][test])
            except KeyError:
                col.append("")
            else:
                i += 1

        if i:
            _item.append(_iss)
            for j in range(len(tests)):
                mat[j].append(col[j])

    f = open("%s.csv" % _prof, "w")

    _tmp = []
    for i in _item[1:]:
        try:
            _tmp.append(ISSUERS[i])
        except KeyError:
            _tmp.append(i)

    _i = [""]
    _i.extend(_tmp)
    f.write(";".join(_i))
    f.write("\n")
    for j in range(len(tests)):
        f.write(";".join(mat[j]))
        f.write("\n")
    f.close()


inp = json.load(open("p2.json"))
issuers = inp.keys()
p2t = json.load(open("profile2test.json"))

for _prof in PROF.keys():
    do_profile(_prof, p2t[PROF[_prof]], issuers, inp)