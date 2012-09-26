#!/usr/bin/env python

import json

BASE = "https://openidconnect.ebay.com/oreo"
from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://openidconnect.ebay.com/"}

info["interaction"]= [
    {
        "matches": {
            "url":"%s/primary-auth/dummy-signin.jsp" % BASE
        },
        "page-type": "login",
        "control":{
            "type":"form",
            "set": {"username": "test", "password": "password"}
        }
    },{
        "matches": {
            "url": "%s/consent/consent-pp-like.jsp" % BASE
        },
        "page-type": "user-consent",
        "control": {
            "type":"form"
        }
    },{
        "matches": {
            "url": "%s/consent/consent-plain.jsp" % BASE
        },
        "page-type": "user-consent",
        "control": {
            "type":"form"
        }
    }
]

print json.dumps(info)