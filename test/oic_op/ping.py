#!/usr/bin/env python
import json
from default import DEFAULT

__author__ = 'rohe0002'

info = DEFAULT.copy()

# NO key export
info["features"]["key_export"] = False
#del info["client"]["key_export_url"]

PI = "https://connect-interop.pinglabs.org:9031"

info["provider"] = {
    "dynamic": PI
#    "authorization_endpoint": "%s/as/authorization.oauth2" % PI,
#    "token_endpoint": "%s/as/token.oauth2" % PI,
#    "userinfo_endpoint": "%s/idp/userinfo.openid" % PI
}

info["interaction"] = [
    {
        "matches": {
            "url": "%s/as/authorization.oauth2" % PI,
            "title": "Sign On"
            },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {
                #"pf.ok":"Non-JS Sign In",
                "pf.username": "joe",
                "pf.pass": "test"}
        }
    },
    {
        "matches": {
            #"url": "%s/as/5ZS5x/resume/as/Dyom4/resume/as/authorization.ping" % PI,
            "title": "Information Access Approval"
        },
        "page-type": "user-consent",
        "control": {
            "type": "form",
            "set": {
                #"pf.oauth.authz.consent": "allow",
                "scope": "openid"}
        }
    }
]

print json.dumps(info)