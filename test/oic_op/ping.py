#!/usr/bin/env python
import json
from default import DEFAULT

__author__ = 'rohe0002'

info = DEFAULT.copy()

# NO key export
info["features"]["key_export"] = False
del info["client"]["key_export_url"]

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
            "set": {"username":"joe","password": "test"}
        }
    }
]

print json.dumps(info)