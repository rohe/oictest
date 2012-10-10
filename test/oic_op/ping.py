#!/usr/bin/env python
import json
from default import DEFAULT

__author__ = 'rohe0002'

info = DEFAULT.copy()

# NO key export
info["features"]["key_export"] = False
del info["client"]["key_export_url"]

PI = "https://connect-interop.pinglabs.org:9031"

info["provider"] = {"dynamic": PI}

info["interaction"] = [
    {
        "matches": {
            "url": "http://id-natnext.orange.fr/auth_user/bin/authNuser.cgi",
            },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"credential":"0692411424","pwd": "723CBP"}
        }
    }
]

print json.dumps(info)