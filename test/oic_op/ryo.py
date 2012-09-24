#!/usr/bin/env python

import json

from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://openidconnect.info/"}

info["interaction"] = [
    {
        "matches": {
            "url": "https://openidconnect.info/account/login"
        },
        "page-type": "login",
        "control": {
            "type": "link",
            "path": "/account/fake"
        }
    }, {
        "matches": {
            "url": "https://openidconnect.info/connect/consent"
        },
        "page-type": "user-consent",
        "control": {
            "type": "form"
        }
    }
]

print json.dumps(info)