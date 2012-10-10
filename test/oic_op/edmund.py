#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://connect.openid4.us/"}

info["interaction"]= [
        {
            "matches": {
                "title": "connect.openid4.us OP"
            },
            "control": {
                "type": "form"
            },
            "page-type": "login"
        }, {
            "matches": {
                "title": "connect.openid4.us AX Confirm"
            },
            "control": {
                "type": "form",
                "pick": {
                    "control": {"id": "persona", "value": "Default"}
                }
            },
            "page-type": "user-consent"
        }
    ]

print json.dumps(info)