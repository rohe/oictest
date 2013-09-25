#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://mitreid.org/"}

info["interaction"] = [
    {
        "matches": {
            "url": "https://mitreid.org",
        },
        "page-type": "user-consent",
        "control": {
            "type": "form",
        }
    },
    {
        "matches": {
            "url": "https://mitreid.org/login",
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"j_username": "user", "j_password": "password"}
        }
    }
]

print json.dumps(info)
