#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://mitreid.org/"}

info["interaction"] = [
    {
        "matches": {
            "url": "https://mitreid.org/login",
            "title": "MIT KIT Demo Server",
            "content": "Approve New Site"
        },
        "page-type": "user-consent",
        "control": {
            "type": "form",
        }
    },
    {
        "matches": {
            "url": "https://mitreid.org/authorize",
            "title": "MIT KIT Demo Server - Approve Access",
            "content": "Approve New Site"
        },
        "page-type": "user-consent",
        "control": {
            "type": "form",
        }
    },
    {
        "matches": {
            "url": "https://mitreid.org/login",
            "content": "Login with Username and Password"
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"j_username": "admin", "j_password": "password"}
        }
    }
]

print json.dumps(info)
