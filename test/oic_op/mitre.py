#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "http://rivers.richer.org:8080/openid-connect-server/"}

info["interaction"] = [
    {
        "matches": {
            "url": "https://www.example.com/authorization",
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"login": "diana", "password": "krall"}
        }
    }
]

print json.dumps(info)
