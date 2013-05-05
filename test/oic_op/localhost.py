#!/usr/bin/env python

import json

from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://localhost:8092/"}

info["interaction"] = [
    {
        "matches": {
            "url": "https://localhost:8092/authorization",
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"login": "diana", "password": "krall"}
        }
    }
]

print json.dumps(info)