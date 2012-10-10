#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://id.mitre.org/connect/"}

info["interaction"] =[
    {
        "matches": {
            "url": "https://www.example.com/authorization",
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"login":"diana","password": "krall"}
        }
    }
]

print json.dumps(info)
