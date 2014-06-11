#!/usr/bin/env python

import json

from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://localhost:8092/"}

info["interaction"] = [
    {
        "matches": {
            "url": "https://localhost:8092/authorization",
            "title": "OpenID Connect provider example"
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"login": "diana", "password": "krall"}
        }
    },
    {
        "matches": {
            "url": "https://localhost:8092/authorization",
            "title": "Submit This Form"
        },
        "page-type": "other",
        "control": {
            "type": "form",
        }
    }
]

print json.dumps(info)