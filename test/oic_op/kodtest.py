#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://www.kodtest.se:8088/"}

info["interaction"] = [
    {
        "matches": {
            "url": "https://www.kodtest.se:8088/authorization",
        },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"login": "diana", "password": "krall"}
        }
    }
]

print json.dumps(info)