#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

HOST = "https://xenosmilus2.umdc.umu.se:8091/"

info["provider"] = {"dynamic": HOST}

info["interaction"] = [
    {
        "matches": {
            "url": "%sauthorization" % HOST,
            },
        "page-type": "login",
        "control": {
            "type": "form",
            "set": {"login": "diana", "password": "krall"}
        }
    }
]

print json.dumps(info)
