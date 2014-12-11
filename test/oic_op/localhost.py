#!/usr/bin/env python

import json

from default import DEFAULT

info = DEFAULT.copy()

BASE = "https://localhost:8092"

info["provider"] = {"dynamic": "%s/" % BASE}

info["interaction"] = [
    {
        "matches": {
            "url": "%s/authorization" % BASE,
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
            "url": "%s/authorization" % BASE,
            "title": "Submit This Form"
        },
        "page-type": "other",
        "control": {
            "type": "form",
        }
    }
]

info["deviate"] = ["no_https_issuer"]
print json.dumps(info)