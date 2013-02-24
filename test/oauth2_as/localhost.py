#!/usr/bin/env python

__author__ = 'rolandh'

import json

BASE = "https://localhost:8092"

info = {
    "versions": {"oauth": "2.0"},
    "features": {
        "registration": False,
        "discovery": False,
        "session_management": False,
        "key_export": False,
        },
    "provider": {
        "endpoints": {
            "token_endpoint": "%s/token_endpoint" % BASE,
            "authorization_endpoint": '%s/authorization_endpoint' % BASE,
        }
    },
    "client": {
        "client_id": "1234567890",
        "client_secret": "SoonerOrLater",
        "redirect_uris": ["https://localhost:8091/"]
    },
    "interaction": [
        {
            "matches": {
                "url": "%s/authorization_endpoint" % BASE,
                },
            "page-type": "login",
            "control": {
                "type": "form",
                "set": {"login":"diana","password": "krall"}
            }
        }
    ]
}

print json.dumps(info)