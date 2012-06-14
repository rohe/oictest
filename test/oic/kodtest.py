#!/usr/bin/env python

import json

info = {
    "versions": { "oauth": "2.0", "openid": "3.0"},
    "features": {
        "registration":True,
        "discovery": True,
        "session_management": False,
        "key_export": True
    },
    "client": {
        "redirect_uris": ["https://%s/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
        "key_export_url": "http://%s:8090/export"
    },
    "provider": {
        "dynamic": "https://www.kodtest.se:8088/",
    },
    "interaction": [
        {
            "matches": {
                "url": "https://www.kodtest.se:8088/authorization",
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