#!/usr/bin/env python

import json

info = {
    "features": {
        "registration":True,
        "discovery": True,
        "session_management": False,
        "key_export": True,
        "use_nonce": True
    },
    "client": {
        "redirect_uris": ["https://%s/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
        "key_export_url": "http://%s:8090/export"
    },
    "provider": {
        "version": { "oauth": "2.0", "openid": "3.0"},
        "dynamic": "https://localhost:8088/",
        },
    "interaction": [
            {
            "matches": {
                "url": "https://localhost:8088/authorization",
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