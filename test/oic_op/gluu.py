#!/usr/bin/env python

import json

info = {
    "features": {
        "registration":True,
        "discovery": True,
        "session_management": False,
        "key_export": True,
        "sector_identifier_url": True
    },
    "client": {
        "redirect_uris": ["https://%s/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
        "key_export_url": "http://%s:8090/",
        },
    "provider": {
        "version": { "oauth": "2.0", "openid": "3.0"},
        "dynamic": "https://seed.gluu.org",
        },
    "interaction": [
            {
            "matches": {
                "url":"https://seed.gluu.org/oxauth/login.seam"
            },
            "page-type": "login",
            "control":{
                "type":"form",
                "set": {"loginForm:username": "mike",
                        "loginForm:password": "secret"}
            }
        },
        {
            "matches": {
                "url": "https://seed.gluu.org/oxauth/authorize.seam"
            },
            "page-type": "user-consent",
            "control": {
                "type": "form",
                "click": "authorizeForm:allowButton"
            }
        }
    ]
}

print json.dumps(info)