#!/usr/bin/env python

import json

BASE = "https://openidconnect.ebay.com/oreo"

info = {
    "features": {
        "registration":True,
        "discovery": True,
        "session_management": False,
        "key_export": True,
        "sector_identifier_url": True,
        "use_nonce": True
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
        "dynamic": "https://openidconnect.ebay.com/",
        },
    "interaction": [
            {
            "matches": {
                "url":"%s/primary-auth/dummy-signin.jsp" % BASE
            },
            "page-type": "login",
            "control":{
                "type":"form",
                "set": {"username": "test", "password": "password"}
            }
        },
            {
            "matches": {
                "url": "%s/consent/consent-pp-like.jsp" % BASE
            },
            "page-type": "user-consent",
            "control": {
                "type":"form"
            }
        },
            {
            "matches": {
                "url": "%s/consent/consent-plain.jsp" % BASE
            },
            "page-type": "user-consent",
            "control": {
                "type":"form"
            }
        }
    ]
}

print json.dumps(info)