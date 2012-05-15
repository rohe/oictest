#!/usr/bin/env python

import json

info = {
    "features": {
        "registration":True,
        "discovery": True,
        "sessionmangement": False,
#        "key_export": {
#            "script": "../../script/static_provider.py",
#            "server": "http://localhost:8090/export",
#            "local_path": "./keys",
#            "sign": {
#                "alg":"rsa",
#                "create_if_missing": True,
#                "format": "jwk",
#                #"name": "jwk.json",
#            }
#        }
    },
    "client": {
        "redirect_uris": ["https://smultron.catalogix.se/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
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