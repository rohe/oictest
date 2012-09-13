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
        "version": {
            "oauth": "2.0",
            "openid": "3.0"
        },
        "dynamic": "https://vhost0026.dc1.co.us.compute.ihost.com/",
    },
    "interaction":[
            {
            "matches" : {
                "url": "https://vhost0026.dc1.co.us.compute.ihost.com/FIM/sps/auth",
                "title": "Login Page"
            },
            "page-type": "login",
            "pick": {
                "action":"https://vhost0026.dc1.co.us.compute.ihost.com/pkmslogin.form"
            },
            "control": {
                "type": "form",
                "set": {"username":"roland","password": "password"}
            }
        },{
            "matches" : {
                "url": "https://vhost0026.dc1.co.us.compute.ihost.com/FIM/sps/auth",
                "title": "OAuth 2.0 - Consent to Authorize"
            },
            "page-type": "user-consent",
            "pick": {
                "action":"/FIM/sps/connect/oauth20/authorize"
            },
            "control": {
                "type": "form",
            }
        }
    ]
}

print json.dumps(info)