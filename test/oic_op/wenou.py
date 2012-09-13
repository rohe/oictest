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
        "dynamic": "https://wenou-test.wenoit.org/",
        },
    "interaction": [
            {
            "matches": {
                "url": "https://wenou-test.wenoit.org/authorize",
                "content": "Email:"
            },
            "page-type": "login",
            "control": {
                "type": "form",
                "pick": { "control": {"id":"login_form", "value": "email"}},
                "set":{
                    "email":"roland@catalogix.se",
                    },
            }
        },
            {
            "matches": {
                "url":"https://wenou-test.wenoit.org/username-password/password"
            },
            "page-type": "login",
            "control": {
                "type": "form",
                "pick": {
                    "method": "POST",
                },
                "set": {
                    "password":"DentalCarev6"
                },
                #"click": "form.commit"
            }
        },{
            "matches": {
                "url": "https://wenou-test.wenoit.org/oauth/authorize",
                "content": "Or enter another email:"
            },
            "page-type": "login",
            "control": {
                "type": "form",
                #                "set": {
                #                    "email":"roland@catalogix.se",
                #                    },
                #"click": "form.commit"
            }
        },
    ]
}

print json.dumps(info)