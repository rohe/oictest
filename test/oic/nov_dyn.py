#!/usr/bin/env python

import json

info = {
    "client": {
        "redirect_uris": ["https://connect-rp.heroku.com"],
        "contact": ["nov@matake.jp"],
        "application_type": "web",
        "application_name": "Nov RP",
        "register": True
    },
    "provider": {
        "version": {
            "oauth": "2.0",
            "openid": "3.0"
        },
        "dynamic": "https://connect-op.heroku.com/"
    },
    "interaction": [{
        "matched":{
            "url": "https://connect-op.heroku.com/"
        },
        "page-type":"login",
        "control": {
            "type": "form",
            "action": "/connect/fake"
        }
        },{
        "https://connect-op.heroku.com/authorizations/new": [
            "select_form",
                {
                "_form_pick_": {
                    "action": "/authorizations",
                    "class": "approve"
                }
            }
        ]}
    ]
}

print json.dumps(info)