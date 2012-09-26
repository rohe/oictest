#!/usr/bin/env python

import json

from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://wenou-test.wenoit.org/"}

info["interaction"] = [
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
    },{
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

print json.dumps(info)