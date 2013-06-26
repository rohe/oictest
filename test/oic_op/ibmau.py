#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://vhost0026.dc1.co.us.compute.ihost.com/"}

info["interaction"] = [
    {
        "matches": {
            "url": "https://vhost0026.dc1.co.us.compute.ihost.com/FIM/sps/auth",
            "title": "Login Page"
        },
        "page-type": "login",
        "pick": {
            "action": "https://vhost0026.dc1.co.us.compute.ihost.com/pkmslogin.form"
        },
        "control": {
            "type": "form",
            "set": {"username": "roland", "password": "boarding"}
        }
    }, {
        "matches": {
            "url": "https://vhost0026.dc1.co.us.compute.ihost.com/FIM/sps/auth",
            "title": "OAuth 2.0 - Consent to Authorize"
        },
        "page-type": "user-consent",
        "pick": {
            "action": "/FIM/sps/connect/oauth20/authorize"
        },
        "control": {
            "type": "form",
        }
    }, {
        "matches": {
            "url": "https://vhost0026.dc1.co.us.compute.ihost.com/pkmslogin.form",
            "title": "PKMS Administration: Expired Password"
        },
        "page-type": "passwd update",
        "pick": {
            "action": "https://vhost0026.dc1.co.us.compute.ihost.com/pkmslogin.form"
        },
        "control": {
            "type": "form",
            "set": {"old": "boarding", "new1": "pass", "new2": "pass"}
        }
    }
]

print json.dumps(info)