#!/usr/bin/env python

import json

info = {
    "client": {
        "redirect_uris": ["https://smultron.catalogix.se/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
        "register": True
    },
    "provider": {
        "version": {
            "oauth": "2.0",
            "openid": "3.0"
        },
        "dynamic": "https://openidconnect.info/"
    },
    "interaction": {
        "https://openidconnect.info/account/login": ["chose", {"path": "/account/fake"}],
        "https://openidconnect.info/connect/consent": ["select_form", {}]
    }
}

print json.dumps(info)