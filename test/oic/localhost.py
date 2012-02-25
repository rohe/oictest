#!/usr/bin/env python

import json

info = {
    "client": {
        "redirect_uris": ["https://smultron.catalogix.se/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
        "register":True,
        },
    "provider": {
        "version": { "oauth": "2.0", "openid": "3.0"},
        "dynamic": "https://localhost:8088/",
        },

    "interaction": {
        "https://localhost:8088/authorization": ["select_form",
                {"login":"diana", "password": "krall"}],
    }
}

print json.dumps(info)