#!/usr/bin/env python

#"https://seed.gluu.org/oxauth/seam/resource/restv1/oxauth/register"

#https://seed.gluu.org/

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
        "dynamic": "https://seed.gluu.org/",
        },

    "interaction": {
        "https://seed.gluu.org/login.seam": ["select_form",
                {"loginForm:username":"diana", "loginForm:password": "krall"}],
        #        "https://connect-op.heroku.com/authorizations/new": ["select_form",
        #                {"_form_pick_": {"action": "/authorizations",
        #                                 "class": "approve"}}],
        #        "https://connect-op.heroku.com/authorizations",
    }
}

print json.dumps(info)