#!/usr/bin/env python

import json

info = {
    "features": {
        "registration":True,
        "discovery": True,
        "session_management": False,
        #"key_export": "http://%s:8090/export",
    },
    "client": {
        "redirect_uris": ["https://%s/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
    },
    "provider": {
        "version": { "oauth": "2.0", "openid": "3.0"},
        "issuer": "https://connect-op.heroku.com",
        "authorization_endpoint": "https://connect-op.heroku.com/authorizations/new",
        "token_endpoint": "https://connect-op.heroku.com/access_tokens",
        "userinfo_endpoint": "https://connect-op.heroku.com/user_info",
        "check_id_endpoint": "https://connect-op.heroku.com/id_token",
        "registration_endpoint": "https://connect-op.heroku.com/connect/client",
        "scopes_supported": ["openid", "profile", "email", "address", "phone"],
        "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "id_token token", "code id_token token"],
        "user_id_types_supported": ["public", "pairwise"],
        "id_token_algs_supported": ["RS256"],
        "x509_url": "https://connect-op.heroku.com/cert.pem"
    },
    "interaction": {
        "https://connect-op.heroku.com/": [
            "select_form", {
                "_form_pick_": {
                    "action": "/connect/fake"
                }
            }
        ],
        "https://connect-op.heroku.com/authorizations/new": [
            "select_form",
                {
                "_form_pick_": {
                    "action": "/authorizations",
                    "class": "approve"
                }
            }
        ]
    }
}

print json.dumps(info)