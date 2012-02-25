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
    "version": "3.0",
    "issuer": "https://connectop.heroku.com",
    "authorization_endpoint": "https://connectop.heroku.com/authorizations/new",
    "token_endpoint": "https://connectop.heroku.com/access_tokens",
    "userinfo_endpoint": "https://connectop.heroku.com/user_info",
    "check_id_endpoint": "https://connectop.heroku.com/id_token",
    "registration_endpoint": "https://connectop.heroku.com/connect/client",
    "scopes_supported": ["openid", "profile", "email", "address", "phone"],
    "response_types_supported": ["code", "token", "id_token", "code token", "code id_token", "id_token token", "code id_token token"],
    "user_id_types_supported": ["public", "pairwise"],
    "id_token_algs_supported": ["RS256"],
    "x509_url": "https://connectop.heroku.com/cert.pem"
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