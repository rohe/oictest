#!/usr/bin/env python

import json

info = {
  "features": {
    "registration":True,
    "discovery": True,
    "sessionmangement": False,
  },
  "client": {
    "redirect_uris": ["https://connect-rp.heroku.com"],
    "contact": ["nov@matake.jp"],
    "application_type": "web",
    "application_name": "Nov RP",
  },
  "provider": {
    "version": "3.0",
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
  "interaction":[
          {
          "matches" : {
              "url": "https://connect-op.heroku.com/authorizations/new"
          },
          "page-type": "user-consent",
          "control": {
              "type": "form",
              "pick": {
                  "form": {"action": "/authorizations",
                           "class": "approve"}
              }

          }
      },{
          "matches" : {
              "url": "https://connect-op.heroku.com/"
          },
          "page-type": "login",
          "control": {
              "type": "form",
              "pick":{
                  "form":{"action": "/connect/fake"}
              }
          }
      }
  ]
}

print json.dumps(info)