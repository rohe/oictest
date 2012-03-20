#!/usr/bin/env python

import json

info = {
  "features": {
    "registration":True,
    "discovery": True,
    "sessionmangement": False,
  },
  "client": {
    "redirect_uris": ["https://smultron.catalogix.se/authz_cb"],
    "contact": ["roland.hedberg@adm.umu.se"],
    "application_type": "web",
    "application_name": "OIC test tool",
  },
  "provider": {
    "version": {
      "oauth": "2.0",
      "openid": "3.0"
    },
    "dynamic": "https://openidconnect.info/"
  },
  "interaction": [
      {
          "matches" : {
              "url": "https://openidconnect.info/account/login"
          },
          "page-type": "login",
          "control": {
              "type": "link",
              "path": "/account/fake"
          }
      },{
          "matches" : {
              "url": "https://openidconnect.info/connect/consent"
          },
          "page-type": "user-consent",
          "control": {
              "type": "form"
          }
      }
  ]
}

print json.dumps(info)