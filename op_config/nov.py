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