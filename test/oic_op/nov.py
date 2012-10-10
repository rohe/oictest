#!/usr/bin/env python

import json
from default import DEFAULT

info = DEFAULT.copy()

info["provider"] = {"dynamic": "https://connect-op.heroku.com/"}

info["interaction"] =[
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

print json.dumps(info)