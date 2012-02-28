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
    "dynamic": "https://connect.openid4.us/"
  },
  "interaction": [
          {
          "matches" : {
              "title": "connect.openid4.us OP"
          },
          "control": {
              "type": "form"
          },
          "page-type": "login"
      },{
          "matches" : {
              "title": "connect.openid4.us AX Confirm"
          },
          "control": {
              "type": "form",
              "pick": {
                  "control": {"id":"persona", "value":"Default"}
              }
          },
          "page-type":"user-consent"
      }
  ]
}

print json.dumps(info)