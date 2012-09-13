#!/usr/bin/env python

import json

info = {
  "features": {
      "registration":True,
      "discovery": True,
      "session_management": False,
      "key_export": True,
      "sector_identifier_url": True
  },
  "client": {
        "redirect_uris": ["https://%s/authz_cb"],
        "contact": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "application_name": "OIC test tool",
        "key_export_url": "http://%s:8090/",
  },
  "provider": {
    "version": {
      "oauth": "2.0",
      "openid": "3.0"
    },
    #"dynamic": "https://connect.openid4.us/abop/"
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