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

  "interaction": {
    "https://connect.openid4.us/abop/op.php/auth": ["select_form", None],
    "https://connect.openid4.us/abop/op.php/login": ["select_form", {
      "_form_pick_": {
        "control": ("persona", "Default")
      }
    }]
  }
}

print json.dumps(info)