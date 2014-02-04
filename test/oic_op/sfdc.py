#!/usr/bin/env python

import json

from default import DEFAULT

info = DEFAULT.copy()

info["features"] = {
    "registration": False,
    "discovery": True,
    "session_management": False,
    "key_export": False
}

info["provider"] = {
    "dynamic": "https://delauth-responder.herokuapp.com"
}

# This is the minimum I think I need to make the example JS redirection
# test-case work. This doesn't represent what we would use to run the
# tests in real-world
info["client"] = {
    "redirect_uris": ["https://delauth-responder.herokuapp.com/callback"],
    "client_id": "3MVG9AOp4kbriZOIuLSjz.GXg.POjC3jL_fudBIaK4cVLPUrTFVvgQqhMkigCB5SbG09nThu8AgtuAzyyKsps",
    "client_secret": "3928835641696011102",
    "contacts": ["cwhite@salesforce.com"],
    "application_type": "web",
    "client_name": "OIC test tool",
    "key_export_url": "http://%s:8090/",
    "keys": {
        "RSA": {
            "key": "keys/pyoidc",
            "use": []
        }
    }
}

# Example of an interaction that demonstrates the test-flow
#
# The full-flow is as follows
# 1) [authorize]- https://delauth-responder.herokuapp.com/authorize
# 2) [authorize] returns 302 redirect to
#    https://delauth-responder.herokuapp.com/authorize_redirect
# 3) https://delauth-responder.herokuapp.com/authorize_redirect contains JS
#    redirect to https://delauth-responder.herokuapp.com/redirect
# 4) The test-case is a success if the final URL is
#    https://delauth-responder.herokuapp.com/redirect

info["interaction"] = [
    {
        "matches": {
            "url": "https://delauth-responder.herokuapp.com/authorize_redirect"
        },
        "page-type": "redirect",
        "control": {
            "type": "javascript_redirect",
            "url_regex": 'document\.location = \'(https://.*)\''
        }
    }
]

print json.dumps(info)