#!/usr/bin/env python

import json

info = {
    "client": {
        "client_id": "client_1",
        "client_secret": "hemlig",
        },
    "provider": {
        "version": { "oauth": "2.0", "openid": "3.0"},
        "endpoints": {
            "userclaims_endpoint": "https://localhost:8089/claims"},
        "dynamic": "http://localhost:8089/",
        },
}

print json.dumps(info)