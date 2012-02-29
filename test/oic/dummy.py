#!/usr/bin/env python

import json

info = {
    "versions": {
        "oauth": "2.0",
        "openid": "3.0"
    },
    "provider": {
        "features": {
            "discovery": True,
            "registration": True,
            "sessionmanagement": False
        },
        "supported_response_types": ["code", "code id_token"],
        "supported_scopes": ["openid"],
        "algoritms": ["HS256"],
        "issuer": "https://connect.openid4.us",
        "dynamic": "https://connect.openid4.us"
    },
    "client": {
        "auth_type": "client_secret_basic",
        "client_type": "confidential",
        "client_id": "13e92a9d-156e-4475-b425-1872343f7ff8",
        "redirect_uris": ["https://localhost/callback1", "https://localhost/callback2"],
        "client_secret": "",
        "register": True
    }
}

print json.dumps(info)
