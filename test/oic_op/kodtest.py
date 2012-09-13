#!/usr/bin/env python

import json

info = {
    "versions": { "oauth": "2.0", "openid": "3.0"},
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
        #"request_object_alg": "RS256",
        #"userinfo_signed_response_alg": "RS256",
        #"id_token_signed_response_alg": "RS256"
        "preferences":{
            "user_id_type": ["pairwise", "public"],
            "require_signed_request_object": ["RS256", "RS384", "RS512",
                                              "HS512", "HS384", "HS256"],
            "token_endpoint_auth_type": ["client_secret_basic",
                                         "client_secret_post",
                                         "client_secret_jwt",
                                         "private_key_jwt"],
            "userinfo_signed_response_algs": ["RS256", "RS384", "RS512",
                                              "HS512", "HS384", "HS256"],
            #"userinfo_encrypted_response_alg",
            #"userinfo_encrypted_response_enc",
            #"userinfo_encrypted_response_int",
            "id_token_signed_response_algs": ["RS256", "RS384", "RS512",
                                              "HS512", "HS384", "HS256"],
            #"id_token_encrypted_response_alg",
            #"id_token_encrypted_response_enc",
            #"id_token_encrypted_response_int",
            "default_max_age": 3600,
            "require_auth_time": True,
            "default_acr":["2", "1"]
        }
    },
    "provider": {
        "dynamic": "https://www.kodtest.se:8088/",
    },
    "interaction": [
        {
            "matches": {
                "url": "https://www.kodtest.se:8088/authorization",
            },
            "page-type": "login",
            "control": {
                "type": "form",
                "set": {"login":"diana","password": "krall"}
            }
        }
    ]
}

print json.dumps(info)