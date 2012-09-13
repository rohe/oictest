#!/usr/bin/env python

__author__ = 'rohe0002'
import json
from oic.utils.jwt import SIGNER_ALGS
from oic.oic.message import SCOPE2CLAIMS

ISSUER = "https://server.example.com"

ENDPOINTS = ["authorization_endpoint", "token_endpoint",
             "userinfo_endpoint", "refresh_session_endpoint",
             #"check_session_endpoint",
             "end_session_endpoint", "registration_endpoint"]

info = {
    "issuer":
        "%s" % ISSUER,
    "token_endpoint_auth_types_supported":
        ["client_secret_basic", "private_key_jwt"],
    "jwk_url":
        "https://server.example.com/jwk.json",
    "scopes_supported": SCOPE2CLAIMS.keys(),
    "response_types_supported":
        ["code", "token", "id_token", "code token", "code id_token",
         "token id_token", "code token id_token"],
    "acrs_supported": ["1","2"],
    "user_id_types_supported": ["public", "pairwise"],
    "userinfo_algs_supported": SIGNER_ALGS.keys(),
    "id_token_algs_supported": SIGNER_ALGS.keys(),
    "request_object_algs_supported": SIGNER_ALGS.keys()
}

for end in ENDPOINTS:
    info[end] = "%s/%s" % (ISSUER, end)

print json.dumps(info)