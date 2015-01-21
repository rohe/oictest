__author__ = 'roland'


MODE = {}

FLOWS = {
    "RP-01": {
        "flow": [{"action": "discover", "args": {}}],
        "desc": "Can Discover Identifiers using URL Syntax"
    },
    "RP-02": {
        "flow": [{"action": "discover", "args": "acct:local@localhost:8080"}],
        "desc": "Can Discover Identifiers using acct Syntax"
    },
    "RP-03": {
        "flow": [{"action": "discover", "args": {}}, 
                 {"action": "provider_info", "args": {}}],
        "desc": "Uses openid-configuration Discovery Information"
    },
    "RP-04": {
        "flow": [{"action": "discover", "args": {}}, 
                 {"action": "provider_info", "args": {}},
                 {"action": "registration", "args": {}}],
        "desc": "Uses Dynamic Registration"
    },
    "RP-05": {
        "flow": [{"action": "discover", "args": {}}, 
                 {"action": "provider_info", "args": {}},
                 {"action": "registration", "args": {}},
                 {"action": "authn_req",
                  "args": {"scope": "openid", "response_type": ["code"]}}],
        "desc": "Can Make Request with 'code' Response Type"
    },
    "RP-06": {
        "flow": [{"action": "discover", "args": {}}, 
                 {"action": "provider_info", "args": {}},
                 {"action": "registration",
                  "args": {"id_token_signed_response_alg": "RS256"}},
                 {"action": "authn_req",
                  "args": {"scope": "openid", "response_type": ["id_token"]}}],
        "desc": "Can Make Request with 'id_token' Response Type"
    },
    "RP-07": {
        "flow": [{"action": "discover", "args": {}}, 
                 {"action": "provider_info", "args": {}},
                 {"action": "registration",
                  "args": {"id_token_signed_response_alg": "RS256"}},
                 {"action": "authn_req",
                  "args": {"scope": "openid",
                           "response_type": ["id_token", "token"]}}],
        "desc": "Can Make Request with 'id_token token' Response Type"
    },
    "RP-08": {
        "flow": [{"action": "discover", "args": {}}, 
                 {"action": "provider_info", "args": {}},
                 {"action": "registration", "args": {}},
                 {"action": "authn_req",
                  "args": {"scope": "openid", "response_type": ["code"]}},
                 {"action": "token_req",
                  "args": {"authn_method": "client_secret_basic"}}],
        "desc": "Can Make Access Token Request with 'client_secret_basic' "
                "Authentication"
    },
    "RP-09": {
        "flow": [{"action": "discover", "args": {}}, 
                 {"action": "provider_info", "args": {}},
                 {"action": "registration",
                  "args": {"token_endpoint_auth_method": "client_secret_jwt"}},
                 {"action": "authn_req",
                  "args": {"scope": "openid", "response_type": ["code"]}},
                 {"action": "token_req",
                  "args": {"authn_method": "client_secret_jwt"}}
        ],
        "desc": "Can Make Access Token Request with 'client_secret_jwt' "
                "Authentication"
    },
    "RP-10": {
        "flow": [
            {"action": "discover", "args": {}}, 
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {"token_endpoint_auth_method": "client_secret_post"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req",
             "args": {"authn_method": "client_secret_post"}}
        ],
        "desc": "Can Make Access Token Request with 'client_secret_post' "
                "Authentication"
    },
    "RP-11": {
        "flow": [{"action": "discover", "args": {}}, 
                 {"action": "provider_info", "args": {}},
                 {"action": "registration",
                  "args": {"token_endpoint_auth_method": "private_key_jwt"}},
                 {"action": "authn_req",
                  "args": {"scope": "openid", "response_type": ["code"]}},
                 {"action": "token_req",
                  "args": {"authn_method": "private_key_jwt"}}
        ],
        "desc": "Can Make Access Token Request with 'private_key_jwt' "
                "Authentication"
    },
    # TODO form_post
    # === Accept Valid ? ID Token Signature	===
    # Asymmetric
    "RP-12": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration", 
             "args": {"id_token_signed_response_alg": "RS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]}}
        ],
        "desc": "Accept Valid Asymmetric ID Token Signature"
    },
    # Symmetric
    "RP-13": {
        "flow": [
            {"action": "discover", "args": {}}, 
            {"action": "provider_info", "args": {}},
            {"action": "registration", 
             "args": {"id_token_signed_response_alg": "HS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]}}
        ],
        "desc": "Accept Valid Symmetric ID Token Signature"
    },
    # === Reject Invalid ? ID Token Signature ===
    # Asymmetric
    "RP-14": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info",
             "args": {"issuer": "https://localhost:8080/_/_/idts/normal"}},
            {"action": "registration",
             "args": {"id_token_signed_response_alg": "RS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]}}
        ],
        "desc": "Reject Invalid Asymmetric ID Token Signature"
    },
    # Symmetric
    "RP-15": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info",
             "args": {"issuer": "https://localhost:8080/_/_/idts/normal"}},
            {"action": "registration",
             "args": {"id_token_signed_response_alg": "HS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]}}
        ],
        "desc": "Reject Invalid Symmetric ID Token Signature"
    },
    # === Can Request and Use ? ID Token Response ===
    # Signed and Encrypted
    # *signed is already tested*
    "RP-16": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {
                 "id_token_signed_response_alg": "HS256",
                 "id_token_encrypted_response_alg": "RSA1_5",
                 "id_token_encrypted_response_enc": "A128CBC-HS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]}}
        ],
        "desc": "Can Request and Use Signed and Encrypted ID Token Response"
    },
    # Unsigned
    "RP-17": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {"id_token_signed_response_alg": "none"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}}
        ],
        "desc": "Can Request and Use Signed and Encrypted ID Token Response"
    },
    # Can Use Elliptic Curve ID Token Signatures
    "RP-18": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {"id_token_signed_response_alg": "ES256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]}}
        ],
        "desc": "Can Request and Use Signed and Encrypted ID Token Response"
    },
    # ==== Accesses UserInfo Endpoint with Header Method ====
    # === Can Request and Use ? UserInfo Response ====
    # JSON
    "RP-19": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration", "args": {}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
        ],
        "desc": "Rejects incorrect at_hash when Implicit Flow Used"
    },
    # Signed
    "RP-20": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {"userinfo_signed_response_alg": "HS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
        ],
        "desc": "Rejects incorrect at_hash when Implicit Flow Used"
    },
    # Encrypted
    "RP-21": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {
                 "userinfo_encrypted_response_alg": "RSA1_5",
                 "userinfo_encrypted_response_enc": "A128CBC-HS256"
             }},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
            {"action": "userinfo_req", "args": {}}
        ],
        "desc": "Rejects incorrect at_hash when Implicit Flow Used"
    },
    # Signed+Encrypted
    "RP-22": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {
                 "userinfo_signed_response_alg": "HS256",
                 "userinfo_encrypted_response_alg": "RSA1_5",
                 "userinfo_encrypted_response_enc": "A128CBC-HS256"
             }},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
            {"action": "userinfo_req", "args": {}}
        ],
        "desc": "Rejects incorrect at_hash when Implicit Flow Used"
    },
    # ==== Can Use request_uri Request Parameter with ? Request ===
    # Unsigned
    # Signed
    # Encrypted
    # Signed+Encrypted
    #
    # ==== Requesting UserInfo Claims with ? ====
    # scope Values
    # claims Request Parameter
    #
    # ==== Uses ? Claims ====
    # Normal
    # Aggregated
    # Distributed
    #
    # ==== Uses Keys Discovered with jwks_uri Value ====
    #
    # ==== Can Rollover RP ? Key ====
    # Signing
    # Encryption
    #
    # ==== Rejects Discovered issuer Not Matching ? ====
    # ID Token iss Value
    # openid-configuration Path Prefix
    #
    # ==== Support OP ? Key Rollover ====
    # Signing
    # Encryption
    #
}
