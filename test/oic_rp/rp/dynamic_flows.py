from jwkest import BadSignature
from oic.oic.message import AtHashError
from oic.oic.message import CHashError

__author__ = 'roland'

MODE = {}

FLOWS = {
    "RP-A-01": {
        "flow": [{"action": "discover", "args": {}}],
        "desc": "Can Discover Identifiers using URL Syntax"
    },
    "RP-A-02": {
        "flow": [{"action": "discover", "args": "acct:%s@localhost:8080"}],
        "desc": "Can Discover Identifiers using acct Syntax"
    },
    "RP-B-01": {
        "flow": [{"action": "discover", "args": {}},
                 {"action": "provider_info", "args": {}}],
        "desc": "Uses openid-configuration Discovery Information"
    },
    "RP-C-01": {
        "flow": [{"action": "discover", "args": {}},
                 {"action": "provider_info", "args": {}},
                 {"action": "registration", "args": {}}],
        "desc": "Uses Dynamic Registration"
    },
    # Can Make Request with ? Response Type
    "RP-D-01": {
        "flow": [{"action": "discover", "args": {}},
                 {"action": "provider_info", "args": {}},
                 {"action": "registration", "args": {}},
                 {"action": "authn_req",
                  "args": {"scope": "openid", "response_type": ["code"]}}],
        "desc": "Can Make Request with 'code' Response Type"
    },
    "RP-D-02": {
        "flow": [{"action": "discover", "args": {}},
                 {"action": "provider_info", "args": {}},
                 {"action": "registration",
                  "args": {"id_token_signed_response_alg": "RS256"}},
                 {"action": "authn_req",
                  "args": {"scope": "openid", "response_type": ["id_token"]}}],
        "desc": "Can Make Request with 'id_token' Response Type"
    },
    "RP-D-03": {
        "flow": [{"action": "discover", "args": {}},
                 {"action": "provider_info", "args": {}},
                 {"action": "registration",
                  "args": {"id_token_signed_response_alg": "RS256"}},
                 {"action": "authn_req",
                  "args": {"scope": "openid",
                           "response_type": ["id_token", "token"]}}],
        "desc": "Can Make Request with 'id_token token' Response Type"
    },
    ### Can Make Access Token Request with ? Authentication
    # Client_secret_basic
    "RP-E-01": {
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
    # client_secret_jwt
    "RP-E-02": {
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
    # client_secret_post
    "RP-E-03": {
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
    # private_key_jwt
    "RP-E-04": {
        "flow": [{"action": "discover", "args": {}},
                 {"action": "provider_info", "args": {}},
                 {"action": "registration",
                  "args": {"token_endpoint_auth_method": "private_key_jwt",
                           "jwks_uri": "https://localhost:8088/static/jwk.json"}},
                 {"action": "authn_req",
                  "args": {"scope": "openid", "response_type": ["code"]}},
                 {"action": "token_req",
                  "args": {"authn_method": "private_key_jwt"}}
        ],
        "desc": "Can Make Access Token Request with 'private_key_jwt' "
                "Authentication"
    },
    ### === Accept Valid ? ID Token Signature	===
    # Asymmetric
    "RP-F-01": {
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
    "RP-F-02": {
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
    ### === Reject Invalid ? ID Token Signature ===
    # Asymmetric
    "RP-G-01": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info",
             "args": {"issuer": "https://localhost:8080/_/_/idts/normal"}},
            {"action": "registration",
             "args": {"id_token_signed_response_alg": "RS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]},
             "error": BadSignature}
        ],
        "desc": "Reject Invalid Asymmetric ID Token Signature"
    },
    # Symmetric
    "RP-G-02": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info",
             "args": {"issuer": "https://localhost:8080/_/_/idts/normal"}},
            {"action": "registration",
             "args": {"id_token_signed_response_alg": "HS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]},
             "error": BadSignature}
        ],
        "desc": "Reject Invalid Symmetric ID Token Signature"
    },
    ### === Can Request and Use ? ID Token Response ===
    # Signed and Encrypted
    # *signed is already tested*
    "RP-H-01": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {
                 "id_token_signed_response_alg": "HS256",
                 "id_token_encrypted_response_alg": "RSA1_5",
                 "id_token_encrypted_response_enc": "A128CBC-HS256",
                 "jwks_uri": None}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]}}
        ],
        "desc": "Can Request and Use Signed and Encrypted ID Token Response"
    },
    # Unsigned
    "RP-H-02": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {"id_token_signed_response_alg": "none"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}}
        ],
        "desc": "Can Request and Use unSigned ID Token Response"
    },
    # ? at_hash when code Flow Used
    # Reject incorrect
    "RP-I-01": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info",
             "args": {"issuer": "https://localhost:8080/_/_/ch/normal"}},
            {"action": "registration", "args": {}},
            {"action": "authn_req",
             "args": {"scope": "openid",
                      "response_type": ["code", "id_token"]}},
            {"action": "token_req", "args": {},
             "error": CHashError},
        ],
        "desc": "Rejects incorrect c_hash when Code Flow is Used"
    },
    # Accept correct
    "RP-I-02": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration", "args": {}},
            {"action": "authn_req",
             "args": {"scope": "openid",
                      "response_type": ["code", "id_token"]}},
            {"action": "token_req", "args": {}},
        ],
        "desc": "Verifies correct c_hash when Code Flow is Used"
    },
    # ? at_hash when Implicit Flow Used
    # Reject incorrect
    "RP-J-01": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info",
             "args": {"issuer": "https://localhost:8080/_/_/ath/normal"}},
            {"action": "registration", "args": {}},
            {"action": "authn_req",
             "args": {"scope": "openid",
                      "response_type": ["id_token", "token"]},
             "error": AtHashError},
        ],
        "desc": "Rejects incorrect at_hash when Implicit Flow is Used"
    },
    # Accept correct
    "RP-J-02": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration", "args": {}},
            {"action": "authn_req",
             "args": {"scope": "openid",
                      "response_type": ["id_token", "token"]}},
        ],
        "desc": "Verifies correct at_hash when Code Implicit is Used"
    },
    # Can Use Elliptic Curve ID Token Signatures
    "RP-K-01": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {"id_token_signed_response_alg": "ES256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["id_token"]}}
        ],
        "desc": "Can Use Elliptic Curve ID Token Signatures"
    },
    "RP-L-01": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration", "args": {}},
            {"action": "authn_req",
             "args": {"scope": "openid",
                      "claims": {"id_token": {"name": None}},
                      "response_type": ["code"]}},
            {"action": "token_req", "args": {}}
        ],
        "desc": "Can Request and Use Claims in id_token using the 'claims' "
                "request parameter"
    },
    #
    "RP-M-01": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration", "args": {}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
            {"action": "userinfo_req",
             "args": {"authn_method": "bearer_header"}}
        ],
        "desc": "Accesses UserInfo Endpoint with Header Method"
    },
    #
    "RP-N-01": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration", "args": {}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
            {"action": "userinfo_req",
             "args": {"authn_method": "bearer_header"}}
        ],
        "desc": "Can Request and Use JSON UserInfo Response"
    },
    #
    "RP-N-02": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {"userinfo_signed_response_alg": "RS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
            {"action": "userinfo_req",
             "args": {"authn_method": "bearer_header"}}
        ],
        "desc": "Can Request and Use Signed UserInfo Response"
    },
    "RP-N-03": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {
                 "userinfo_signed_response_alg": "none",
                 "userinfo_encrypted_response_alg": "RSA1_5",
                 "userinfo_encrypted_response_enc": "A128CBC-HS256",
                 "jwks_uri": None
             }},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
            {"action": "userinfo_req",
             "args": {"authn_method": "bearer_header"}}
        ],
        "desc": "Can Request and Use Encrypted UserInfo Response"
    },
    "RP-N-04": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {
                 "userinfo_signed_response_alg": "HS256",
                 "userinfo_encrypted_response_alg": "RSA1_5",
                 "userinfo_encrypted_response_enc": "A128CBC-HS256",
                 "jwks_uri": None
             }},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
            {"action": "userinfo_req",
             "args": {"authn_method": "bearer_header"}}
        ],
        "desc": "Can Request and Use Signed and Encrypted UserInfo Response"
    },
    # ==== Can Use request_uri Request Parameter with ? Request ===
    # Unsigned
    "RP-O-01": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {"request_object_signing_alg": "none"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
        ],
        "desc": "Can Use request_uri Request Parameter with Unsigned Request"
    },
    # Signed
    "RP-O-02": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {"request_object_signing_alg": "RS256"}},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
        ],
        "desc": "Can Use request_uri Request Parameter with Signed Request"
    },
    # Encrypted
    "RP-O-03": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {
                 "request_object_signing_alg": "none",
                 "request_object_encryption_alg": "RSA1_5",
                 "request_object_encryption_enc": "A128CBC-HS256"
             }},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
        ],
        "desc": "Can Use request_uri Request Parameter with Encrypted Request"
    },
    # Signed+Encrypted
    "RP-O-04": {
        "flow": [
            {"action": "discover", "args": {}},
            {"action": "provider_info", "args": {}},
            {"action": "registration",
             "args": {
                 "request_object_signing_alg": "RS256",
                 "request_object_encryption_alg": "RSA1_5",
                 "request_object_encryption_enc": "A128CBC-HS256"
             }},
            {"action": "authn_req",
             "args": {"scope": "openid", "response_type": ["code"]}},
            {"action": "token_req", "args": {}},
        ],
        "desc": "Can Use request_uri Request Parameter with Signed and "
                "Encrypted Request"
    },
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
    # ==== ID Spoofing ====
    # ==== Issuer Confusion ====
    # ==== Signature Manipulation ====
    # ==== Sub Claims Spoofing ====
    # ==== Redirect URI Manipulation ====
}
