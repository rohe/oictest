CLIENT = {
    "keys": [
        {
            "type": "RSA",
            "key": "../keys/second_enc.key",
            "use": ["enc"],
        },
        {
            "type": "RSA",
            "key": "../keys/second_sig.key",
            "use": ["sig"],
        },
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["enc"]}
    ],
    "behaviour": {
        "profile": "C.F.F..",
        "scope": ["openid", "profile", "email", "address", "phone"],
    },
    "preferences":{
        "subject_type": "public",
        "request_object_signing_alg": [
            "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
        ],
        "token_endpoint_auth_method": [
            "client_secret_basic", "client_secret_post",
            "client_secret_jwt", "private_key_jwt"],
        "response_types": [
            "code", "token", "id_token", "token id_token",
            "code id_token", "code token", "code token id_token"
        ],
        "grant_types":["authorization_code", "implicit", "refresh_token",
                       "urn:ietf:params:oauth:grant-type:jwt-bearer:"],
        "userinfo_signed_response_alg": [
            "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
        ],
        "id_token_signed_response_alg": [
            "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
        ],
        "default_max_age": 3600,
        "require_auth_time": True,
    }
}