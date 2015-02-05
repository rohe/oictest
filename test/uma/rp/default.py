CLIENT = {
    "keys": [
        {
            "type": "RSA",
            "key": "../keys/pyoidc_enc",
            "use": ["enc"],
        },
        {
            "type": "RSA",
            "key": "../keys/pyoidc_sig",
            "use": ["sig"],
        },
        {"type": "EC", "crv": "P-256", "use": ["sig"]},
        {"type": "EC", "crv": "P-256", "use": ["enc"]}
    ],
    "behaviour": {
        "scope": ["openid", "uma_authorization", "uma_protection"],
    },
    "preferences": {
        "request_object_signing_alg": [
            "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
        ],
        "token_endpoint_auth_method": [
            "client_secret_basic", "client_secret_post",
            "client_secret_jwt", "private_key_jwt"],
        "response_types": ["code", "token"],
        "grant_types": ["authorization_code", "implicit", "refresh_token"],
        "default_max_age": 3600,
        "require_auth_time": True,
    }
}