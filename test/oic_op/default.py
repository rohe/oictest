__author__ = 'rohe0002'

DEFAULT = {
    "versions": { "oauth": "2.0", "openid": "3.0"},
    "features": {
        "registration": True,
        "discovery": True,
        "session_management": False,
        "key_export": True,
        #"sector_identifier_url": True
    },
    "client": {
        "redirect_uris": ["https://%s/authz_cb"],
        "contacts": ["roland.hedberg@adm.umu.se"],
        "application_type": "web",
        "client_name": "OIC test tool",
        "key_export_url": "http://%s:8090/",
        "keys": {
            "RSA": {
                "key": "keys/pyoidc",
                "use": ["enc", "sig"]
            }
        },
        #"request_object_alg": "RS256",
        #"userinfo_signed_response_alg": "RS256",
        #"id_token_signed_response_alg": "RS256"
        "preferences":{
            "subject_types": ["pairwise", "public"],
            "request_object_signing_algs": [
                "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
            ],
            "token_endpoint_auth_methods": [
                "client_secret_basic", "client_secret_post",
                "client_secret_jwt", "private_key_jwt"],
            "response_types": [
                "code", "token", "id_token", "token id_token",
                "code id_token", "code token", "code token id_token"
            ],
            "grant_types":["authorization_code", "implicit", "refresh_token",
                           "urn:ietf:params:oauth:grant-type:jwt-bearer:"],
            "userinfo_signed_response_algs": [
                "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
            ],
            #"userinfo_encrypted_response_alg",
            #"userinfo_encrypted_response_enc",
            #"userinfo_encrypted_response_int",
            "id_token_signed_response_algs": [
                "RS256", "RS384", "RS512", "HS512", "HS384", "HS256"
            ],
            #"id_token_encrypted_response_alg",
            #"id_token_encrypted_response_enc",
            #"id_token_encrypted_response_int",
            "default_max_age": 3600,
            "require_auth_time": True,
            "default_acr_values":["2", "1"]
        }
    },
}