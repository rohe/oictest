HOST = "localhost"
PORT = 8088
BASE = "https://%s:%d/" % (HOST, PORT)

# If default port
#BASE = "https://%s/" % HOST

# If BASE is https these has to be specified
SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
CA_BUNDLE = None
VERIFY_SSL = False

CLIENT = {
    "keys": {
        "RSA": {
            "key": "../keys/pyoidc",
            "use": ["enc", "sig"]
        }
    },
    "base_url": BASE,
    "srv_discovery_url": "https://localhost:8092/",
    "client_info": {
        "application_type": "web",
        "application_name": "OIC test tool",
        "contacts": ["roland.hedberg@umu.se"],
        "redirect_uris": ["%sauthz_cb" % BASE],
        "post_logout_redirect_uris": ["%slogout" % BASE],
    },
    "key_export_url": "%sexport/jwk.json" % BASE,
    "behaviour": {
        "response_type": "code",
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