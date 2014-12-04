import copy
import default
from sslconf import *

HOST = "localhost"
PORT = 8088
BASE = "https://%s:%d/" % (HOST, PORT)

CLIENT = {
    "base_url": BASE,
    "srv_discovery_url": "https://demo.nuveam.com/",
    "client_registration_type": "oauth2",
    "client_info": {
        "client_name": "OIC test tool",
        "contacts": ["roland.hedberg@umu.se"],
        "redirect_uris": ["%sauthz_cb" % BASE],
    },
    # "jwks_uri": SINGLE_OPTIONAL_STRING,
    "key_export_url": "%sexport/jwk.json" % BASE,
    "behaviour": {
        "response_type": "code",
        "scope": ["openid", "profile", "email", "address", "phone"],
    },
    "preferences": {
        # "client_uri": SINGLE_OPTIONAL_STRING,
        # "logo_uri": SINGLE_OPTIONAL_STRING,
        # "tos_uri": SINGLE_OPTIONAL_STRING,
        # "policy_uri": SINGLE_OPTIONAL_STRING,
        # "software_id": SINGLE_OPTIONAL_STRING,
        # "software_version": SINGLE_OPTIONAL_STRING,
        "token_endpoint_auth_method": [
            "client_secret_basic", "client_secret_post",
            "client_secret_jwt", "private_key_jwt"],
        "response_types": [
            "code", "token", "id_token", "token id_token",
            "code id_token", "code token", "code token id_token"
        ],
        "grant_types": ["authorization_code", "implicit", "refresh_token",
                        "urn:ietf:params:oauth:grant-type:jwt-bearer:"],
    }
}

for arg in ["keys", "behaviour", "preferences"]:
    CLIENT[arg] = copy.deepcopy(default.CLIENT[arg])