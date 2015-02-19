import copy
import default
from sslconf import *

HOST = "localhost"
PORT = 8088
BASE = "https://%s:%d/" % (HOST, PORT)

CLIENT = {
    "base_url": BASE,
    "srv_discovery_url": "https://localhost:8092/",
    "acr_values": ["1"],
    "client_registration": {
        "redirect_uris": ["%sauthz_cb" % BASE],
        "client_id": "BasicClient",
        "client_secret": "PassWord"
    },
    "key_export_url": "%sexport/jwk_%%s.json" % BASE,
    "provider_info": {
        "issuer": "https://identity.mifetest.com:9443/oauth2",
        "authorization_endpoint":
            "https://identity.mifetest.com:9443/oauth2/authorize",
        "token_endpoint": "https://identity.mifetest.com:9443/oauth2/token",
        "response_types_supported": ["code"],
        "acr_values_supported": ["1", "2", "3", "4  "]
    }

}

for arg in ["keys", "behaviour", "preferences"]:
    CLIENT[arg] = copy.deepcopy(default.CLIENT[arg])