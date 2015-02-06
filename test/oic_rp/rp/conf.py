__author__ = 'roland'

PORT = 8088
BASE = "https://localhost:" + str(PORT) + "/"

# If BASE is https these has to be specified
SERVER_CERT = "certs/server.crt"
SERVER_KEY = "certs/server.key"
CA_BUNDLE = None
VERIFY_SSL = False

ISSUER = "https://localhost:8080/"
#ISSUER = "https://oictest.umdc.umu.se:8051/"

keys = [
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
]

KEY_EXPORT_URL = "%sexport/jwk.json" % BASE

CLIENT_INFO = {
    "redirect_uris": ["%sauthz_cb" % BASE],
    "application_type": "web",
    "contact": ["foo@example.com"]
}