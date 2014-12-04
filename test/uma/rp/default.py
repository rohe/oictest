__author__ = 'roland'

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
}