__author__ = 'roland'

MODE = {}

FLOWS = {
    # private_key_jwt
    "RP-11": {
        "flow": [{"action": "discover", "args": {}},
                 {"action": "provider_info", "args": {}},
                 {"action": "static_registration",
                  "args": {"client_id": "i5izKjIK2iVn",
                           "client_secret": "e65862ba55fc227024d17124a49b4c9162cb5d89d61f77f58538b6ac"}},
                 {"action": "authn_req",
                  "args": {"scope": "openid", "response_type": ["code"]}},
                 {"action": "token_req",
                  "args": {"authn_method": "private_key_jwt"}}
        ],
        "desc": "Can Make Access Token Request with 'private_key_jwt' "
                "Authentication"
    },
}
