__author__ = 'roland'


MODE = {}

FLOWS = {
    "RP-1": {
        "flow": [("discover", None)],
        "desc": "Can Discover Identifiers using URL Syntax"
    },
    "RP-2": {
        "flow": [("discover", "acct:local@localhost:8080")],
        "desc": "Can Discover Identifiers using acct Syntax"
    },
    "RP-3": {
        "flow": [("discover", None), ("provider_info", None)],
        "desc": "Uses openid-configuration Discovery Information"
    },
    "RP-4": {
        "flow": [("discover", None), ("provider_info", None),
                 ("registration", None)],
        "desc": "Uses Dynamic Registration"
    },
    "RP-5": {
        "flow": [("discover", None), ("provider_info", None),
                 ("registration", None),
                 ("authn_req", {"scope": "openid", "response_type": ["code"]})],
        "desc": "Can Make Request with 'code' Response Type"
    },
    "RP-6": {
        "flow": [("discover", None), ("provider_info", None),
                 ("registration", None),
                 ("authn_req", {"scope": "openid",
                                "response_type": ["id_token"]})],
        "desc": "Can Make Request with 'id_token' Response Type"
    },
    "RP-7": {
        "flow": [("discover", None), ("provider_info", None),
                 ("registration", None),
                 ("authn_req", {"scope": "openid",
                                "response_type": ["id_token", "token"]})],
        "desc": "Can Make Request with 'id_token token' Response Type"
    },
    "RP-8": {
        "flow": [("discover", None), ("provider_info", None),
                 ("registration", None),
                 ("authn_req", {"scope": "openid",
                                "response_type": ["code"]}),
                 ("token_req", {"authn_method": "client_secret_basic"})],
        "desc": "Can Make Access Token Request with 'client_secret_basic' "
                "Authentication"
    },
    "RP-9": {
        "flow": [("discover", None), ("provider_info", None),
                 ("registration", None),
                 ("authn_req", {"scope": "openid",
                                "response_type": ["code"]}),
                 ("token_req", {"authn_method": "client_secret_jwt"})],
        "desc": "Can Make Access Token Request with 'client_secret_jwt' "
                "Authentication"
    },
    "RP-10": {
        "flow": [("discover", None), ("provider_info", None),
                 ("registration", None),
                 ("authn_req", {"scope": "openid",
                                "response_type": ["code"]}),
                 ("token_req", {"authn_method": "client_secret_post"})],
        "desc": "Can Make Access Token Request with 'client_secret_post' "
                "Authentication"
    },
    "RP-11": {
        "flow": [("discover", None), ("provider_info", None),
                 ("registration", None),
                 ("authn_req", {"scope": "openid",
                                "response_type": ["code"]}),
                 ("token_req", {"authn_method": "client_secret_basic"})],
        "desc": "Can Make Access Token Request with 'client_secret_basic' "
                "Authentication"
    },
}
