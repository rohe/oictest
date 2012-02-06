#!/usr/bin/env python
__author__ = 'rohe0002'

# ========================================================================

from oictest.check import *
# Used upstream not in this module so don't remove
from oictest.opfunc import *

# ========================================================================

RESPOND = {
    "method": "POST",
    }

AUTHZREQ_CODE = {
    "request": "AuthorizationRequest",
    "method": "GET",
    "args": {
        "request": {"response_type": "code",
                    "scope": ["openid"],
        },
    },
}

AUTHZRESP = {
    "response": "AuthorizationResponse",
    "where": "url",
    "type": "urlencoded",
    "tests": {"post": [CheckAuthorizationResponse]}
    }

OPENID_REQUEST_CODE = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code", "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_DISPLAY_PAGE = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "display": "page"}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_DISPLAY_POPUP = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "display": "popup"}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_PROMPT_NONE = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "prompt": "none"}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_PROMPT_LOGIN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "prompt": "login"}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_PROFILE = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid", "profile"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_EMAIL = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid", "email"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_ADDRESS = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid", "address"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_PHONE = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid","phone"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_ALL = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid", "address", "email", "phone",
                                   "profile"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_SPEC1 = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "userinfo_claims": {"claims": {"name": None}}}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_SPEC2 = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "userinfo_claims": {
                             "claims": {
                                 "picture": {"optional":True},
                                 "email": {"optional": True}}}}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_SPEC3 = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "userinfo_claims": {
                             "claims": {
                                 "name": None,
                                 "picture": {"optional":True},
                                 "email": {"optional": True}}}}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_IDTC1 = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "idtoken_claims":{"claims":{"auth_time": None}}}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_IDTC2 = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "idtoken_claims":{"claims":{
                                                "acr": {"values": ["2"]}}}}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_IDTC3 = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "idtoken_claims":{"claims":{"acr": None}}}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_IDTC4 = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "code",
                         "scope": ["openid"],
                         "idtoken_claims":{"max_age": 10 }}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_TOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "token", "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_IDTOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": "id_token", "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

# {"OpenIDRequest": {"request", {"response_type":["code","token"]}}}

OPENID_REQUEST_CODE_TOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": ["code","token"],
                         "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_IDTOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": ["code","id_token"],
                         "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_TOKEN_IDTOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": ["token","id_token"],
                         "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

OPENID_REQUEST_CODE_TOKEN_IDTOKEN = {
    "request": "OpenIDRequest",
    "method": "GET",
    "args": {"request": {"response_type": ["code", "token", "id_token"],
                         "scope": ["openid"]}},
    "tests": {
        "pre": [CheckResponseType],
        "post": [CheckHTTPResponse]
    }
}

# 2.1.2.1.2
# The User Identifier for which an ID Token is being requested.
# If the specified user is not currently authenticated to the Authorization
# Server, they may be prompted for authenticated, unless the prompt parameter
# in the Authorization Request is set to none. The Claim Value in the request
# is an object containing the single element value.
#"user_id": {"value":"248289761001"}

#OPENID_REQUEST_CODE_21212 = {
#    "request": "AuthorizationRequest",
#    "method": "GET",
#    "args": {
#        "request": {"response_type": "code",
#                    "scope": ["oic"],
#                    "prompt": "none"
#                    },
#        "kw": {
#            "idtoken_claims": {
#                "claims": {"user_id": {"value":"248289761001"}}
#            }
#        }
#    }
#}

ACCESS_TOKEN_RESPONSE = {
    "response": "AccessTokenResponse",
    "where": "body",
    "type": "json"
}

USER_INFO_RESPONSE = {
    "response": "OpenIDSchema",
    "where": "body",
    "type": "json",
    "tests": {
        "post": [ScopeWithClaims]
    }
}

ACCESS_TOKEN_REQUEST_PASSWD = {
    "request":"AccessTokenRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "client_secret_basic"}
    },
}

ACCESS_TOKEN_REQUEST_CLI_SECRET = {
    "request":"AccessTokenRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "client_secret_post"}
    },
}

USER_INFO_REQUEST = {
    "request":"UserInfoRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "bearer_header"}
    },
}

USER_INFO_REQUEST_POST_BB = {
    "request":"UserInfoRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "bearer_body"}
    },
}

USER_INFO_REQUEST_POST_BH = {
    "request":"UserInfoRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "bearer_header"}
    },
    }

#USER_INFO_REQUEST_BODY_GET = {
#    "request":"UserInfoRequest",
#    "method": "GET",
#    "args": {
#        "kw": {"authn_method": "bearer_body"}
#    },
#}

PROVIDER_CONFIGURATION = {
    "request": "ProviderConfigurationRequest"
}

CHECK_ID_REQUEST_GET_BH = {
    "request": "CheckIDRequest",
    "method": "GET",
    "args": {
        "kw": {"authn_method": "bearer_header"}
    },
}

CHECK_ID_REQUEST_POST_BH = {
    "request": "CheckIDRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "bearer_header"}
    },
    }

CHECK_ID_REQUEST_POST_BB = {
    "request": "CheckIDRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "bearer_body"}
    },
}

CHECK_ID_RESPONSE = {
    "response": "IdToken",
    "where": "body",
    "type": "json"
}

PHASES= {
    "login": (AUTHZREQ_CODE, AUTHZRESP),
    "oic-login": (OPENID_REQUEST_CODE, AUTHZRESP),
    "oic-login+profile": (OPENID_REQUEST_CODE_PROFILE, AUTHZRESP),
    "oic-login+email": (OPENID_REQUEST_CODE_EMAIL, AUTHZRESP),
    "oic-login+phone": (OPENID_REQUEST_CODE_PHONE, AUTHZRESP),
    "oic-login+address": (OPENID_REQUEST_CODE_ADDRESS, AUTHZRESP),
    "oic-login+all": (OPENID_REQUEST_CODE_ALL, AUTHZRESP),
    "oic-login+spec1": (OPENID_REQUEST_CODE_SPEC1, AUTHZRESP),
    "oic-login+spec2": (OPENID_REQUEST_CODE_SPEC2, AUTHZRESP),
    "oic-login+spec3": (OPENID_REQUEST_CODE_SPEC3, AUTHZRESP),

    "oic-login+idtc1": (OPENID_REQUEST_CODE_IDTC1, AUTHZRESP),
    "oic-login+idtc2": (OPENID_REQUEST_CODE_IDTC2, AUTHZRESP),
    "oic-login+idtc3": (OPENID_REQUEST_CODE_IDTC3, AUTHZRESP),
    "oic-login+idtc4": (OPENID_REQUEST_CODE_IDTC4, AUTHZRESP),

    "oic-login+disp_page": (OPENID_REQUEST_CODE_DISPLAY_PAGE, AUTHZRESP),
    "oic-login+disp_popup": (OPENID_REQUEST_CODE_DISPLAY_POPUP, AUTHZRESP),

    "oic-login+prompt_none": (OPENID_REQUEST_CODE_PROMPT_NONE, AUTHZRESP),
    "oic-login+prompt_login": (OPENID_REQUEST_CODE_PROMPT_LOGIN, AUTHZRESP),

    "oic-login-token": (OPENID_REQUEST_TOKEN, AUTHZRESP),
    "oic-login-idtoken": (OPENID_REQUEST_IDTOKEN, AUTHZRESP),
    "oic-login-code+token": (OPENID_REQUEST_CODE_TOKEN, AUTHZRESP),
    "oic-login-code+idtoken": (OPENID_REQUEST_CODE_IDTOKEN, AUTHZRESP),
    "oic-login-idtoken+token": (OPENID_REQUEST_TOKEN_IDTOKEN, AUTHZRESP),
    "oic-login-code+idtoken+token": (OPENID_REQUEST_CODE_TOKEN_IDTOKEN,
                                     AUTHZRESP),
#
    "access-token-request":(ACCESS_TOKEN_REQUEST_CLI_SECRET,
                            ACCESS_TOKEN_RESPONSE),
    "check-id-request_gbh":(CHECK_ID_REQUEST_GET_BH, CHECK_ID_RESPONSE),
    "check-id-request_pbh":(CHECK_ID_REQUEST_POST_BH, CHECK_ID_RESPONSE),
    "check-id-request_pbb":(CHECK_ID_REQUEST_POST_BB, CHECK_ID_RESPONSE),
    "user-info-request":(USER_INFO_REQUEST, USER_INFO_RESPONSE),
    "user-info-request_pbh":(USER_INFO_REQUEST_POST_BH, USER_INFO_RESPONSE),
    "user-info-request_pbb":(USER_INFO_REQUEST_POST_BB, USER_INFO_RESPONSE),
}


FLOWS = {
    'oic-code': {
        "name": 'Request with response_type=code',
        "descr": ('Request with response_type=code'),
        "sequence": ["oic-login"],
        "endpoints": ["authorization_endpoint"]
    },
    'oic-token': {
        "name": 'Request with response_type=token',
        "descr": ('Request with response_type=token'),
        "sequence": ["oic-login-token"],
        "endpoints": ["authorization_endpoint"]
    },
    'oic-idtoken': {
        "name": 'Request with response_type=id_token',
        "descr": ('Request with response_type=id_token'),
        "sequence": ["oic-login-idtoken"],
        "endpoints": ["authorization_endpoint"]
    },
    'oic-code+token': {
        "name": 'Request with response_type=code token',
        "descr": ("Request with response_type=code token"),
        "sequence": ["oic-login-code+token"],
        "endpoints": ["authorization_endpoint"],
        },
    'oic-code+idtoken': {
        "name": 'Request with response_type=code id_token',
        "descr": ("Request with response_type=code id_token"),
        "sequence": ['oic-login-code+idtoken'],
        "endpoints": ["authorization_endpoint"],
        },
    'oic-idtoken+token': {
        "name": 'Request with response_type=id_token token',
        "descr": ("Request with response_type=id_token token"),
        "sequence": ['oic-login-idtoken+token'],
        "endpoints": ["authorization_endpoint"],
        },
    'oic-code+idtoken+token': {
        "name": 'Request with response_type=code id_token token',
        "descr": ("Request with response_type=code id_token token"),
        "sequence": ['oic-login-code+idtoken+token'],
        "endpoints": ["authorization_endpoint",],
        },
    # -------------------------------------------------------------------------
    'oic-code-token': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code'],
        "sequence": ["oic-login", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+token-token': {
        "name": "",
        "descr": ("1) Request with response_type='code token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code+token'],
        "sequence": ["oic-login-code+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken-token': {
        "name": "",
        "descr": ("1) Request with response_type='code id_token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code+idtoken'],
        "sequence": ["oic-login-code+idtoken", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtoken+token-token': {
        "name": "",
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code+idtoken+token'],
        "sequence": ["oic-login-code+idtoken+token", "access-token-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # -------------------------------------------------------------------------
    'oic-code-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'oic-code+profile-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'profile']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+profile", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+email-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'email']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+email", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+address-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'address']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+address", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+phone-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'phone']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+phone", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+all-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid', 'email', 'phone', 'address', 'profile']",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+all", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+spec1-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+spec1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+spec2-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+spec2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+spec3-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+spec3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtc1-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+idtc1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtc2-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+idtc2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-code+idtc3-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type=code",
                  "scope = ['openid'], claims={'name':None}",
                  "2) AccessTokenRequest",
                  "Authentication method used is 'client_secret_post'"),
        "depends": ['oic-code-token-userinfo'],
        "sequence": ["oic-login+idtc3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'oic-token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type='token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-token'],
        "sequence": ['oic-login-token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+token-userinfo': {
        "name": '',
        "descr": ("1) Request with response_type='code token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code+token'],
        "sequence": ['oic-login-code+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken-token-userinfo': {
        "name": 'Implicit flow with Code+IDToken ',
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code+idtoken-token'],
        "sequence": ['oic-login-code+idtoken', "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'oic-idtoken+token-userinfo': {
        "name": 'Implicit flow with Token+IDToken ',
        "descr": ("1) Request with response_type='id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-idtoken+token'],
        "sequence": ['oic-login-idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-userinfo': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends":["oic-code+idtoken+token"],
        "sequence": ['oic-login-code+idtoken+token', "user-info-request"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'oic-code+idtoken+token-token-userinfo': {
        "name": ("Get an accesstoken using access code with 'token' and ",
                 "'idtoken' in response type"),
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code+idtoken+token-token'],
        "sequence": ["oic-login-code+idtoken+token", "access-token-request",
                     'user-info-request'],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },

    # -------------------------------------------------------------------------
    'oic-code-token-check_id': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request", "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'oic-code-token-check_id_pbh': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'oic-code-token-check_id_pbb': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'oic-idtoken+token-check_id': {
        "name": '',
        "descr": ("1) Request with response_type='id_token token'",
                  "2) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-idtoken+token'],
        "sequence": ['oic-login-idtoken+token', "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": ["compare-idoken-received-with-check_id-response"]
    },
    'oic-code+idtoken-check_id': {
        "name": '',
        "descr": ("1) Request with response_type='code id_token'",
                  "2) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends":["oic-code+idtoken"],
        "sequence": ['oic-login-code+idtoken', "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": ["compare-idoken-received-with-check_id-response"]
    },
    'oic-code+idtoken+token-check_id': {
        "name": 'Implicit flow with Code+Token+IDToken ',
        "descr": ("1) Request with response_type='code id_token token'",
                  "2) CheckIDRequest",
                  "  'bearer_body' authentication used"),
        "depends":["oic-code+idtoken+token"],
        "sequence": ['oic-login-code+idtoken+token', "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "check_id_endpoint"],
        "tests": ["compare-idoken-received-with-check_id-response"]
    },
    # beared body authentication
    'oic-code-token-userinfo_bb': {
        "name": '',
        "descr": ("1) Request with response_type='code'",
                  "2) AccessTokenRequest",
                  "  Authentication method used is 'client_secret_post'",
                  "3) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-code-token'],
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'oic-token-userinfo_bb': {
        "name": '',
        "descr": ("1) Request with response_type='token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-token'],
        "sequence": ['oic-login-token', "user-info-request_pbb"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },
    'mj-01': {
        "name": 'Request with response_type=code',
        "sequence": ["oic-login"],
        "endpoints": ["authorization_endpoint"]
    },
    'mj-02': {
        "name": 'Request with response_type=token',
        "sequence": ["oic-login-token"],
        "endpoints": ["authorization_endpoint"]
    },
    'mj-03': {
        "name": 'Request with response_type=id_token',
        "sequence": ["oic-login-idtoken"],
        "endpoints": ["authorization_endpoint"]
    },
    'mj-04': {
        "name": 'Request with response_type=code token',
        "sequence": ["oic-login-code+token"],
        "endpoints": ["authorization_endpoint"],
        },
    'mj-05': {
        "name": 'Request with response_type=code id_token',
        "sequence": ['oic-login-code+idtoken'],
        "endpoints": ["authorization_endpoint"],
        },
    'mj-06': {
        "name": 'Request with response_type=id_token token',
        "sequence": ['oic-login-idtoken+token'],
        "endpoints": ["authorization_endpoint"],
        },
    'mj-07': {
        "name": 'Request with response_type=code id_token token',
        "sequence": ['oic-login-code+idtoken+token'],
        "endpoints": ["authorization_endpoint",],
        },
    # -------------------------------------------------------------------------
    'mj-08': {
        "name": 'Check ID Endpoint Access with GET and bearer_header',
        "sequence": ["oic-login", "access-token-request", "check-id-request_gbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'mj-09': {
        "name": 'Check ID Endpoint Access with POST and bearer_header',
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    'mj-10': {
        "name": 'Check ID Endpoint Access with POST and bearer_body',
        "sequence": ["oic-login", "access-token-request",
                     "check-id-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "check_id_endpoint"],
        },
    # -------------------------------------------------------------------------
    'mj-11': {
        "name": 'UserInfo Endpoint Access with GET and bearer_header',
        "sequence": ["oic-login", "access-token-request", "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-12': {
        "name": 'UserInfo Endpoint Access with POST and bearer_header',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_pbh"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'mj-13': {
        "name": 'UserInfo Endpoint Access with POST and bearer_body',
        "sequence": ["oic-login", "access-token-request",
                     "user-info-request_pbb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    # -------------------------------------------------------------------------
    'mj-14': {
        "name": 'Scope Requesting profile Claims',
        "sequence": ["oic-login+profile", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-15': {
        "name": 'Scope Requesting email Claims',
        "sequence": ["oic-login+email", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-16': {
        "name": 'Scope Requesting address Claims',
        "sequence": ["oic-login+address", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-17': {
        "name": 'Scope Requesting phone Claims',
        "sequence": ["oic-login+phone", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-18': {
        "name": 'Scope Requesting all Claims',
        "sequence": ["oic-login+all", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-19': {
        "name": 'OpenID Request Object with Required name Claim',
        "sequence": ["oic-login+spec1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-20': {
        "name": 'OpenID Request Object with Optional email and picture Claim',
        "sequence": ["oic-login+spec2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-21': {
        "name": ('OpenID Request Object with Required name and Optional email and picture Claim'),
        "sequence": ["oic-login+spec3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-22': {
        "name": 'Requesting ID Token with auth_time Claim',
        "sequence": ["oic-login+idtc1", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-23': {
        "name": 'Requesting ID Token with Required acr Claim',
        "sequence": ["oic-login+idtc2", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-24': {
        "name": 'Requesting ID Token with Optional acr Claim',
        "sequence": ["oic-login+idtc3", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-25': {
        "name": 'Requesting ID Token with max_age=10 seconds Restriction',
        "sequence": ["oic-login+idtc4", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # ---------------------------------------------------------------------
    'mj-26': {
        "name": 'Request with display=page',
        "sequence": ["oic-login+disp_page", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-27': {
        "name": 'Request with display=popup',
        "sequence": ["oic-login+disp_popup", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-28': {
        "name": 'Request with prompt=none',
        "sequence": ["oic-login+prompt_none", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    'mj-29': {
        "name": 'Request with prompt=login',
        "sequence": ["oic-login+prompt_login", "access-token-request",
                     "user-info-request"],
        "endpoints": ["authorization_endpoint", "token_endpoint"],
        },
    # ---------------------------------------------------------------------
}

if __name__ == "__main__":
    for name, spec in FLOWS.items():
        try:
            for dep in spec["depends"]:
                try:
                    assert dep in FLOWS
                except AssertionError:
                    print "%s missing in FLOWS" % dep
                    raise
        except KeyError:
            pass
        for op in spec["sequence"]:
            try:
                assert op in PHASES
            except AssertionError:
                print "%s missing in PHASES" % op
                raise