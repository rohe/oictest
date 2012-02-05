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
    "type": "json"
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

USER_INFO_REQUEST_BODY = {
    "request":"UserInfoRequest",
    "method": "POST",
    "args": {
        "kw": {"authn_method": "bearer_body"}
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
    "user-info-request_bb":(USER_INFO_REQUEST_BODY, USER_INFO_RESPONSE)
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
                     "user-info-request_bb"],
        "endpoints": ["authorization_endpoint", "token_endpoint",
                      "userinfo_endpoint"],
        },
    'oic-token-userinfo_bb': {
        "name": '',
        "descr": ("1) Request with response_type='token'",
                  "2) UserinfoRequest",
                  "  'bearer_body' authentication used"),
        "depends": ['oic-token'],
        "sequence": ['oic-login-token', "user-info-request_bb"],
        "endpoints": ["authorization_endpoint", "userinfo_endpoint"],
        },

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